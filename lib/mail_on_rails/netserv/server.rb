# frozen_string_literal: true

require "socket"
require_relative "config"
require_relative "conn_limiter"
require_relative "auth_throttle"
require_relative "rate_limiter"
require_relative "denylist"
require_relative "transcript"
require_relative "probe_signatures"
require_relative "honeypot_session"
require_relative "tls"
require_relative "ops_sync"

module MailOnRails
  module Netserv
    # Listener scaffolding shared by the SMTP and IMAP servers: one accept
    # thread per listener spec, one thread per connection, connection caps,
    # per-IP anti-abuse state, and TLS material handling. Keeping this in
    # one place means the flood, lockout and TLS-accept behavior cannot
    # drift apart between the two protocols (it did once: the IMAP fork
    # missed every per-IP protection SMTP grew).
    #
    # Sessions do not run on the accept threads. Each accepted socket gets
    # its own thread: the tarpit delay the RateLimiter handed out is slept
    # there first, then the implicit-TLS handshake (bounded by
    # HANDSHAKE_TIMEOUT so a connected-but-silent peer can't park the
    # thread and leak its ConnLimiter slot), then the protocol session
    # doing plain blocking IO under its own idle timeout.
    #
    # The ConnLimiter, AuthThrottle, RateLimiter and Denylist all live on
    # the accept side, so the connection caps (process-wide and per-IP),
    # the per-IP auth-failure lockout, the per-IP connection rate and the
    # admin ban list stay exact process-wide.
    #
    # Subclasses define MAX_CONNECTIONS (plus the per-IP constants below)
    # and the protocol specifics: protocol_name, busy_line (sent when the
    # connection cap is hit), listener_label(spec), session_class, and
    # optionally locked_line. TLS (material, context, accept) is the shared
    # Netserv::Tls; the daemons resolve the per-protocol material at boot.
    class Server
      # Reap dead peers at the TCP layer (Postal's timings): first probe
      # after 50s idle, then every 10s, gone after 5 unanswered probes -
      # ~100s to reclaim a half-open connection's ConnLimiter slot instead
      # of waiting out the sessions' 300s idle timeout.
      KEEPALIVE_IDLE = 50
      KEEPALIVE_INTERVAL = 10
      KEEPALIVE_PROBES = 5

      # Per-IP anti-abuse defaults; protocol subclasses override (with
      # env-driven values). nil/0 disables.
      MAX_CONNECTIONS_PER_IP = nil
      AUTH_LOCKOUT_FAILURES = nil
      AUTH_LOCKOUT_SECONDS = 900
      CONN_RATE_LIMIT = nil
      CONN_RATE_WINDOW = 60
      # Absolute cap on one connection's lifetime, seconds. The sessions'
      # read timeouts are per-read, so a peer trickling bytes (slowloris)
      # holds its thread and ConnLimiter slot indefinitely; the reaper
      # thread force-closes anything older than this regardless of how
      # "active" it looks. nil/0 disables; per-listener
      # spec[:session_lifetime] overrides.
      SESSION_LIFETIME = nil

      # Cap on the implicit-TLS handshake. The session's own idle timeout
      # is only set once the session runs - after TLS.accept - so without
      # this bound a connected-but-silent peer parks its thread forever and
      # its ConnLimiter slot leaks (TCP keepalive only reaps dead peers,
      # not alive-and-idle ones). Overridable per listener via
      # spec[:handshake_timeout].
      HANDSHAKE_TIMEOUT = 30

      # Cadence of the ops-state sync thread (Netserv::OpsSync), seconds.
      # nil = the live Settings[:ops_sync_interval]; test servers pin a
      # small constant.
      OPS_SYNC_INTERVAL = nil

      # One live connection's registry entry. peer_ip/spec/connected_at are
      # fixed at accept time; thread and session are filled in as the
      # connection comes up (spawn_session / handle). The session reference
      # is what lets #connections report protocol-level state (user, HELO,
      # ...) without the registry having to track it. started_at is the
      # monotonic twin of connected_at - the reaper measures age against a
      # clock a step of the wall clock can't fool. tarpit is the delay the
      # RateLimiter served this connection (nil when none), kept so the ops
      # UI can mark slowed connections live and in the history log. id is
      # the per-listener sequence number that keys the connection's
      # open_connections row.
      Conn = Struct.new(:thread, :session, :peer_ip, :spec, :connected_at, :started_at, :tarpit, :id)

      def self.run(store, listeners, tls_material)
        new(store, listeners, tls_material).run
      end

      def initialize(store, listeners, tls_material)
        @store = store
        @listeners = listeners
        @tls_material = tls_material
        # The guards keep their per-IP state for the server's lifetime;
        # their limits are lambdas resolved per check, so a settings change
        # retunes them live without wiping counts or lockouts.
        @limiter = ConnLimiter.new(-> { max_connections }, per_ip: -> { max_connections_per_ip })
        @throttle = AuthThrottle.new(limit: -> { auth_lockout_failures },
                                     window: -> { auth_lockout_seconds })
        @rate = RateLimiter.new(limit: -> { conn_rate_limit },
                                window: -> { conn_rate_window })
        @denylist = Denylist.new(store)
        # The ops-state projection (live connections, lockouts, heartbeat,
        # kicks) - see Netserv::OpsSync. Its interval is the class constant
        # when a test server pins one, else the live setting.
        @ops = OpsSync.new(self, store, interval: -> { self.class::OPS_SYNC_INTERVAL })
        # Lifecycle state shared between the accept threads, the connection
        # threads, and the host's boot/shutdown calls.
        @lifecycle = Mutex.new
        @lifecycle_cv = ConditionVariable.new
        @listener_sockets = []
        @listener_threads = []
        @sessions = {} # raw accepted socket => Conn
        @expected_listeners = nil
        @bound_listeners = 0
        @stopping = false
      end

      def run
        # Build the context at boot so TLS problems surface here, not on
        # the first connection.
        @tls = @tls_material && Tls::ContextProvider.new(@tls_material)

        active = @listeners.reject { |spec| spec[:tls] == :implicit && @tls.nil? }
        @lifecycle.synchronize do
          @expected_listeners = active.size
          @lifecycle_cv.broadcast
        end
        threads = active.map do |spec|
          session_spec = spec.slice(:host, :port, :tls, :role, :hostname, :trace,
                                    :handshake_timeout, :session_lifetime, :honeypot_banner).freeze
          Thread.new(spec) { |listener| accept_loop(listener, session_spec) }
        end
        @lifecycle.synchronize { @listener_threads = threads }
        start_session_reaper(active)
        @ops.start
        @store.log(:info, "#{protocol_name} listening: #{@listeners.map { |s| listener_label(s) }.join(", ")}")
        threads.each(&:join)
      end

      # This server's identity in the ops tables (one UUID per instance).
      def listener_id = @ops.listener_id

      # The ports this server was configured to bind (ints), for the
      # listener row.
      def listener_ports
        @listeners.map { |spec| spec[:port] }.compact
      end

      # The accept-side denylist (admin bans); OpsSync kicks live sessions
      # it now matches.
      attr_reader :denylist

      # True once every listener socket is bound - the host process must
      # not report itself healthy before this (a deploy health check that
      # passes with unbound mail ports would resume traffic too early).
      def ready?
        @lifecycle.synchronize { ready_locked? }
      end

      # False once any listener's accept thread has died - a bind failure
      # or a crashed accept loop. accept_loop rescues, logs and ends its
      # own thread while `run` keeps joining the others, so without this
      # probe a server missing one of its ports still looks alive
      # (`ready?` never decrements). Vacuously true before `run` starts
      # the threads: readiness is ready?'s job, this catches death. The
      # Runtime monitor restarts an unhealthy server.
      def healthy?
        @lifecycle.synchronize { @listener_threads.none? { |thread| !thread.alive? } }
      end

      # True once every listener thread has ended (after run started them):
      # the server is over, whether or not shutdown ran. The ops thread
      # stops ticking on this.
      def dead?
        @lifecycle.synchronize { @listener_threads.any? && @listener_threads.none?(&:alive?) }
      end

      # Blocks up to +timeout+ seconds for every listener to bind. False on
      # timeout or shutdown; a listener that died binding never signals, so
      # a boot problem surfaces here rather than hanging the host.
      def wait_ready(timeout = 15)
        deadline = monotonic + timeout
        @lifecycle.synchronize do
          until ready_locked?
            remaining = deadline - monotonic
            return false if remaining <= 0 || @stopping

            @lifecycle_cv.wait(@lifecycle, remaining)
          end
          true
        end
      end

      # Graceful stop: close the listeners (no new connections), give live
      # sessions +drain+ seconds to finish on their own, then force-close
      # the stragglers' sockets - which raises in their blocked reads and
      # unwinds them through their normal ensure paths. Store operations
      # already in progress complete either way (only socket IO raises), so
      # nothing is half-written; an interrupted client reconnects or, for
      # SMTP, retries. No goodbye line is written: sessions may be mid-TLS,
      # and a concurrent write on their SSL socket from this thread is not
      # safe.
      def shutdown(drain: 5)
        listeners = @lifecycle.synchronize do
          @stopping = true
          @lifecycle_cv.broadcast
          @listener_sockets.dup
        end
        listeners.each { |socket| close_quietly(socket) }

        deadline = monotonic + drain
        @lifecycle.synchronize do
          while @sessions.any? && (remaining = deadline - monotonic) > 0
            @lifecycle_cv.wait(@lifecycle, remaining)
          end
        end

        stragglers = @lifecycle.synchronize { @sessions.to_a }
        @store.log(:info, "#{protocol_name} closing #{stragglers.size} sessions after #{drain}s drain") if stragglers.any?
        stragglers.each { |socket, _conn| close_quietly(socket) }
        stragglers.each { |_socket, conn| conn.thread&.join(2) }
        # Last: the ops thread's final cleanup removes this listener's rows
        # so the dashboard does not wait out the stale window.
        @ops.stop
      end

      # Snapshot of the live connections for the ops UI: an array of
      # plain-value Hashes - no sockets or threads escape. Registry fields
      # are copied under the lifecycle lock; the session-side fields (user,
      # protocol state) come from Session#live_info, which reads the
      # session thread's own ivars - racy by design, and a momentarily
      # stale row costs a dashboard nothing.
      def connections
        entries = @lifecycle.synchronize { @sessions.values.map { |conn| [ conn.dup, conn.session ] } }
        entries.map do |conn, session|
          { protocol: protocol_name, connection_id: conn.id, peer_ip: conn.peer_ip,
            port: conn.spec[:port], role: conn.spec[:role],
            connected_at: conn.connected_at,
            tarpit: conn.tarpit }.merge(session ? session.live_info : {})
        end
      end

      # Tells the host the live-connection picture changed, via the
      # MailOnRails.on_connection_activity seam. Called by OpsSync after it
      # has written the changed picture (so a dashboard refresh never
      # races the rows it announces), never from accept or connection
      # threads. Resolved through respond_to? because the netserv tree
      # also boots stdlib-only, without the Rails-glue module attributes.
      # Best-effort: a dashboard hook must never disturb a listener, so
      # exceptions are logged and dropped.
      def notify_activity
        return unless MailOnRails.respond_to?(:on_connection_activity)

        hook = MailOnRails.on_connection_activity
        return unless hook

        @protocol_key ||= protocol_name.downcase.to_sym
        hook.call(@protocol_key)
      rescue StandardError => e
        begin
          @store.log(:warn, "#{protocol_name} connection-activity hook failed: #{e.class}: #{e.message}")
        rescue StandardError
          nil
        end
      end

      # Snapshot of the AuthThrottle's current per-IP lockouts for the ops
      # UI: { ip => seconds remaining }. Refused connections from these
      # addresses never become sessions, so without this they would be
      # invisible to the dashboard.
      def lockouts
        @throttle.locked_ips
      end

      # Force-closes live connections whose peer IP the caller's test
      # matches (an admin ban: the accept-side denylist only stops future
      # connections). Closing the raw socket raises in the session's
      # blocked read and unwinds it through handle's ensure, releasing its
      # limiter slot. Returns how many connections were closed.
      def kick(&matcher)
        victims = @lifecycle.synchronize do
          @sessions.filter_map { |socket, conn| socket if conn.peer_ip && matcher.call(conn.peer_ip) }
        end
        victims.each { |socket| close_quietly(socket) }
        victims.size
      end

      # Reloads the denylist from the store right now, bypassing its poll
      # interval - the Rails side calls this (via Runtime) after a
      # BannedIp commit, so a new ban is enforced on the very next
      # connection rather than up to Denylist::TTL seconds later.
      def refresh_denylist
        @denylist.refresh!
      end

      # -- accept-side limits ------------------------------------------------
      #
      # Resolved per check through the guards' lambdas. The protocol
      # servers override these with settings-schema reads so an admin's
      # change applies to the next accept without a restart; the base
      # reads the legacy class constants, which doubles as the test seam
      # (a bespoke server subclass sets MAX_CONNECTIONS = 1 and so on).
      # Public because the host's ops UI reports the caps alongside the
      # live connection list.

      def max_connections = self.class::MAX_CONNECTIONS
      def max_connections_per_ip = self.class::MAX_CONNECTIONS_PER_IP
      def auth_lockout_failures = self.class::AUTH_LOCKOUT_FAILURES
      def auth_lockout_seconds = self.class::AUTH_LOCKOUT_SECONDS
      def conn_rate_limit = self.class::CONN_RATE_LIMIT
      def conn_rate_window = self.class::CONN_RATE_WINDOW

      private

      # The protocol servers' limit readers: a constant defined on the
      # concrete class at or below +anchor+ (the protocol server) wins -
      # the seam every bespoke test server uses - otherwise the fallback
      # block supplies the live settings value.
      def tunable(const_name, anchor)
        klass = self.class
        loop do
          return klass.const_get(const_name, false) if klass.const_defined?(const_name, false)
          break if klass == anchor

          klass = klass.superclass
        end
        yield
      end

      def ready_locked?
        !@stopping && @expected_listeners && @bound_listeners >= @expected_listeners
      end

      def stopping?
        @lifecycle.synchronize { @stopping }
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # -- session reaper ----------------------------------------------------
      #
      # One thread sweeping the registry for connections past their
      # absolute lifetime. Closing the raw socket raises in the session's
      # blocked read and unwinds it through handle's ensure (the same
      # mechanism kick and shutdown use); no goodbye line is written, for
      # shutdown's reason - the session may be mid-TLS. Not started when
      # nothing configures a lifetime, which keeps the IMAP server (whose
      # IDLE connections are long-lived by design) reaper-free by default.

      def start_session_reaper(specs)
        lifetimes = specs.map { |spec| spec.fetch(:session_lifetime) { self.class::SESSION_LIFETIME } }
                         .select { |lifetime| lifetime&.positive? }
        return if lifetimes.empty?

        # Sweep often enough that no connection outlives its cap by more
        # than a fraction; the cv wait (not sleep) lets shutdown's
        # broadcast end the thread promptly.
        interval = (lifetimes.min / 4.0).clamp(0.05, 30)
        Thread.new do
          loop do
            @lifecycle.synchronize do
              @lifecycle_cv.wait(@lifecycle, interval) unless @stopping
            end
            break if stopping?

            reap_expired_sessions
          end
        end
      end

      def reap_expired_sessions
        now = monotonic
        victims = @lifecycle.synchronize do
          @sessions.filter_map do |socket, conn|
            lifetime = conn.spec.fetch(:session_lifetime) { self.class::SESSION_LIFETIME }
            [ socket, conn ] if lifetime&.positive? && now - conn.started_at > lifetime
          end
        end
        victims.each do |socket, conn|
          @store.log(:warn, "#{protocol_name} closing connection from #{conn.peer_ip}: session lifetime exceeded")
          close_quietly(socket)
        end
      end

      def record_auth_failure(ip)
        return unless @throttle.record(ip) == :locked

        @store.log(:warn, "#{protocol_name} locking out #{ip} for #{auth_lockout_seconds}s " \
                          "after #{auth_lockout_failures} failed authentication attempts")
        # The dashboard's locked-out table just grew a row; OpsSync's next
        # tick writes and announces it.
      end

      def accept_loop(spec, session_spec)
        server = spec[:tcp_server] || build_listener(spec[:host], spec[:port])
        @lifecycle.synchronize do
          @listener_sockets << server
          @bound_listeners += 1
          @lifecycle_cv.broadcast
        end
        loop do
          # Socket#accept returns [socket, Addrinfo] and destructures;
          # an injected TCPServer (tests) returns just the socket, so
          # addr is nil and peer_ip falls back to getpeername.
          socket, addr = server.accept
          ip = peer_ip(socket, addr)
          # Admin-banned addresses (the Rails app's BannedIp) get a bare
          # close before any banner or limiter slot - a banned scanner
          # earns silence, not a banner.
          if @denylist.banned?(ip)
            close_quietly(socket)
            next
          end
          tune_keepalive(socket)
          delay = @rate.delay(ip) # every attempt counts, even ones refused below
          if @throttle.locked?(ip)
            reject(socket, locked_line) # before acquire: locked IPs must not consume slots
          elsif @limiter.acquire(ip)
            spawn_session(socket, session_spec, ip, delay)
          else
            reject(socket, busy_line)
          end
        end
      rescue StandardError => e
        @store.log(:error, "#{protocol_name} listener #{spec[:port]} died: #{e.class}: #{e.message}") unless stopping?
      end

      def spawn_session(socket, session_spec, ip, delay)
        tarpit = delay&.positive? ? delay : nil
        conn = Conn.new(nil, nil, ip, session_spec, Time.now, monotonic, tarpit, @ops.next_connection_id)
        @lifecycle.synchronize { @sessions[socket] = conn }
        thread = Thread.new { handle(socket, session_spec, ip, delay) }
        # The session may already have finished and deregistered itself;
        # only record the thread while the registration is still live.
        @lifecycle.synchronize { @sessions[socket]&.thread = thread }
      rescue StandardError # ThreadError: out of threads; keep accepting
        @lifecycle.synchronize { @sessions.delete(socket) }
        @limiter.release(ip)
        close_quietly(socket)
      end

      # Runs on the connection's own thread. +raw+ stays the registry key
      # even after a TLS upgrade swaps the working socket.
      def handle(raw, spec, ip, delay)
        socket = raw
        # Tarpit (RateLimiter's verdict): served before the TLS handshake
        # and banner. The sleeping connection keeps holding its ConnLimiter
        # slot - that is the cost to the flooding peer.
        sleep(delay) if delay&.positive?
        ctx = @tls&.context
        if spec[:tls] == :implicit && ctx
          socket.timeout = spec[:handshake_timeout] || HANDSHAKE_TIMEOUT if socket.respond_to?(:timeout=)
          socket = Tls.accept(socket, ctx)
        end
        session = session_class.new(socket, @store, spec, ctx)
        # Seed the accept-time address so session logs and policy checks
        # (SPF, DNSBL) don't re-derive it via getpeername.
        session.peer_ip = ip if ip && session.respond_to?(:peer_ip=)
        # Sessions that support it report failed AUTHs so the per-IP
        # throttle sees attempts across connections.
        if ip && session.respond_to?(:on_auth_failure=)
          session.on_auth_failure = -> { record_auth_failure(ip) }
        end
        # And re-read the throttle's verdict per attempt: the accept-side
        # locked_line check only guards NEW connections, so sessions already
        # open when the IP locks would otherwise keep their full
        # per-connection attempt budget (times MAX_CONNECTIONS_PER_IP).
        if ip && session.respond_to?(:auth_locked=)
          session.auth_locked = -> { @throttle.locked?(ip) }
        end
        @lifecycle.synchronize { @sessions[raw]&.session = session }
        session.run
      rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
        nil # session logs its own protocol-level errors; this is connection debris
      ensure
        begin
          socket.close
        rescue StandardError
          nil
        end
        @limiter.release(ip)
        # Report before deregistering: shutdown's drain waits on @sessions
        # emptying, so the history row must be written while this session
        # still counts as live - otherwise stop_servers can return with the
        # insert still in flight.
        conn = @lifecycle.synchronize { @sessions[raw] }
        report_closed(conn)
        report_honeypot(conn)
        @lifecycle.synchronize do
          @sessions.delete(raw)
          @lifecycle_cv.broadcast
        end
      end

      # Hands the finished connection to the store's history log (the
      # Rails UI's closed-connections table), when the store keeps one -
      # the vendored memory stores don't, hence the respond_to? guard.
      # Runs on the dying connection thread after the limiter slot is
      # back; best-effort, so a history problem can never disturb a
      # teardown.
      def report_closed(conn)
        return unless conn && @store.respond_to?(:record_closed_connection)

        now = Time.now
        info = { protocol: protocol_name.downcase, ip: conn.peer_ip,
                 port: conn.spec[:port], role: conn.spec[:role],
                 connected_at: conn.connected_at, closed_at: now,
                 duration_seconds: now - conn.connected_at,
                 tarpit_seconds: conn.tarpit }
        info.merge!(conn.session.live_info) if conn.session
        # Sessions that capture transcripts (smtp_trace_capture) hand one
        # over here; the store persists it alongside the history row so
        # the /smtp page can link the two.
        if conn.session.respond_to?(:transcript_capture) && (capture = conn.session.transcript_capture)
          info.merge!(capture)
        end
        @store.record_closed_connection(info)
      rescue StandardError
        nil
      end

      # Flushes a triggered honeypot session's full transcript at teardown (the
      # ban and initial event already landed when it triggered mid-session).
      # No-ops for a session that never triggered. Best-effort like
      # report_closed - a honeypot problem can never disturb a teardown.
      def report_honeypot(conn)
        session = conn&.session
        session.finalize_honeypot if session.respond_to?(:finalize_honeypot)
      rescue StandardError
        nil
      end

      # The listener is a plain Socket rather than a TCPServer because
      # Socket#accept hands back the Addrinfo that accept(2) itself
      # captured. TCPServer#accept discards it, leaving only getpeername -
      # which raises ENOTCONN once a scanner's immediate RST lands, so
      # those connections used to show up with no IP at all.
      def build_listener(host, port)
        addr = Addrinfo.tcp(host, port)
        server = Socket.new(addr.afamily, :STREAM)
        server.setsockopt(:SOCKET, :REUSEADDR, true)
        # An IPv6 bind serves IPv4 too (v4-mapped addresses), so "::" is a
        # true dual-stack listener even where the platform defaults
        # IPV6_V6ONLY on. Best-effort: a platform without the option just
        # keeps its default.
        if addr.ipv6?
          begin
            server.setsockopt(:IPV6, :V6ONLY, false)
          rescue StandardError
            nil
          end
        end
        server.bind(addr)
        server.listen(Socket::SOMAXCONN)
        server
      end

      # The peer address at accept time, threaded through to the release
      # path so both sides of the per-IP accounting use the same key.
      # Prefers the Addrinfo accept(2) reported (valid even for an
      # already-reset peer); the getpeername fallback covers injected
      # test listeners, where a vanished peer still yields nil (and nil
      # never matches a denylist entry).
      def peer_ip(socket, addr = nil)
        (addr || socket.remote_address).ip_address
      rescue StandardError
        nil
      end

      # TCP_KEEP* constants are platform-dependent (macOS has no
      # TCP_KEEPIDLE); missing ones just mean kernel-default timings.
      def tune_keepalive(socket)
        socket.setsockopt(:SOCKET, :KEEPALIVE, true)
        socket.setsockopt(:TCP, :KEEPIDLE, KEEPALIVE_IDLE) if Socket.const_defined?(:TCP_KEEPIDLE)
        socket.setsockopt(:TCP, :KEEPINTVL, KEEPALIVE_INTERVAL) if Socket.const_defined?(:TCP_KEEPINTVL)
        socket.setsockopt(:TCP, :KEEPCNT, KEEPALIVE_PROBES) if Socket.const_defined?(:TCP_KEEPCNT)
      rescue SystemCallError
        nil
      end

      def reject(socket, line)
        socket.write("#{line}\r\n")
        socket.close
      rescue StandardError
        nil
      end

      def close_quietly(socket)
        socket.close
      rescue StandardError
        nil
      end

      # Sent to connections from locked-out IPs; protocol subclasses may
      # override with a more specific message.
      def locked_line = busy_line
    end
  end
end
