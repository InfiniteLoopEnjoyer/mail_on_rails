# frozen_string_literal: true

require "socket"
require_relative "conn_limiter"
require_relative "denylist"
require_relative "tls"

module MailOnRails
  module Imap
    # Shared listener scaffolding for the SMTP and IMAP servers: one accept
    # thread per listener spec, one thread per connection, a connection cap,
    # and TLS material handling. Keeping this in one place means the
    # connection-flood and TLS-accept behavior can't drift apart between the
    # two protocols.
    #
    # Sessions do not run on the accept threads. Each accepted socket gets
    # its own thread: implicit-TLS handshake first (capped so a silent
    # client can't hold the thread), then the protocol session, which does
    # plain blocking IO under the session's own IO#timeout idle limit. The
    # ConnLimiter caps live connection threads process-wide; slots are
    # released in the connection thread's ensure.
    #
    # Subclasses define MAX_CONNECTIONS and the protocol specifics:
    # protocol_name, busy_line (sent when the connection cap is hit),
    # listener_label(spec) and session_class.
    class Server
      # Reap dead peers at the TCP layer (Postal's timings): first probe
      # after 50s idle, then every 10s, gone after 5 unanswered probes -
      # ~100s to reclaim a half-open connection's ConnLimiter slot instead
      # of waiting out the sessions' 1800s idle timeout, which matters even
      # more for IMAP's long-lived connections than it does for SMTP.
      KEEPALIVE_IDLE = 50
      KEEPALIVE_INTERVAL = 10
      KEEPALIVE_PROBES = 5

      # A client that connects and then never speaks TLS gets this long to
      # finish the implicit-TLS handshake before its thread and limiter
      # slot are reclaimed.
      TLS_HANDSHAKE_TIMEOUT = 30

      # One live connection's registry entry. peer_ip/spec/connected_at are
      # fixed at accept time; thread and session are filled in as the
      # connection comes up (spawn_session / handle). The session reference
      # is what lets #connections report protocol-level state (user, IDLE,
      # ...) without the registry having to track it.
      Conn = Struct.new(:thread, :session, :peer_ip, :spec, :connected_at)

      def self.run(store, listeners, tls_material)
        new(store, listeners, tls_material).run
      end

      def initialize(store, listeners, tls_material)
        @store = store
        @listeners = listeners
        @tls_material = tls_material
        @limiter = ConnLimiter.new(self.class::MAX_CONNECTIONS)
        @denylist = Denylist.new(ENV["MAIL_ON_RAILS_IMAP_DENYLIST_FILE"])
        # Lifecycle state shared between the accept threads, the connection
        # threads, and the host's boot/shutdown calls.
        @lifecycle = Mutex.new
        @lifecycle_cv = ConditionVariable.new
        @listener_sockets = []
        @sessions = {} # raw accepted socket => Conn
        @expected_listeners = nil
        @bound_listeners = 0
        @stopping = false
      end

      def run
        # Build the context at boot so TLS problems surface here, not on the
        # first connection.
        @tls = @tls_material && TLS::ContextProvider.new(@tls_material)

        active = @listeners.reject { |spec| spec[:tls] == :implicit && @tls.nil? }
        @lifecycle.synchronize do
          @expected_listeners = active.size
          @lifecycle_cv.broadcast
        end
        threads = active.map do |spec|
          Thread.new(spec) { |listener| accept_loop(listener, listener.slice(:host, :port, :tls).freeze) }
        end
        @store.log(:info, "#{protocol_name} listening: #{@listeners.map { |s| listener_label(s) }.join(", ")}")
        threads.each(&:join)
      end

      # True once every listener socket is bound - the host process must
      # not report itself healthy before this (a deploy health check that
      # passes with unbound mail ports would resume traffic too early).
      def ready?
        @lifecycle.synchronize { ready_locked? }
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
          { protocol: protocol_name, peer_ip: conn.peer_ip,
            port: conn.spec[:port], role: conn.spec[:role],
            connected_at: conn.connected_at }.merge(session ? session.live_info : {})
        end
      end

      # Force-closes live connections whose peer IP the caller's test
      # matches (an admin ban: the accept-side denylist only stops future
      # connections, and an IMAP session can otherwise idle on for another
      # half hour). Closing the raw socket raises in the session's blocked
      # read and unwinds it through handle's ensure, releasing its limiter
      # slot. Returns how many connections were closed.
      def kick(&matcher)
        victims = @lifecycle.synchronize do
          @sessions.filter_map { |socket, conn| socket if conn.peer_ip && matcher.call(conn.peer_ip) }
        end
        victims.each { |socket| close_quietly(socket) }
        victims.size
      end

      private

      def ready_locked?
        !@stopping && @expected_listeners && @bound_listeners >= @expected_listeners
      end

      def stopping?
        @lifecycle.synchronize { @stopping }
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def accept_loop(spec, session_spec)
        server = spec[:tcp_server] || TCPServer.new(spec[:host], spec[:port])
        @lifecycle.synchronize do
          @listener_sockets << server
          @bound_listeners += 1
          @lifecycle_cv.broadcast
        end
        loop do
          socket = server.accept
          ip = peer_ip(socket)
          # Admin-banned addresses (the Rails app's BannedIp) get a bare
          # close before any greeting or limiter slot - a banned scanner
          # earns silence, not a banner. No release needed: nothing was
          # acquired.
          if @denylist.banned?(ip)
            close_quietly(socket)
            next
          end
          tune_keepalive(socket)
          if @limiter.acquire
            spawn_session(socket, session_spec, ip)
          else
            reject_busy(socket)
          end
        end
      rescue StandardError => e
        @store.log(:error, "#{protocol_name} listener #{spec[:port]} died: #{e.class}: #{e.message}") unless stopping?
      end

      def spawn_session(socket, session_spec, ip)
        @lifecycle.synchronize { @sessions[socket] = Conn.new(nil, nil, ip, session_spec, Time.now) }
        thread = Thread.new { handle(socket, session_spec) }
        # The session may already have finished and deregistered itself;
        # only record the thread while the registration is still live.
        @lifecycle.synchronize { @sessions[socket]&.thread = thread }
      rescue StandardError # ThreadError: out of threads; keep accepting
        @lifecycle.synchronize { @sessions.delete(socket) }
        @limiter.release
        close_quietly(socket)
      end

      # Runs on the connection's own thread. +raw+ stays the registry key
      # even after a TLS upgrade swaps the working socket.
      def handle(raw, spec)
        socket = raw
        ctx = @tls&.context
        if spec[:tls] == :implicit && ctx
          io_timeout(socket, TLS_HANDSHAKE_TIMEOUT)
          socket = TLS.accept(socket, ctx)
        end
        session = session_class.new(socket, @store, spec, ctx)
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
        @limiter.release
        conn = @lifecycle.synchronize do
          @sessions.delete(raw).tap { @lifecycle_cv.broadcast }
        end
        report_closed(conn)
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
                 duration_seconds: now - conn.connected_at }
        @store.record_closed_connection(info.merge(conn.session ? conn.session.live_info : {}))
      rescue StandardError
        nil
      end

      def io_timeout(socket, seconds)
        socket.timeout = seconds if socket.respond_to?(:timeout=)
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

      def reject_busy(socket)
        socket.write("#{busy_line}\r\n")
        socket.close
      rescue StandardError
        nil
      end

      # nil rather than "?" on failure so an address we couldn't read can
      # never match a denylist entry (same care as Session#throttle_ip).
      def peer_ip(socket)
        socket.remote_address.ip_address
      rescue StandardError
        nil
      end

      def close_quietly(socket)
        socket.close
      rescue StandardError
        nil
      end
    end
  end
end
