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
        @sessions = {} # raw accepted socket => connection thread
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
        stragglers.each { |socket, _thread| close_quietly(socket) }
        stragglers.each { |_socket, thread| thread&.join(2) }
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
          # Admin-banned addresses (the Rails app's BannedIp) get a bare
          # close before any greeting or limiter slot - a banned scanner
          # earns silence, not a banner. No release needed: nothing was
          # acquired.
          if @denylist.banned?(peer_ip(socket))
            close_quietly(socket)
            next
          end
          tune_keepalive(socket)
          if @limiter.acquire
            spawn_session(socket, session_spec)
          else
            reject_busy(socket)
          end
        end
      rescue StandardError => e
        @store.log(:error, "#{protocol_name} listener #{spec[:port]} died: #{e.class}: #{e.message}") unless stopping?
      end

      def spawn_session(socket, session_spec)
        @lifecycle.synchronize { @sessions[socket] = nil }
        thread = Thread.new { handle(socket, session_spec) }
        # The session may already have finished and deregistered itself;
        # only record the thread while the registration is still live.
        @lifecycle.synchronize { @sessions[socket] = thread if @sessions.key?(socket) }
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
        session_class.new(socket, @store, spec, ctx).run
      rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
        nil # session logs its own protocol-level errors; this is connection debris
      ensure
        begin
          socket.close
        rescue StandardError
          nil
        end
        @limiter.release
        @lifecycle.synchronize do
          @sessions.delete(raw)
          @lifecycle_cv.broadcast
        end
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
