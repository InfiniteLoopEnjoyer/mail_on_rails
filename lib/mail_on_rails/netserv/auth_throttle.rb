# frozen_string_literal: true

module MailOnRails
  module Netserv
    # Per-IP lockout for repeated authentication failures. A session can only
    # count its own attempts (MAX_AUTH_ATTEMPTS per connection), so a client
    # that reconnects gets a fresh allowance - and every guess costs the host
    # app an HTTP credential check. This throttle spans connections.
    #
    # Lives on the accept side, where the state is shared across every
    # connection: sessions report failures upward through on_auth_failure
    # and the accept loop refuses connections from locked-out IPs outright
    # with the protocol's locked_line. Tempfail semantics
    # are deliberate: if a NAT/shared IP hosts both an abuser and a
    # legitimate sender, the legitimate mail is delayed for the lockout
    # window, never lost.
    #
    # +limit+ failures within +window+ seconds locks the IP for +window+
    # seconds from its last failure; a quiet gap of +window+ seconds forgives
    # the count. A nil/0 limit disables the throttle. +clock+ is injectable
    # for tests and must be monotonic.
    #
    # limit/window may be plain values or callables resolved per check (the
    # servers pass settings-backed lambdas, so retuning applies to the next
    # failure/lookup without a restart and without wiping the recorded
    # failure history). Callables are resolved before the mutex so a slow
    # settings source can never stall the accept path.
    class AuthThrottle
      SWEEP_THRESHOLD = 1_000 # purge expired entries when the table grows past this

      Entry = Struct.new(:count, :last_at, :locked_until)

      def initialize(limit:, window:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @limit = limit
        @window = window
        @clock = clock
        @entries = {}
        @mutex = Mutex.new
      end

      # Records one failed authentication attempt. Returns :locked on exactly
      # the attempt that trips the lockout, so the caller can log the
      # transition once; further failures while locked (from sessions already
      # in flight) extend the lockout silently.
      def record(ip)
        limit = current_limit
        return nil unless limit && ip

        window = current_window
        now = @clock.call
        @mutex.synchronize do
          sweep(now, window) if @entries.size > SWEEP_THRESHOLD
          entry = (@entries[ip] ||= Entry.new(0, now, nil))
          entry.count = 0 if now - entry.last_at > window # quiet period forgives
          entry.count += 1
          entry.last_at = now
          if entry.count >= limit
            newly = entry.count == limit
            entry.locked_until = now + window
            newly ? :locked : nil
          end
        end
      end

      def locked?(ip)
        return false unless current_limit && ip

        now = @clock.call
        @mutex.synchronize do
          locked_until = @entries[ip]&.locked_until
          !locked_until.nil? && locked_until > now
        end
      end

      # Snapshot of the addresses currently locked out, for the ops UI:
      # { ip => seconds remaining }, longest remaining first. Plain values
      # only - nothing mutable escapes the mutex.
      def locked_ips
        return {} unless current_limit

        now = @clock.call
        locked = @mutex.synchronize do
          @entries.filter_map do |ip, e|
            [ ip, e.locked_until - now ] if e.locked_until && e.locked_until > now
          end
        end
        locked.sort_by { |_, remaining| -remaining }.to_h
      end

      private

      def current_limit
        limit = @limit.respond_to?(:call) ? @limit.call : @limit
        limit&.positive? ? limit : nil
      end

      def current_window
        (@window.respond_to?(:call) ? @window.call : @window).to_f
      end

      # Drops entries whose lockout and failure window have both expired.
      def sweep(now, window)
        @entries.delete_if do |_ip, e|
          (e.locked_until.nil? || e.locked_until <= now) && now - e.last_at > window
        end
      end
    end
  end
end
