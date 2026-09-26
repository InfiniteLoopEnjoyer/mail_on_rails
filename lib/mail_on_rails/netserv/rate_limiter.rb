# frozen_string_literal: true

require "ipaddr"
require_relative "ip"

module MailOnRails
  module Netserv
    # Per-IP sliding-window connection rate, answered with an escalating
    # tarpit delay rather than a refusal. Completes the per-IP anti-abuse
    # set: ConnLimiter caps concurrent connections, AuthThrottle locks out
    # credential guessing, and this slows connection churn (bots that open,
    # send, and reconnect fast to stay under the concurrent cap).
    #
    # Within +limit+ connections per +window+ seconds the delay is zero.
    # Each connection beyond the limit doubles it - base_delay, 2x, 4x, ...
    # capped at max_delay - and the delay is served before the banner on
    # the session's own connection thread, never on an accept thread. A
    # tarpitted connection holds its ConnLimiter slot while it waits, so
    # together with the per-IP concurrent cap C this bounds a flood to
    # C/max_delay connections per second without ever hard-refusing a
    # legitimate burst.
    #
    # Lives on the accept side like the other two, so the counts stay
    # exact process-wide. Keys on Netserv.throttle_key (the /64 for IPv6).
    # A nil/0 limit disables. +clock+ is injectable for tests and must be
    # monotonic.
    class RateLimiter
      BASE_DELAY = 1.0
      MAX_DELAY = 16.0
      OVERAGE_MEMORY = 64 # timestamps kept per IP beyond the limit; deeper is at max delay anyway
      SWEEP_THRESHOLD = 1_000 # purge idle IPs when the table grows past this
      SWEEP_INTERVAL = 1.0 # ...but at most this often: a sweep is O(n) on the accept path
      # Hard ceiling on tracked keys, applied to the two tables separately:
      # past it the least recently seen WITHIN-BUDGET key is evicted, never
      # a tarpitted one - a flood of single connections from 50k distinct
      # /64s must not wash out the tarpits it is trying to escape. The
      # tarpitted table has the same ceiling, so a flood that earns 50k
      # tarpits evicts its own oldest first; total memory is bounded at 2x
      # and no accept ever turns into a full-table walk.
      MAX_ENTRIES = 50_000

      # limit/window may be plain values or callables resolved per check
      # (the servers pass settings-backed lambdas, so retuning applies to
      # the next connection without a restart and without dropping the
      # recorded timestamps). Callables are resolved before the mutex so a
      # slow settings source can never stall the accept path.
      def initialize(limit:, window:, base_delay: BASE_DELAY, max_delay: MAX_DELAY,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @limit = limit
        @window = window
        @base_delay = base_delay
        @max_delay = max_delay
        @clock = clock
        @entries = {} # within-budget key => connection timestamps within the window, oldest first; LRU order
        @tarpitted = {} # over-budget key => the same, earliest tarpitted first
        @last_sweep = nil
        @mutex = Mutex.new
      end

      # Records one connection attempt from +ip+ and returns the tarpit
      # delay in seconds (0.0 while within budget). Every attempt counts,
      # including ones the caller goes on to refuse - a peer bouncing off
      # the concurrent cap is exactly the churn this measures. Loopback
      # peers are exempt (healthchecks and embedded development connect
      # from 127.0.0.1 at machine rates; Postfix likewise exempts
      # $mynetworks from its client rate limits).
      def delay(ip)
        limit = current_limit
        return 0.0 unless limit && ip
        return 0.0 if loopback?(ip)

        window = current_window
        now = @clock.call
        key = Netserv.throttle_key(ip)
        @mutex.synchronize do
          sweep(now, window, limit) if @entries.size + @tarpitted.size > SWEEP_THRESHOLD && sweep_due?(now)
          stamps = @tarpitted.delete(key) || @entries.delete(key) || []
          stamps.shift while stamps.any? && now - stamps.first > window
          stamps.shift if stamps.size >= limit + OVERAGE_MEMORY # bound per-IP memory
          stamps << now
          over = stamps.size - limit
          # Re-inserting moves the key to the end of its table: Hash keeps
          # insertion order, so the front is always the least recently
          # seen (or the earliest tarpitted).
          if over <= 0
            @entries[key] = stamps
            @entries.shift while @entries.size > MAX_ENTRIES
            0.0
          else
            @tarpitted[key] = stamps
            @tarpitted.shift while @tarpitted.size > MAX_ENTRIES
            [ @base_delay * (2**[ over - 1, 10 ].min), @max_delay ].min
          end
        end
      end

      private

      def current_limit
        limit = @limit.respond_to?(:call) ? @limit.call : @limit
        limit&.positive? ? limit : nil
      end

      def current_window
        (@window.respond_to?(:call) ? @window.call : @window).to_f
      end

      def loopback?(ip)
        IPAddr.new(ip).loopback?
      rescue IPAddr::InvalidAddressError
        false # not an IP; still rate-limited under its own key
      end

      def sweep_due?(now)
        @last_sweep.nil? || now - @last_sweep >= SWEEP_INTERVAL
      end

      # Drops IPs whose every timestamp has aged out of the window, and
      # returns a tarpitted IP to the idle table once enough of its
      # timestamps have aged out that it is back within budget - its
      # tarpit has expired, so it is fair game for LRU eviction again.
      def sweep(now, window, limit)
        @last_sweep = now
        @entries.delete_if { |_ip, stamps| stamps.empty? || now - stamps.last > window }
        @tarpitted.delete_if do |ip, stamps|
          stamps.shift while stamps.any? && now - stamps.first > window
          next true if stamps.empty?

          @entries[ip] = stamps if stamps.size <= limit
          stamps.size <= limit
        end
      end
    end
  end
end
