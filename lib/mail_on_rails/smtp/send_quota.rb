# frozen_string_literal: true

require_relative "../settings"

module MailOnRails
  module Smtp
    # Per-account sliding-window cap on recipients accepted from
    # authenticated sessions. The per-IP anti-abuse set (ConnLimiter,
    # AuthThrottle, RateLimiter) never sees the signature of a stolen
    # credential worked from a botnet - one account, many IPs, each under
    # every per-IP budget - so this keys on the authenticated account
    # instead and bounds what a compromised password is worth.
    #
    # Each accepted RCPT consumes one slot at RCPT time, whether or not
    # the message is later completed (same accounting as Postfix's anvil
    # rate counters): counting at completion would let concurrent
    # in-flight transactions overshoot the budget arbitrarily, and an
    # abandoned transaction costing its sender quota punishes only abuse.
    # Slots are only consumed while under the limit, so an account holds
    # at most +limit+ timestamps.
    #
    # A nil/0 limit disables. +clock+ is injectable for tests and must be
    # monotonic.
    class SendQuota
      SWEEP_THRESHOLD = 1_000 # purge idle accounts when the table grows past this

      # The process-wide quota, its limit and window read through the
      # settings schema per consume - retuning (or disabling with 0)
      # applies to the next RCPT without a restart, and existing window
      # timestamps stay counted.
      SHARED_LOCK = Mutex.new
      def self.shared
        SHARED_LOCK.synchronize do
          @shared ||= new(limit: -> { Settings[:smtp_send_quota] },
                          window: -> { Settings[:smtp_send_quota_window] })
        end
      end

      # limit/window may be plain values or callables resolved per consume;
      # a nil/0 limit disables.
      def initialize(limit:, window:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @limit = limit
        @window = window
        @clock = clock
        @entries = {} # account => consumed-slot timestamps within the window, oldest first
        @mutex = Mutex.new
      end

      # Atomically consumes one recipient slot for +account+ and returns
      # true, or returns false without consuming when the account's window
      # budget is exhausted.
      def consume(account)
        limit = current_limit
        return true unless limit && account

        window = current_window
        now = @clock.call
        @mutex.synchronize do
          sweep(now, window) if @entries.size > SWEEP_THRESHOLD
          stamps = (@entries[account] ||= [])
          stamps.shift while stamps.any? && now - stamps.first > window
          return false if stamps.size >= limit

          stamps << now
          true
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

      # Drops accounts whose every timestamp has aged out of the window.
      def sweep(now, window)
        @entries.delete_if { |_account, stamps| stamps.empty? || now - stamps.last > window }
      end
    end
  end
end
