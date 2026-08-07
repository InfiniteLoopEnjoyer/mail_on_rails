# frozen_string_literal: true

require_relative "../netserv/config"

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
      # Read at load time (in the app these files load from the Puma
      # plugin, with the environment already set). 0 disables.
      LIMIT = Netserv::Config.int("SMTP_SEND_QUOTA", 200)
      WINDOW = Netserv::Config.int("SMTP_SEND_QUOTA_WINDOW", 3600, min: 1)
      SWEEP_THRESHOLD = 1_000 # purge idle accounts when the table grows past this

      # The process-wide quota, or nil when disabled by SMTP_SEND_QUOTA=0.
      SHARED_LOCK = Mutex.new
      def self.shared
        return nil unless LIMIT.positive?

        SHARED_LOCK.synchronize { @shared ||= new(limit: LIMIT, window: WINDOW) }
      end

      def initialize(limit:, window:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @limit = limit if limit&.positive?
        @window = window.to_f
        @clock = clock
        @entries = {} # account => consumed-slot timestamps within the window, oldest first
        @mutex = Mutex.new
      end

      # Atomically consumes one recipient slot for +account+ and returns
      # true, or returns false without consuming when the account's window
      # budget is exhausted.
      def consume(account)
        return true unless @limit && account

        now = @clock.call
        @mutex.synchronize do
          sweep(now) if @entries.size > SWEEP_THRESHOLD
          stamps = (@entries[account] ||= [])
          stamps.shift while stamps.any? && now - stamps.first > @window
          return false if stamps.size >= @limit

          stamps << now
          true
        end
      end

      private

      # Drops accounts whose every timestamp has aged out of the window.
      def sweep(now)
        @entries.delete_if { |_account, stamps| stamps.empty? || now - stamps.last > @window }
      end
    end
  end
end
