# frozen_string_literal: true

require_relative "settings"

module MailOnRails
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
  # Two backings, chosen per consume:
  #
  #   durable  - MailOnRails::SendQuotaSlot rows, whenever Active Record
  #              is connected and the table exists. The budget is then one
  #              budget across the web process (composer, vacation
  #              replies) and every SMTP listener container, and survives
  #              restarts - a stolen password cannot spend the limit once
  #              per process.
  #   memory   - the in-process table, for processes without a database
  #              (the memory stores, Rails-free suites). Per process by
  #              nature; the class comment on SendQuotaSlot says why that
  #              is not enough for production.
  #
  # A nil/0 limit disables. +clock+ is injectable for tests and must be
  # monotonic (the durable path keeps wall-clock time in the rows).
  class SendQuota
    SWEEP_THRESHOLD = 1_000 # purge idle accounts when the table grows past this
    # How long a "no database here" answer is trusted before re-probing:
    # a process that never gets a connection must not pay an exception
    # per RCPT, one that gains its connection late must notice.
    DURABLE_RECHECK = 5.0

    # The process-wide quota, its limit and window read through the
    # settings schema per consume - retuning applies to the next RCPT
    # without a restart, and existing window slots stay counted.
    SHARED_LOCK = Mutex.new
    def self.shared
      SHARED_LOCK.synchronize do
        @shared ||= new(limit: -> { Settings[:smtp_send_quota] },
                        window: -> { Settings[:smtp_send_quota_window] })
      end
    end

    # limit/window may be plain values or callables resolved per consume;
    # a nil/0 limit disables. +durable+ is :auto (use SendQuotaSlot when
    # it is reachable), false (memory only - the unit tests), or an
    # object answering consume(account, limit:, window:) (the model
    # itself, or a stand-in).
    def initialize(limit:, window:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                   durable: :auto)
      @limit = limit
      @window = window
      @clock = clock
      @durable = durable
      @durable_checked_at = nil
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
      if (store = durable_store)
        with_database { store.consume(account, limit: limit, window: window) }
      else
        consume_in_memory(account, limit, window)
      end
    end

    # Which backing the next consume would use: :durable or :memory. For
    # the ops UI and tests.
    def backing
      durable_store ? :durable : :memory
    end

    private

    def consume_in_memory(account, limit, window)
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

    # The durable store when one is usable, else nil. Explicit stores are
    # taken as given; :auto probes for a connected Active Record with the
    # slots table, caching a positive answer for good and a negative one
    # for DURABLE_RECHECK seconds.
    def durable_store
      return nil unless @durable
      return @durable unless @durable == :auto
      return @resolved if @resolved

      now = @clock.call
      return nil if @durable_checked_at && now - @durable_checked_at < DURABLE_RECHECK

      @durable_checked_at = now
      @resolved = probe_durable
    end

    def probe_durable
      return nil unless defined?(::ActiveRecord::Base) && MailOnRails.const_defined?(:SendQuotaSlot)

      model = MailOnRails::SendQuotaSlot
      with_database { model.table_exists? } ? model : nil
    rescue StandardError, LoadError
      nil # no connection (or no table yet): stay in memory
    end

    # Database work from a listener thread runs inside the host's
    # executor when there is one (connection checkout/return, reloading
    # cooperation - the same wrapper the AR stores use), else a plain pool
    # checkout; an injected store in a process without Active Record at
    # all is simply called.
    def with_database(&)
      executor = MailOnRails.respond_to?(:app_executor) && MailOnRails.app_executor
      return executor.wrap(&) if executor
      return yield unless defined?(::ActiveRecord::Base)

      ::ActiveRecord::Base.connection_pool.with_connection(&)
    end

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
