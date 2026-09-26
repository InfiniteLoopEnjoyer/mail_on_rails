# frozen_string_literal: true

module MailOnRails
  module Settings
    # The database tier: a cached snapshot of the settings table's override
    # rows, typed through each dynamic Definition. Modeled on
    # Netserv::Denylist - a pull every TTL seconds against a monotonic
    # clock, failing soft to the last good snapshot on any store error
    # (the mail must keep flowing on the boot-time configuration if the
    # database goes away). The store is a host-provided callable (the
    # engine wires it to Setting.override_rows under the app executor); a
    # process that never sets one - the Rails-free protocol test suites, a
    # web-only boot - reads pure ENV/initializer configuration with zero
    # overhead here.
    #
    # Who pulls: a process with a listener has its OpsSync tick call poll!
    # every couple of seconds, and while those calls keep coming every
    # reader (the accept thread's limit lambdas included) only ever takes
    # the current snapshot - no store call on a mail path. A process
    # without a poller (the web app, a job worker) falls back to the lazy
    # pull: whichever thread trips the TTL performs it. The fallback also
    # resumes automatically if a poller goes quiet for three TTLs, so a
    # dead ops thread never freezes the configuration.
    #
    # The store is NEVER called while holding the mutex: settings are read
    # from inside ActiveRecord transactions (the auth throttle) as well as
    # from accept threads, so holding a lock across a connection checkout
    # invites a lock-order inversion against whoever holds a connection
    # and wants the settings (fatal under the test harness's single locked
    # connection, a stall under an exhausted pool in production). Readers
    # always return the current snapshot immediately; whichever thread
    # pulls does so unlocked and swaps the result in, newest pull wins.
    #
    # Writers are validated strictly (Setting.write), so an uncoercible row
    # only appears through hand-edits or version skew; it is skipped with a
    # warning rather than poisoning the snapshot.
    class DynamicOverrides
      TTL = 5
      # How many TTLs a poller may go quiet before readers pull for
      # themselves again.
      POLL_GRACE = 3

      def initialize(ttl: TTL)
        @ttl = ttl
        @mutex = Mutex.new
        @store = nil
        @snapshot = {}.freeze
        @checked_at = nil
        @polled_at = nil
        @pulling = false
        @pull_version = 0
        @applied_version = 0
      end

      def store=(callable)
        @mutex.synchronize do
          @store = callable
          @snapshot = {}.freeze
          @checked_at = nil
          @polled_at = nil
        end
      end

      # Test seam: 0 makes every read pull fresh rows - transactional app
      # tests never fire after_commit, so the push half never runs there.
      # (A 0 TTL also zeroes the poll grace, so an embedded listener's ops
      # tick cannot switch that seam off.)
      def ttl=(seconds)
        @mutex.synchronize do
          @ttl = seconds
          @checked_at = nil
        end
      end

      # The current typed overrides. Refreshes from the store when the TTL
      # has lapsed AND no background poller is keeping it fresh; only one
      # thread pulls at a time and it does so without the lock -
      # concurrent readers get the existing snapshot instantly.
      def snapshot
        pull_if_due(background: false)
        @mutex.synchronize { @snapshot }
      end

      # The background poller's call (Netserv::OpsSync, once per tick):
      # pulls when the TTL has lapsed and marks this process as polled, so
      # readers stop pulling inline (see the class comment).
      def poll!
        pull_if_due(background: true)
      end

      # Immediate reload bypassing the TTL - Setting's after_commit calls
      # this (via Settings.refresh!) so an admin's change applies to the
      # very next connection; the TTL polling covers writers in other
      # processes. Always pulls, even alongside an in-flight TTL pull: the
      # version guard keeps the freshest result.
      def refresh!
        store = @mutex.synchronize do
          @checked_at = clock
          @store
        end
        pull(store) if store
      end

      private

      def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      def pull_if_due(background:)
        store = nil
        due = @mutex.synchronize do
          return unless @store

          now = clock
          if background
            @polled_at = now
          elsif @polled_at && now - @polled_at < @ttl * POLL_GRACE
            next false # a poller has this covered
          end
          if !@pulling && (@checked_at.nil? || now - @checked_at >= @ttl)
            @pulling = true
            @checked_at = now
            store = @store
            true
          end
        end
        pull(store) if due
      end

      # Runs with no lock held. The version, taken at pull start, stops an
      # older in-flight pull from clobbering a newer one's snapshot.
      def pull(store)
        version = @mutex.synchronize { @pull_version += 1 }
        rows = begin
          store.call
        rescue StandardError
          nil
        end
        parsed = parse(rows) if rows.is_a?(Hash)
        @mutex.synchronize do
          if parsed && version > @applied_version
            @snapshot = parsed.freeze
            @applied_version = version
          end
        end
      ensure
        @mutex.synchronize { @pulling = false }
      end

      def parse(rows)
        parsed = {}
        rows.each do |key, raw|
          definition = Settings.lookup(key.to_s.to_sym)
          next unless definition&.dynamic?

          begin
            value = definition.coerce(raw)
            parsed[definition.name] = value unless value.nil?
          rescue StandardError => e
            warn_skipped(key, e)
          end
        end
        parsed
      end

      def warn_skipped(key, error)
        return unless MailOnRails.respond_to?(:logger) && MailOnRails.logger

        MailOnRails.logger.warn("[mail_on_rails] ignoring unusable settings row #{key.inspect}: #{error.message}")
      rescue StandardError
        nil
      end
    end
  end
end
