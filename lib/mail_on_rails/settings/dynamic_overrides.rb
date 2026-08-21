# frozen_string_literal: true

module MailOnRails
  module Settings
    # The database tier: a cached snapshot of the settings table's override
    # rows, typed through each dynamic Definition. Modeled on
    # Netserv::Denylist - a lazy pull on the calling thread every TTL
    # seconds against a monotonic clock, failing soft to the last good
    # snapshot on any store error (the mail must keep flowing on the
    # boot-time configuration if the database goes away). The store is a
    # host-provided callable (the engine wires it to Setting.override_rows
    # under the app executor); a process that never sets one - the
    # Rails-free protocol test suites, a web-only boot - reads pure
    # ENV/initializer configuration with zero overhead here.
    #
    # Unlike the denylist, the store is NEVER called while holding the
    # mutex: settings are read from inside ActiveRecord transactions (the
    # auth throttle) as well as from accept threads, so holding a lock
    # across a connection checkout invites a lock-order inversion against
    # whoever holds a connection and wants the settings (fatal under the
    # test harness's single locked connection, a stall under an exhausted
    # pool in production). Readers always return the current snapshot
    # immediately; whichever thread trips the TTL performs the pull
    # unlocked and swaps the result in, newest pull wins.
    #
    # Writers are validated strictly (Setting.write), so an uncoercible row
    # only appears through hand-edits or version skew; it is skipped with a
    # warning rather than poisoning the snapshot.
    class DynamicOverrides
      TTL = 5

      def initialize(ttl: TTL)
        @ttl = ttl
        @mutex = Mutex.new
        @store = nil
        @snapshot = {}.freeze
        @checked_at = nil
        @pulling = false
        @pull_version = 0
        @applied_version = 0
      end

      def store=(callable)
        @mutex.synchronize do
          @store = callable
          @snapshot = {}.freeze
          @checked_at = nil
        end
      end

      # Test seam: 0 makes every read pull fresh rows - transactional app
      # tests never fire after_commit, so the push half never runs there.
      def ttl=(seconds)
        @mutex.synchronize do
          @ttl = seconds
          @checked_at = nil
        end
      end

      # The current typed overrides; refreshes from the store when the TTL
      # has lapsed. Only one thread pulls at a time and it does so without
      # the lock - concurrent readers get the existing snapshot instantly.
      def snapshot
        store = nil
        due = @mutex.synchronize do
          return @snapshot unless @store

          now = clock
          if !@pulling && (@checked_at.nil? || now - @checked_at >= @ttl)
            @pulling = true
            @checked_at = now
            store = @store
            true
          end
        end
        pull(store) if due
        @mutex.synchronize { @snapshot }
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
