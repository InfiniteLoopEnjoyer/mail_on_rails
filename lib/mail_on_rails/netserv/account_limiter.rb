# frozen_string_literal: true

module MailOnRails
  module Netserv
    # Caps the number of simultaneously authenticated sessions one account
    # may hold in this process. ConnLimiter bounds connections per peer
    # address; this bounds them per identity, so a stolen password used
    # from many addresses (each under the per-IP cap) still cannot hold
    # hundreds of IDLE or submission sessions open. Per process, like the
    # other accept-side limiters: each protocol daemon has its own.
    #
    # The limit may be an Integer or a callable resolved per check - the
    # servers pass a settings-backed lambda so an admin's change applies to
    # the next login without a restart. A nil/0 limit disables the cap;
    # counts keep running so enabling it live applies to sessions already
    # open.
    class AccountLimiter
      def initialize(max)
        @max = max
        @counts = Hash.new(0)
        @mutex = Mutex.new
      end

      # Reserves a session slot for +key+ (the account's canonical email or
      # id). Returns true when acquired, false when the account is at its
      # cap. The caller must release with the same key exactly once. An
      # explicit +limit+ overrides the configured one for this check (the
      # listener-spec seam the servers' tests use).
      def acquire(key, limit: nil)
        return true if key.nil?

        max = limit.nil? ? resolve(@max) : limit
        max = nil unless max&.positive?
        @mutex.synchronize do
          return false if max && @counts[key] >= max

          @counts[key] += 1
          true
        end
      end

      def release(key)
        return if key.nil?

        @mutex.synchronize do
          next unless @counts.key?(key)

          @counts[key] -= 1
          @counts.delete(key) if @counts[key] <= 0 # never grows with account history
        end
      end

      # Sessions currently held by +key+ (tests, ops).
      def count(key)
        @mutex.synchronize { @counts[key] }
      end

      private

      def resolve(value) = value.respond_to?(:call) ? value.call : value
    end
  end
end
