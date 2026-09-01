# frozen_string_literal: true

# SMTP-layer idempotency for accepted mail. The SMTP session persists a
# message and then writes "250 Ok"; when the connection dies in between,
# a conformant sender redelivers the identical message, and nothing at
# the protocol layer remembered the first copy (the mailroom's
# Message-ID dedupe only catches senders that reuse the id). One row per
# accepted message, keyed by the session's digest over envelope + body
# as received; a second claim of the same digest is the redelivery.
#
# Written from Store::SmtpBackend#smtp_store inside the persist
# transaction. Rows are only useful for as long as a sender might retry,
# so the table is pruned opportunistically on every claim.
module MailOnRails
  class SmtpReceipt < Record
    RETENTION = 24.hours

    class << self
      # true when this digest is new (and now recorded), false when a
      # receipt for it already exists. The insert runs in a savepoint so a
      # unique violation never poisons the caller's transaction (on
      # PostgreSQL a failed statement aborts the whole transaction).
      def claim(digest, now: Time.current)
        prune!(now: now)
        transaction(requires_new: true) { create!(digest: digest, created_at: now) }
        true
      rescue ActiveRecord::RecordNotUnique
        false
      end

      def prune!(now: Time.current)
        where(created_at: ...(now - RETENTION)).delete_all
      end
    end
  end
end
