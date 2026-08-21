# Remembers when an account last auto-replied to a correspondent, so the
# vacation responder answers each sender once per window instead of once
# per message (see VacationResponder::REPLY_WINDOW).
#
# The sender column only ever holds normalized claim keys (see
# .normalize), so the unique index on [email_account_id, sender] really
# does mean one window slot per mailbox rather than one per spelling.
module MailOnRails
  class VacationReply < Record
    belongs_to :email_account

    # Case and +tag variants of an address all reach the same real mailbox,
    # so they must share one claim key: downcase everything and strip the
    # subaddress tag from the local part.
    def self.normalize(address)
      address = address.to_s.strip.downcase
      local, at, domain = address.rpartition("@")
      return address if at.empty?

      "#{local.sub(/\+.*/, "")}@#{domain}"
    end

    # A cheap read-only check used before spending a send-quota slot;
    # +sender+ must already be normalized.
    def self.replied_recently?(account, sender, window:)
      where(email_account_id: account.id, sender: sender)
        .where("last_sent_at > ?", Time.current - window)
        .exists?
    end

    # Atomically claims the right to reply to +sender+ (a normalized claim
    # key): true when no reply went out within +window+, so concurrent
    # deliveries can't both claim it. Portable across adapters: the insert
    # is arbitrated by the [email_account_id, sender] unique index, and on
    # conflict the guarded UPDATE moves last_sent_at inside the window in
    # one atomic statement - of N concurrent claimants exactly one sees an
    # affected row, because the winner's write makes every other
    # claimant's WHERE fail. (If prune! deletes the row between the rescue
    # and the update, the claim returns false and one auto-reply is
    # skipped - a benign race.)
    def self.claim(account, sender, window:)
      now = Time.current
      # The savepoint keeps a rescued duplicate-key error from poisoning
      # an enclosing transaction on PostgreSQL.
      transaction(requires_new: true) do
        create!(email_account_id: account.id, sender: sender, last_sent_at: now)
      end
      true
    rescue ActiveRecord::RecordNotUnique
      where(email_account_id: account.id, sender: sender)
        .where(last_sent_at: ..(now - window))
        .update_all(last_sent_at: now, updated_at: now) == 1
    end

    # Rows past the reply window no longer suppress anything; without a
    # sweep an attacker cycling addresses grows the table without bound.
    def self.prune!(now: Time.current)
      where("last_sent_at <= ?", now - VacationResponder::REPLY_WINDOW).delete_all
    end
  end
end
