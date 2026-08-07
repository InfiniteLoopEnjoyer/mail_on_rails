# Remembers when an account last auto-replied to a correspondent, so the
# vacation responder answers each sender once per window instead of once
# per message (see VacationResponder::REPLY_WINDOW).
#
# The sender column only ever holds normalized claim keys (see
# .normalize), so the unique index on [email_account_id, sender] really
# does mean one window slot per mailbox rather than one per spelling.
class VacationReply < ApplicationRecord
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
  # key): true when no reply went out within +window+, updating the
  # timestamp in the same statement so concurrent deliveries can't both
  # claim it.
  def self.claim(account, sender, window:)
    now = Time.current
    upserted = connection.select_value(sanitize_sql([ <<~SQL, account.id, sender, now, now, now, now - window ]))
      INSERT INTO vacation_replies (email_account_id, sender, last_sent_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (email_account_id, sender)
      DO UPDATE SET last_sent_at = EXCLUDED.last_sent_at, updated_at = EXCLUDED.updated_at
      WHERE vacation_replies.last_sent_at <= ?
      RETURNING id
    SQL
    !upserted.nil?
  end

  # Rows past the reply window no longer suppress anything; without a
  # sweep an attacker cycling addresses grows the table without bound.
  def self.prune!(now: Time.current)
    where("last_sent_at <= ?", now - VacationResponder::REPLY_WINDOW).delete_all
  end
end
