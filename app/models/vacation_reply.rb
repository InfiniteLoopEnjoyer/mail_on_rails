# Remembers when an account last auto-replied to a correspondent, so the
# vacation responder answers each sender once per window instead of once
# per message (see VacationResponder::REPLY_WINDOW).
class VacationReply < ApplicationRecord
  belongs_to :email_account

  # Atomically claims the right to reply to +sender+: true when no reply
  # went out within +window+, updating the timestamp in the same
  # statement so concurrent deliveries can't both claim it.
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
end
