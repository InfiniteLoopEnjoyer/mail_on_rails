# The vacation responder now normalizes claim keys (downcase, strip the
# +tag subaddress) before touching vacation_replies, so the unique index
# on [email_account_id, sender] means one window slot per real mailbox.
# Rewrite the rows written before that: collapse variants of one mailbox
# into a single row keeping the newest last_sent_at.
class NormalizeVacationReplySenders < ActiveRecord::Migration[8.1]
  def up
    rows = select_all("SELECT id, email_account_id, sender FROM vacation_replies ORDER BY last_sent_at DESC, id DESC")
    seen = {}
    rows.each do |row|
      key = [ row["email_account_id"], normalize(row["sender"]) ]
      if seen[key]
        execute("DELETE FROM vacation_replies WHERE id = #{row['id'].to_i}")
      else
        seen[key] = true
        execute(ActiveRecord::Base.sanitize_sql([ "UPDATE vacation_replies SET sender = ? WHERE id = ?", key.last, row["id"] ]))
      end
    end
  end

  def down
    # Nothing to restore - the original spellings are gone, and the
    # normalized rows remain valid claim keys.
  end

  private

  # Mirrors VacationReply.normalize, inlined so the migration stays valid
  # if the model moves on.
  def normalize(address)
    address = address.to_s.strip.downcase
    local, at, domain = address.rpartition("@")
    return address if at.empty?

    "#{local.sub(/\+.*/, "")}@#{domain}"
  end
end
