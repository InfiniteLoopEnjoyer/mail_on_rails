# ClamAV verdict per stored message: "clean" / "infected" / "unscanned"
# (nil = stored before scanning existed, or scanning disabled). virus_name
# holds the clamd signature for infected mail. The [mailbox_id, message_id]
# index backs the quarantine dedup/sweep lookups in MailroomMailbox.
class AddScanColumnsToEmailMessages < ActiveRecord::Migration[8.1]
  def change
    add_column :email_messages, :scan_status, :string
    add_column :email_messages, :virus_name, :string
    add_index :email_messages, [ :mailbox_id, :message_id ]
  end
end
