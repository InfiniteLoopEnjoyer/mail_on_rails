# Inbound mail no longer pauses in a spool table: the SMTP daemon hands
# accepted messages straight to Action Mailbox's relay ingress over HTTP
# (MailOnRails::IngressClient). Durability during app downtime comes from the
# sending server's SMTP retry schedule (the session answers 451).
class DropSmtpInboundMessages < ActiveRecord::Migration[8.1]
  def change
    drop_table :smtp_inbound_messages do |t|
      t.string "auth_results"
      t.string "authenticated_as"
      t.datetime "created_at", null: false
      t.binary "data", null: false
      t.text "error"
      t.string "mail_from"
      t.datetime "processed_at"
      t.text "rcpt_to", default: "[]", null: false
      t.integer "status", default: 0, null: false
      t.datetime "updated_at", null: false
      t.index [ "status" ], name: "index_smtp_inbound_messages_on_status"
    end
  end
end
