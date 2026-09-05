# frozen_string_literal: true

# Per-account sender allow/deny rules, consulted by the mailroom when it
# picks INBOX or Junk for an unauthenticated inbound message - see
# MailOnRails::SenderRule. Rows are written automatically when a user
# files a message into Junk (deny) or rescues one out of it (allow), over
# IMAP or the web UI (JunkFeedback), and by hand from the account page.
# One row per (account, address); a repeat flips the verdict in place.
class CreateSenderRules < ActiveRecord::Migration[8.1]
  def change
    create_table "mail_on_rails_sender_rules" do |t|
      t.bigint "email_account_id", null: false
      t.string "address", null: false # "alice@example.com" or "@example.com"
      t.string "verdict", null: false # allow | deny
      t.string "source", null: false  # web | imap | import | manual

      t.timestamps

      t.index [ "email_account_id", "address" ], name: "index_sender_rules_on_account_and_address", unique: true
    end

    add_foreign_key "mail_on_rails_sender_rules", "mail_on_rails_email_accounts", column: "email_account_id"
  end
end
