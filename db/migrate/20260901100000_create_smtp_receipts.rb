# frozen_string_literal: true

# One row per message the SMTP edge accepted, keyed by the session's
# digest over envelope + body - see MailOnRails::SmtpReceipt. The unique
# index is the dedupe: a redelivery after a lost 250 fails to claim its
# digest and is answered 250 without a second persist. No updated_at:
# rows are written once and pruned by created_at.
class CreateSmtpReceipts < ActiveRecord::Migration[8.1]
  def change
    create_table "mail_on_rails_smtp_receipts" do |t|
      t.string "digest", null: false, limit: 64
      t.datetime "created_at", null: false
      t.index [ "digest" ], name: "index_smtp_receipts_on_digest", unique: true
      t.index [ "created_at" ], name: "index_smtp_receipts_on_created_at"
    end
  end
end
