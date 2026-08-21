# frozen_string_literal: true

# Remote addresses outbound delivery must skip because the recipient
# reported our mail as spam through a provider feedback loop (ARF to
# fbl@/jmrp@). Written by IngestFblReportJob, consulted by
# DeliverSmtpOutboundJob; an operator lifts a suppression by deleting
# the row.
class CreateSuppressedRecipients < ActiveRecord::Migration[8.1]
  def change
    create_table "mail_on_rails_suppressed_recipients" do |t|
      t.string :email, null: false
      t.string :feedback_type
      t.string :reporter
      t.integer :complaints_count, null: false, default: 0
      t.datetime :last_complaint_at

      t.timestamps

      t.index [ "email" ], name: "index_suppressed_recipients_on_email", unique: true
    end
  end
end
