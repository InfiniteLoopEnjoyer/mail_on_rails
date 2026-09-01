# frozen_string_literal: true

# Durable per-account send quota (MailOnRails::SendQuotaSlot): one row per
# (account, minute bucket) with the recipients consumed in it, so the web
# composer, vacation replies and every SMTP listener draw on one budget
# that survives a restart. Replaces the per-process in-memory counter,
# which stays as the fallback for processes without a database.
class CreateSendQuotaSlots < ActiveRecord::Migration[8.1]
  def change
    create_table "mail_on_rails_send_quota_slots" do |t|
      t.string "account_key", null: false
      t.datetime "window_start", null: false
      t.integer "used", null: false, default: 0
      t.datetime "created_at", null: false
      t.datetime "updated_at", null: false
      t.index %w[account_key window_start], name: "index_send_quota_slots_on_account_and_window", unique: true
      t.index [ "window_start" ], name: "index_send_quota_slots_on_window_start"
    end
  end
end
