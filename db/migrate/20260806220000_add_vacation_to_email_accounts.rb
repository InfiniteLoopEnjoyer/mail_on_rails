class AddVacationToEmailAccounts < ActiveRecord::Migration[8.1]
  def change
    change_table :email_accounts, bulk: true do |t|
      t.boolean :vacation_enabled, default: false, null: false
      t.string :vacation_subject
      t.text :vacation_body
      t.date :vacation_starts_on
      t.date :vacation_ends_on
    end

    # One row per (account, correspondent): last_sent_at gates the
    # one-reply-per-sender-per-window rule (VacationResponder).
    create_table :vacation_replies do |t|
      t.references :email_account, null: false, foreign_key: true
      t.string :sender, null: false
      t.datetime :last_sent_at, null: false
      t.timestamps
    end
    add_index :vacation_replies, [ :email_account_id, :sender ], unique: true
  end
end
