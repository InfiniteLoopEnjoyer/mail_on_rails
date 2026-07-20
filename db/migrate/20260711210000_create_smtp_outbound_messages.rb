class CreateSmtpOutboundMessages < ActiveRecord::Migration[8.0]
  def change
    create_table :smtp_outbound_messages do |t|
      t.string :mail_from, null: false
      t.string :recipient, null: false
      t.binary :data, null: false
      t.integer :status, default: 0, null: false
      t.integer :attempts, default: 0, null: false
      t.datetime :next_attempt_at, null: false
      t.text :last_error
      t.datetime :sent_at

      t.timestamps
    end
    add_index :smtp_outbound_messages, [ :status, :next_attempt_at ]
  end
end
