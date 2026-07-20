class CreateSmtpInboundMessages < ActiveRecord::Migration[8.1]
  def change
    create_table :smtp_inbound_messages do |t|
      t.string :mail_from
      t.text :rcpt_to, null: false, default: "[]"
      t.binary :data, null: false
      t.integer :status, null: false, default: 0
      t.text :error
      t.datetime :processed_at

      t.timestamps
    end
    add_index :smtp_inbound_messages, :status
  end
end
