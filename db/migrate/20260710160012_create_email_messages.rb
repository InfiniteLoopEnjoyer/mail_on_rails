class CreateEmailMessages < ActiveRecord::Migration[8.1]
  def change
    create_table :email_messages do |t|
      t.references :mailbox, null: false, foreign_key: true
      t.integer :uid, null: false
      t.string :message_id
      t.string :subject
      t.string :from_address
      t.text :to_addresses
      t.datetime :internal_date, null: false
      t.integer :size, null: false, default: 0
      t.text :flags, null: false, default: "[]"
      t.binary :raw, null: false

      t.timestamps
    end
    add_index :email_messages, [ :mailbox_id, :uid ], unique: true
    add_index :email_messages, [ :mailbox_id, :internal_date ]
  end
end
