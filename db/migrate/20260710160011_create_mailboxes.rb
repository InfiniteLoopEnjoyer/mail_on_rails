class CreateMailboxes < ActiveRecord::Migration[8.1]
  def change
    create_table :mailboxes do |t|
      t.references :email_account, null: false, foreign_key: true
      t.string :name, null: false
      t.integer :uid_validity, null: false
      t.integer :uid_next, null: false, default: 1

      t.timestamps
    end
    add_index :mailboxes, [ :email_account_id, :name ], unique: true
  end
end
