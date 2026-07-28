class CreateExpungedMessages < ActiveRecord::Migration[8.1]
  def change
    create_table :expunged_messages do |t|
      t.references :mailbox, null: false, foreign_key: true
      t.bigint :uid, null: false
      t.bigint :modseq, null: false
    end
    add_index :expunged_messages, [ :mailbox_id, :modseq ]

    add_column :mailboxes, :tombstone_floor, :bigint, default: 0, null: false
  end
end
