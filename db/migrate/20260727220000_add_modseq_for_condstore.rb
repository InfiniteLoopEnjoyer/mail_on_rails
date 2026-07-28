class AddModseqForCondstore < ActiveRecord::Migration[8.1]
  def change
    add_column :mailboxes, :highest_modseq, :bigint, default: 1, null: false
    add_column :email_messages, :modseq, :bigint, default: 1, null: false
  end
end
