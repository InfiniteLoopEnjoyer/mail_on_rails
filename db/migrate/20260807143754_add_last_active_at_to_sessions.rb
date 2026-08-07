class AddLastActiveAtToSessions < ActiveRecord::Migration[8.1]
  def change
    add_column :sessions, :last_active_at, :datetime
    up_only { execute "UPDATE sessions SET last_active_at = updated_at" }
    change_column_null :sessions, :last_active_at, false
    add_index :sessions, :last_active_at
  end
end
