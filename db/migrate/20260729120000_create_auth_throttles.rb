class CreateAuthThrottles < ActiveRecord::Migration[8.1]
  def change
    create_table :auth_throttles do |t|
      # "ip" or "account"; key is the address or the normalized email.
      t.string :scope, null: false
      t.string :key, null: false
      t.integer :failure_count, null: false, default: 0
      t.datetime :window_started_at, null: false
      t.datetime :blocked_until

      t.timestamps
    end

    # One counter row per (scope, key) - the uniqueness the upsert relies on.
    add_index :auth_throttles, [ :scope, :key ], unique: true
    # Pruning walks stale windows.
    add_index :auth_throttles, :window_started_at
  end
end
