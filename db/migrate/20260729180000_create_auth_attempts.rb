class CreateAuthAttempts < ActiveRecord::Migration[8.1]
  def change
    create_table :auth_attempts do |t|
      t.datetime :occurred_at, null: false
      t.string :ip
      t.string :username
      # imap | smtp | web
      t.string :source, null: false
      # unknown_account | bad_credentials | throttled
      t.string :outcome, null: false
      # Whether the address exists here. Computed at write time so the
      # "is anyone going after a real mailbox" query stays a plain index
      # scan instead of a join against a table that changes underneath it.
      t.boolean :account_exists, null: false, default: false
      # >1 only on rollup rows, where noise from one source has been
      # collapsed rather than stored attempt by attempt.
      t.integer :attempt_count, null: false, default: 1
      t.boolean :rollup, null: false, default: false

      t.timestamps
    end

    add_index :auth_attempts, :occurred_at
    add_index :auth_attempts, [ :ip, :occurred_at ]
    # The signal query: real addresses under attempt, newest first.
    add_index :auth_attempts, [ :account_exists, :occurred_at ]
    add_index :auth_attempts, :username
    # One rollup row per source, protocol and window - the uniqueness the
    # collapse path relies on.
    add_index :auth_attempts, [ :ip, :source, :occurred_at ], unique: true,
              where: "rollup", name: "index_auth_attempts_on_rollup_key"
  end
end
