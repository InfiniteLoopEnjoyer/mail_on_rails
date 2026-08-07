class CreateClosedConnections < ActiveRecord::Migration[8.1]
  def change
    create_table :closed_connections do |t|
      # When the connection ended - the time axis for windows and pruning.
      t.datetime :closed_at, null: false
      # smtp | imap
      t.string :protocol, null: false
      t.string :ip
      # The listener port (internal: 1025/1587/1465/1143/1993).
      t.integer :port
      # SMTP listener role (mx | submission); nil for IMAP.
      t.string :role
      # Who was authenticated when the connection closed, if anyone.
      t.string :username
      t.boolean :tls, null: false, default: false
      # SMTP: the HELO/EHLO name and messages accepted this session.
      t.string :helo
      t.integer :messages
      # IMAP: the protocol state at close (pre-auth / SELECT x / IDLE x).
      t.string :final_state
      # nil on rollup rows, which stand for many connections at once.
      t.datetime :connected_at
      t.float :duration_seconds
      # >1 only on rollup rows, where noise from one source has been
      # collapsed rather than stored connection by connection.
      t.integer :connection_count, null: false, default: 1
      t.boolean :rollup, null: false, default: false

      t.timestamps
    end

    # Pruning by age.
    add_index :closed_connections, :closed_at
    # The page query: one protocol's history, newest first.
    add_index :closed_connections, [ :protocol, :closed_at ]
    # The per-IP cap check inside a window.
    add_index :closed_connections, [ :protocol, :ip, :closed_at ]
    # One rollup row per protocol, address and window - the uniqueness the
    # collapse path relies on (protocol in the key keeps SMTP and IMAP
    # noise from one scanner in separate counters).
    add_index :closed_connections, [ :protocol, :ip, :closed_at ], unique: true,
              where: "rollup", name: "index_closed_connections_on_rollup_key"
  end
end
