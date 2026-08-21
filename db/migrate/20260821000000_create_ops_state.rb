# frozen_string_literal: true

# Ops state the mail daemons project into the database so the admin UI
# works whether the listeners run inside the web process or in their own
# containers (Netserv::OpsSync):
#
# * listeners        - one row per running server (protocol, pid, ports),
#                      heartbeated every sync tick; the UI's "SMTP is up".
# * open_connections - the live connection table, replaced per listener
#                      on every change; bounded by the listener's cap.
# * accept_lockouts  - display-only projection of the accept-side per-IP
#                      auth lockouts (the in-memory Netserv::AuthThrottle),
#                      which never become sessions and so never appear in
#                      open_connections.
# * connection_kicks - the one *command* row: "drop this source's live
#                      connections now" (honeypot kick), one row per
#                      protocol, processed and acknowledged by the daemon.
#
# Rows of a listener whose heartbeat goes stale (a killed container that
# never ran its shutdown) are swept by every other live listener.
class CreateOpsState < ActiveRecord::Migration[8.1]
  include MailOnRails::MigrationHelpers

  def change
    create_table "mail_on_rails_listeners" do |t|
      t.string "listener_id", null: false
      t.string "protocol", null: false
      t.integer "pid"
      t.string "hostname"
      postgres? ? t.jsonb("ports") : t.json("ports")
      t.integer "max_connections"
      t.boolean "ready", null: false, default: false
      t.datetime "started_at", null: false
      t.datetime "heartbeat_at", null: false
      t.datetime "created_at", null: false
      t.datetime "updated_at", null: false
      t.index [ "listener_id" ], name: "index_listeners_on_listener_id", unique: true
      t.index %w[protocol heartbeat_at], name: "index_listeners_on_protocol_and_heartbeat_at"
    end

    create_table "mail_on_rails_open_connections" do |t|
      t.string "listener_id", null: false
      t.bigint "connection_id", null: false
      t.string "protocol", null: false
      t.string "peer_ip"
      t.integer "port"
      t.string "role"
      t.datetime "connected_at", null: false
      t.float "tarpit"
      t.string "username"
      t.string "helo"
      t.integer "messages"
      t.boolean "tls"
      t.string "state"
      t.datetime "created_at", null: false
      t.datetime "updated_at", null: false
      t.index %w[listener_id connection_id], name: "index_open_connections_on_listener_and_connection", unique: true
      t.index %w[protocol connected_at], name: "index_open_connections_on_protocol_and_connected_at"
      t.index [ "peer_ip" ], name: "index_open_connections_on_peer_ip"
    end

    create_table "mail_on_rails_accept_lockouts" do |t|
      t.string "listener_id", null: false
      t.string "protocol", null: false
      t.string "ip", null: false
      t.datetime "locked_until", null: false
      t.datetime "created_at", null: false
      t.datetime "updated_at", null: false
      t.index %w[listener_id ip], name: "index_accept_lockouts_on_listener_and_ip", unique: true
      t.index %w[protocol locked_until], name: "index_accept_lockouts_on_protocol_and_locked_until"
    end

    create_table "mail_on_rails_connection_kicks" do |t|
      t.string "protocol", null: false
      t.string "ip", null: false
      t.string "requested_by"
      t.datetime "expires_at", null: false
      t.datetime "processed_at"
      t.string "processed_by"
      t.integer "kicked_count"
      t.datetime "created_at", null: false
      t.datetime "updated_at", null: false
      t.index %w[protocol processed_at expires_at], name: "index_connection_kicks_on_protocol_pending"
    end
  end
end
