# frozen_string_literal: true

# Envelope facts the submission listener now records for the relay path:
# the RFC 8689 REQUIRETLS promise, the sender's RFC 3461 DSN requests
# (RET/ENVID per message, NOTIFY/ORCPT per recipient), and when a
# delayed-delivery DSN was issued so it is issued at most once.
class AddOutboundDsnAndRequiretls < ActiveRecord::Migration[8.1]
  def change
    change_table "mail_on_rails_smtp_outbound_messages", bulk: true do |t|
      t.boolean :requiretls, null: false, default: false
      t.string :dsn_ret
      t.string :dsn_envid
      t.string :dsn_notify
      t.string :dsn_orcpt
      t.datetime :delay_notified_at
    end
  end
end
