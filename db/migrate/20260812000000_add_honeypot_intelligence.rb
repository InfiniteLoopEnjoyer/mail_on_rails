# frozen_string_literal: true

# Honeypot intelligence (2026-08). Adds the canary flag to email accounts and
# the honeypot event log. Kept as its own migration rather than folded into the
# consolidated create because deployed installs have already recorded that one;
# fresh installs get the same columns from the consolidated migration too.
#
# Adapter-aware (PostgreSQL / MySQL 8.0.13+ / SQLite 3.35+): jsonb vs json for
# the enrichment blob, and an explicit mediumtext limit for the transcript on
# MySQL (its default TEXT caps at 64 KiB).
class AddHoneypotIntelligence < ActiveRecord::Migration[8.1]
  include MailOnRails::MigrationHelpers

  def change
    add_column "mail_on_rails_email_accounts", "honeypot", :boolean, default: false, null: false

    create_table "mail_on_rails_honeypot_events" do |t|
      t.datetime "created_at", null: false
      postgres? ? t.jsonb("enrichment") : t.json("enrichment")
      t.string "helo"
      t.string "ip"
      t.datetime "occurred_at", null: false
      t.integer "port"
      t.string "protocol", null: false
      t.string "response"
      t.string "signature"
      t.text "transcript", **(mysql? ? { limit: 16_777_215 } : {})
      t.string "trigger", null: false
      t.datetime "updated_at", null: false
      t.string "username"
      t.index [ "ip", "occurred_at" ], name: "index_honeypot_events_on_ip_and_occurred_at"
      t.index [ "occurred_at" ], name: "index_honeypot_events_on_occurred_at"
      t.index [ "trigger" ], name: "index_honeypot_events_on_trigger"
    end
  end
end
