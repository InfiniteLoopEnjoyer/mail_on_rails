# frozen_string_literal: true

# Per-IP attribution cache (ASN, AS name, country, prefix, reverse DNS -
# the same CymruLookup blob honeypot events carry) behind the live
# connection pages. One row per address ever displayed: the pages read
# the cache and enqueue lookups for addresses they have not seen, so the
# blocking DNS never runs on a request. jsonb/json split mirrors the
# honeypot enrichment column.
class CreateIpEnrichments < ActiveRecord::Migration[8.1]
  include MailOnRails::MigrationHelpers

  def change
    create_table "mail_on_rails_ip_enrichments" do |t|
      t.string "ip", null: false
      postgres? ? t.jsonb("enrichment") : t.json("enrichment")
      # When a lookup was last enqueued (the in-flight debounce) and when
      # one last completed (the freshness clock) - kept separate so a lost
      # job re-enqueues after the debounce instead of never.
      t.datetime "requested_at"
      t.datetime "looked_up_at"
      t.datetime "created_at", null: false
      t.datetime "updated_at", null: false
      t.index [ "ip" ], name: "index_ip_enrichments_on_ip", unique: true
      t.index [ "updated_at" ], name: "index_ip_enrichments_on_updated_at"
    end
  end
end
