# frozen_string_literal: true

# One DMARC evaluation per accepted-or-rejected inbound message whose
# From domain publishes a DMARC record, written by the SMTP session
# through the store (SmtpBackend#dmarc_event). SendDmarcReportsJob rolls
# the previous day's rows into RFC 7489 aggregate XML reports for each
# policy domain's rua= addresses; retention is enforced daily.
class CreateDmarcAggregateEvents < ActiveRecord::Migration[8.1]
  def change
    create_table "mail_on_rails_dmarc_aggregate_events" do |t|
      t.string :policy_domain, null: false # domain whose record supplied the policy (rua target)
      t.string :from_domain                # RFC5322.From domain
      t.string :source_ip
      t.string :envelope_from
      t.string :disposition, null: false, default: "none" # none/quarantine/reject, post-override
      t.string :override_reason            # set when local policy softened the published disposition
      t.boolean :dkim_aligned, null: false, default: false
      t.boolean :spf_aligned, null: false, default: false
      t.string :spf_result
      t.string :spf_domain
      t.string :dkim_results               # compact "domain=result,..." for the auth_results block
      t.string :policy_p
      t.string :policy_sp
      t.string :policy_adkim
      t.string :policy_aspf
      t.integer :policy_pct
      t.datetime :occurred_at, null: false

      t.index [ "policy_domain", "occurred_at" ], name: "index_dmarc_aggregate_events_on_domain_and_time"
      t.index [ "occurred_at" ], name: "index_dmarc_aggregate_events_on_occurred_at"
    end
  end
end
