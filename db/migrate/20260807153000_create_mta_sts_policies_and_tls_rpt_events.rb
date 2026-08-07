# Outbound transport-security state: the cached MTA-STS policy per
# recipient domain (RFC 8461 requires honoring a fetched policy for its
# max_age even if DNS or the policy host later vanish), and the per-
# delivery-attempt TLS outcome log that feeds daily TLS-RPT reports
# (RFC 8460) back to domains that ask for them.
class CreateMtaStsPoliciesAndTlsRptEvents < ActiveRecord::Migration[8.1]
  def change
    create_table :mta_sts_policies do |t|
      t.string :domain, null: false
      t.string :sts_id, null: false
      t.string :mode, null: false
      t.integer :max_age, null: false
      t.text :mx_patterns, null: false
      t.datetime :fetched_at, null: false
      t.timestamps
      t.index :domain, unique: true
    end

    create_table :tls_rpt_events do |t|
      t.string :policy_domain, null: false
      t.string :receiving_mx
      t.string :policy_type, null: false
      t.string :result_type
      t.string :failure_detail
      t.datetime :occurred_at, null: false
      t.timestamps
      t.index [ :policy_domain, :occurred_at ]
      t.index :occurred_at
    end
  end
end
