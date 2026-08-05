class CreateBannedIps < ActiveRecord::Migration[8.1]
  def change
    create_table :banned_ips do |t|
      # Canonical CIDR ("203.0.113.9", "203.0.113.0/24", "2001:db8::/48").
      t.string :cidr, null: false
      t.string :note
      # "manual" (banned from the auth attempts page) or "spamhaus_drop"
      # (imported by SpamhausDropRefreshJob, replaced wholesale on refresh).
      t.string :source, null: false, default: "manual"

      t.timestamps
    end

    add_index :banned_ips, :cidr, unique: true
    # The DROP refresh replaces its own rows and never touches manual ones.
    add_index :banned_ips, :source
  end
end
