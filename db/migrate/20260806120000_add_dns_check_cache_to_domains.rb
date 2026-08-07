class AddDnsCheckCacheToDomains < ActiveRecord::Migration[8.1]
  def change
    add_column :domains, :dns_checks, :jsonb
    add_column :domains, :dns_checked_at, :datetime
  end
end
