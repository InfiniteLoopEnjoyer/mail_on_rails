class AddDkimPrivateKeyToDomains < ActiveRecord::Migration[8.1]
  # Migration-local model so the backfill doesn't depend on the app's
  # Domain class (whose callbacks/validations may drift later).
  class MigrationDomain < ActiveRecord::Base
    self.table_name = "domains"
    encrypts :dkim_private_key
  end

  # DKIM keys move from per-domain pem files (MAIL_ON_RAILS_DKIM_DIR) into
  # an encrypted column; the files are retired once this has shipped.
  def up
    add_column :domains, :dkim_private_key, :text
    MigrationDomain.reset_column_information

    dir = ENV["MAIL_ON_RAILS_DKIM_DIR"].presence || Rails.root.join("storage/dkim").to_s
    MigrationDomain.find_each do |domain|
      path = File.join(dir, "#{domain.name}.pem")
      next unless File.exist?(path)

      domain.update!(dkim_private_key: File.read(path))
      say "backfilled DKIM key for #{domain.name}"
    end
  end

  def down
    remove_column :domains, :dkim_private_key
  end
end
