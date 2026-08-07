# Nightly pg_dump of the primary database (recurring, see
# config/recurring.yml; on demand via bin/db-backup or `bin/kamal backup`).
# Only the primary is dumped - it holds all the mail; the cache/queue/cable
# databases are derived state that db:prepare recreates empty on restore.
#
# Dumps land in DB_BACKUP_DIR (default storage/backups - in production
# that is the persistent mail_on_rails_storage volume, so backups survive
# container replacement) in pg_dump's custom format, which pg_restore can
# restore selectively and out of order. Retention is DB_BACKUP_KEEP_DAYS
# (default 14); pruning happens after each successful dump, so a failing
# pg_dump can never age the last good backup out.
#
# Copy the directory off the host on your own schedule - a backup on the
# same disk protects against bad deploys and fat fingers, not against
# losing the machine. See docs/backups.md for the restore runbook.
class DatabaseBackupJob < ApplicationJob
  queue_as :default

  KEEP_DAYS = Integer(ENV.fetch("DB_BACKUP_KEEP_DAYS", 14))

  # Returns the path of the dump it wrote. +config+ overrides the primary
  # connection settings (a test seam).
  def perform(config = nil)
    dir = Pathname(ENV.fetch("DB_BACKUP_DIR") { Rails.root.join("storage/backups").to_s })
    dir.mkpath

    config ||= ActiveRecord::Base.connection_db_config.configuration_hash
    file = dir.join("#{config[:database]}-#{Time.now.utc.strftime("%Y%m%dT%H%M%SZ")}.dump")

    run_pg_dump(config, file)
    prune(dir)

    Rails.logger.info "[mail_on_rails] database backup written: #{file} (#{file.size} bytes)"
    file.to_s
  end

  private

  def run_pg_dump(config, file)
    args = [ "pg_dump", "--format=custom", "--no-password", "--file", file.to_s ]
    # A leading-slash host is a Unix socket directory - pg_dump takes both
    # through --host, exactly like the pg adapter.
    host = config[:host] || config[:socket]
    args += [ "--host", host.to_s ] if host
    args += [ "--username", config[:username].to_s ] if config[:username]
    args << config[:database].to_s

    env = config[:password] ? { "PGPASSWORD" => config[:password].to_s } : {}
    return if system(env, *args)

    file.delete if file.exist? # never leave a truncated dump looking real
    raise "pg_dump failed for #{config[:database]} (exit #{$?.exitstatus})"
  end

  def prune(dir)
    cutoff = Time.now - KEEP_DAYS * 86_400
    dir.glob("*.dump").select { |f| f.mtime < cutoff }.each do |stale|
      stale.delete
      Rails.logger.info "[mail_on_rails] pruned database backup #{stale}"
    end
  end
end
