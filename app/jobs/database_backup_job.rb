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
# With DB_BACKUP_ENCRYPTION_KEY set (64 hex chars: `openssl rand -hex 32`),
# the dump is streamed through AES-256-GCM and written as .dump.enc -
# never touching disk in the clear. The key lives in the container
# environment (a Kamal secret), the ciphertext on the storage volume, so
# neither a leaked volume snapshot nor a stolen disk yields the mail store
# by itself. bin/db-backup-decrypt (standalone, no Rails) recovers the
# plain dump for pg_restore; losing the key means losing the backups, so
# escrow it wherever the other deploy secrets live.
#
# Copy the directory off the host on your own schedule - a backup on the
# same disk protects against bad deploys and fat fingers, not against
# losing the machine. See docs/backups.md for the restore runbook.
class DatabaseBackupJob < ApplicationJob
  queue_as :default

  KEEP_DAYS = Integer(ENV.fetch("DB_BACKUP_KEEP_DAYS", 14))

  # bin/db-backup-decrypt mirrors these; change them in lockstep.
  MAGIC = "MORBKUP1"
  CIPHER = "aes-256-gcm"

  # Returns the path of the dump it wrote. +config+ overrides the primary
  # connection settings (a test seam).
  def perform(config = nil)
    dir = Pathname(ENV.fetch("DB_BACKUP_DIR") { Rails.root.join("storage/backups").to_s })
    dir.mkpath

    key = encryption_key
    if key.nil? && Rails.env.production?
      Rails.logger.warn "[mail_on_rails] database backups are UNENCRYPTED - " \
                        "set DB_BACKUP_ENCRYPTION_KEY (openssl rand -hex 32)"
    end

    config ||= ActiveRecord::Base.connection_db_config.configuration_hash
    stamp = Time.now.utc.strftime("%Y%m%dT%H%M%SZ")
    file = dir.join("#{config[:database]}-#{stamp}.dump#{".enc" if key}")

    run_pg_dump(config, file, key)
    prune(dir)

    Rails.logger.info "[mail_on_rails] database backup written: #{file} (#{file.size} bytes)"
    file.to_s
  end

  private

  def run_pg_dump(config, file, key)
    args = [ "pg_dump", "--format=custom", "--no-password" ]
    # A leading-slash host is a Unix socket directory - pg_dump takes both
    # through --host, exactly like the pg adapter.
    host = config[:host] || config[:socket]
    args += [ "--host", host.to_s ] if host
    args += [ "--username", config[:username].to_s ] if config[:username]
    args << config[:database].to_s

    env = config[:password] ? { "PGPASSWORD" => config[:password].to_s } : {}
    file.open("wb") do |out|
      IO.popen(env, args, "rb") do |dump|
        key ? encrypt_stream(dump, out, key) : IO.copy_stream(dump, out)
      end
    end
    return if $?.success?

    file.delete if file.exist? # never leave a truncated dump looking real
    raise "pg_dump failed for #{config[:database]} (exit #{$?.exitstatus})"
  end

  # File layout: MAGIC (8 bytes), IV (12), ciphertext, GCM tag (16). The
  # tag authenticates the whole stream, so pg_restore can only ever see
  # bytes the key holder wrote - truncation or tampering fails decryption.
  def encrypt_stream(dump, out, key)
    cipher = OpenSSL::Cipher.new(CIPHER).encrypt
    cipher.key = key
    out.write(MAGIC, cipher.random_iv)
    while (chunk = dump.read(1 << 20))
      out.write(cipher.update(chunk))
    end
    out.write(cipher.final, cipher.auth_tag)
  end

  # nil when unset (dev default: plain dumps); anything set must be a full
  # 256-bit key - silently deriving from a short passphrase would look
  # encrypted while being guessable.
  def encryption_key
    hex = ENV["DB_BACKUP_ENCRYPTION_KEY"].to_s
    return nil if hex.empty?
    unless hex.match?(/\A\h{64}\z/)
      raise "DB_BACKUP_ENCRYPTION_KEY must be 64 hex characters (openssl rand -hex 32)"
    end

    [ hex ].pack("H*")
  end

  def prune(dir)
    cutoff = Time.now - KEEP_DAYS * 86_400
    dir.glob("*.{dump,dump.enc}").select { |f| f.mtime < cutoff }.each do |stale|
      stale.delete
      Rails.logger.info "[mail_on_rails] pruned database backup #{stale}"
    end
  end
end
