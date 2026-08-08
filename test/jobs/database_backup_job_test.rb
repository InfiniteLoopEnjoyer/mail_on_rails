require "test_helper"

# The nightly pg_dump: a real custom-format dump lands in DB_BACKUP_DIR,
# stale dumps are pruned only after a successful run, and a failed dump
# never leaves a truncated file behind.
class DatabaseBackupJobTest < ActiveSupport::TestCase
  def with_backup_dir
    Dir.mktmpdir do |dir|
      previous = ENV["DB_BACKUP_DIR"]
      ENV["DB_BACKUP_DIR"] = dir
      yield Pathname(dir)
    ensure
      previous ? ENV["DB_BACKUP_DIR"] = previous : ENV.delete("DB_BACKUP_DIR")
    end
  end

  test "writes a custom-format dump of the primary database and prunes stale ones" do
    with_backup_dir do |dir|
      stale = dir.join("old.dump")
      stale.write("x")
      stale.utime(Time.now - (DatabaseBackupJob::KEEP_DAYS + 1) * 86_400,
                  Time.now - (DatabaseBackupJob::KEEP_DAYS + 1) * 86_400)
      fresh = dir.join("fresh.dump")
      fresh.write("x")

      path = DatabaseBackupJob.perform_now

      dump = Pathname(path)
      assert dump.exist?
      assert_equal dir.to_s, dump.dirname.to_s
      assert_match(/\A#{ActiveRecord::Base.connection_db_config.database}-\d{8}T\d{6}Z\.dump\z/,
                   dump.basename.to_s)
      # pg_dump custom format opens with the PGDMP magic bytes.
      assert_equal "PGDMP", dump.binread(5)

      assert_not stale.exist?, "a dump past the retention window must be pruned"
      assert fresh.exist?, "a dump inside the retention window must be kept"
    end
  end

  test "a failed pg_dump raises and leaves no truncated dump behind" do
    with_backup_dir do |dir|
      config = ActiveRecord::Base.connection_db_config.configuration_hash
                                 .merge(database: "no_such_database_anywhere")

      error = assert_raises(RuntimeError) { DatabaseBackupJob.perform_now(config) }
      assert_match(/pg_dump failed/, error.message)
      assert_empty dir.glob("*.dump"), "a failed run must not leave a dump file"
    end
  end

  KEY = "ab" * 32
  DECRYPT = Rails.root.join("bin/db-backup-decrypt").to_s

  def with_encryption_key(key = KEY)
    previous = ENV["DB_BACKUP_ENCRYPTION_KEY"]
    ENV["DB_BACKUP_ENCRYPTION_KEY"] = key
    yield
  ensure
    previous ? ENV["DB_BACKUP_ENCRYPTION_KEY"] = previous : ENV.delete("DB_BACKUP_ENCRYPTION_KEY")
  end

  test "with DB_BACKUP_ENCRYPTION_KEY the dump is encrypted and bin/db-backup-decrypt recovers it" do
    with_backup_dir do |dir|
      path = with_encryption_key { DatabaseBackupJob.perform_now }

      encrypted = Pathname(path)
      assert_match(/\.dump\.enc\z/, encrypted.basename.to_s)
      assert_equal DatabaseBackupJob::MAGIC, encrypted.binread(8)
      assert_not_equal "PGDMP", encrypted.binread(5), "ciphertext must not open like a plain dump"

      assert system({ "DB_BACKUP_ENCRYPTION_KEY" => KEY }, DECRYPT, encrypted.to_s,
                    err: File::NULL, out: File::NULL), "decrypt script must succeed with the right key"
      assert_equal "PGDMP", dir.join(encrypted.basename.to_s.delete_suffix(".enc")).binread(5)
    end
  end

  test "bin/db-backup-decrypt refuses a wrong key and writes nothing" do
    with_backup_dir do |dir|
      encrypted = Pathname(with_encryption_key { DatabaseBackupJob.perform_now })

      assert_not system({ "DB_BACKUP_ENCRYPTION_KEY" => "cd" * 32 }, DECRYPT, encrypted.to_s,
                        err: File::NULL, out: File::NULL)
      assert_empty dir.glob("*.dump"), "a failed decrypt must not leave plaintext output"
    end
  end

  test "a malformed encryption key fails the run instead of writing a plain dump" do
    with_backup_dir do |dir|
      error = assert_raises(RuntimeError) do
        with_encryption_key("too-short") { DatabaseBackupJob.perform_now }
      end
      assert_match(/64 hex characters/, error.message)
      assert_empty dir.glob("*.dump*"), "no dump may be written under a bad key"
    end
  end

  test "pruning covers encrypted dumps too" do
    with_backup_dir do |dir|
      stale = dir.join("old.dump.enc")
      stale.write("x")
      old = Time.now - (DatabaseBackupJob::KEEP_DAYS + 1) * 86_400
      stale.utime(old, old)

      DatabaseBackupJob.perform_now

      assert_not stale.exist?, "a stale encrypted dump must be pruned"
    end
  end
end
