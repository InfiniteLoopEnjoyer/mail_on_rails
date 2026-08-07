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
end
