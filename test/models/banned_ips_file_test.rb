require "test_helper"
require "tmpdir"

class BannedIpsFileTest < ActiveSupport::TestCase
  setup do
    @dir = Dir.mktmpdir
    @path = File.join(@dir, "banned_ips")
    ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"] = @path
  end

  teardown do
    ENV.delete("MAIL_ON_RAILS_BANNED_IPS_FILE")
    FileUtils.remove_entry(@dir)
  end

  test "no-op without the env var" do
    ENV.delete("MAIL_ON_RAILS_BANNED_IPS_FILE")
    assert_equal :skipped, BannedIpsFile.sync!
    assert_equal [], BannedIpsFile.current
  end

  test "writes one CIDR per line, sorted, world-readable" do
    BannedIp.create!(cidr: "203.0.113.0/24")
    BannedIp.create!(cidr: "198.51.100.7")

    assert_equal :written, BannedIpsFile.sync!
    assert_equal %w[198.51.100.7 203.0.113.0/24], File.readlines(@path, chomp: true)
    assert_equal %w[198.51.100.7 203.0.113.0/24], BannedIpsFile.current
    assert_equal 0o644, File.stat(@path).mode & 0o777
  end

  test "no bans writes an empty file, not a missing one" do
    assert_equal :written, BannedIpsFile.sync!
    assert File.exist?(@path), "empty means 'no bans' - written even with zero rows"
    assert_equal "", File.read(@path)
  end

  test "raises when the directory is not writable" do
    ENV["MAIL_ON_RAILS_BANNED_IPS_FILE"] = "/nonexistent/banned_ips"
    assert_raises(BannedIpsFile::Error) { BannedIpsFile.sync! }
  end

  test "ban and unban keep the file in step" do
    ban = BannedIp.create!(cidr: "203.0.113.0/24")
    assert_equal %w[203.0.113.0/24], BannedIpsFile.current

    ban.destroy!
    assert_equal [], BannedIpsFile.current
  end
end
