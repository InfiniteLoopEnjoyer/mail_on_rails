# frozen_string_literal: true

require_relative "test_helper"

# The settings table as the DB tier of MailOnRails::Settings: strict
# writes, fail-soft reads, immediate propagation via the after_commit
# refresh.
class SettingTest < Minitest::Test
  def setup
    MailOnRails::Setting.delete_all
    MailOnRails::Settings.reset!
    MailOnRails::Settings.store = -> { MailOnRails::Setting.override_rows }
  end

  def teardown
    MailOnRails::Setting.delete_all
    MailOnRails::Settings.reset!
  end

  test "write stores the canonical form and read returns the typed value" do
    assert_equal 55, MailOnRails::Setting.write(:smtp_max_conn, "55")
    assert_equal "55", MailOnRails::Setting.find_by(key: "smtp_max_conn").value
    MailOnRails::Settings.refresh!
    assert_equal 55, MailOnRails::Setting.read(:smtp_max_conn)
    assert_equal :db, MailOnRails::Settings.provenance(:smtp_max_conn)
  end

  test "booleans and lists serialize canonically" do
    MailOnRails::Setting.write(:smtp_sender_auth, "0")
    assert_equal "0", MailOnRails::Setting.find_by(key: "smtp_sender_auth").value
    MailOnRails::Setting.write(:smtp_rbl_zones, "zen.spamhaus.org  bl.example.org")
    assert_equal "zen.spamhaus.org,bl.example.org", MailOnRails::Setting.find_by(key: "smtp_rbl_zones").value
    MailOnRails::Settings.refresh!
    assert_equal false, MailOnRails::Setting.read(:smtp_sender_auth)
    assert_equal %w[zen.spamhaus.org bl.example.org], MailOnRails::Setting.read(:smtp_rbl_zones)
  end

  test "write refuses unknown keys, static keys, and junk values" do
    assert_raises(ArgumentError) { MailOnRails::Setting.write(:no_such_setting, "1") }
    error = assert_raises(ArgumentError) { MailOnRails::Setting.write(:smtp_port, "2525") }
    assert_match(/boot-only/, error.message)
    assert_raises(ArgumentError) { MailOnRails::Setting.write(:smtp_max_conn, "many") }
    assert_raises(ArgumentError) { MailOnRails::Setting.write(:smtp_max_conn, "0") }
    assert_raises(ArgumentError) { MailOnRails::Setting.write(:smtp_helo_hostname, "not a host!") }
    assert_empty MailOnRails::Setting.override_rows
  end

  test "blank write clears the override" do
    MailOnRails::Setting.write(:smtp_max_conn, 55)
    MailOnRails::Setting.write(:smtp_max_conn, "  ")
    assert_empty MailOnRails::Setting.override_rows
    assert_equal 100, MailOnRails::Setting.read(:smtp_max_conn)
  end

  test "a commit refreshes the settings cache without waiting for the TTL" do
    assert_equal 100, MailOnRails::Setting.read(:smtp_max_conn) # prime the snapshot
    MailOnRails::Setting.write(:smtp_max_conn, 55)
    assert_equal 55, MailOnRails::Setting.read(:smtp_max_conn)
    MailOnRails::Setting.clear(:smtp_max_conn)
    assert_equal 100, MailOnRails::Setting.read(:smtp_max_conn)
  end

  test "trash retention delegates through the schema" do
    assert_equal 30, MailOnRails::Setting.trash_retention_days
    MailOnRails::Setting.trash_retention_days = "45"
    assert_equal 45, MailOnRails::Setting.trash_retention_days
    assert_raises(ArgumentError) { MailOnRails::Setting.trash_retention_days = 0 }
    assert_raises(ArgumentError) { MailOnRails::Setting.trash_retention_days = "soon" }
    assert_equal 45, MailOnRails::Setting.trash_retention_days
  end

  test "helo hostname keeps its normalization, validation and blank-clears" do
    MailOnRails::Setting.smtp_helo_hostname = "  Mail.Example.COM "
    assert_equal "mail.example.com", MailOnRails::Setting.smtp_helo_hostname_override
    assert_equal "mail.example.com", MailOnRails::Setting.smtp_helo_hostname
    assert_raises(ArgumentError) { MailOnRails::Setting.smtp_helo_hostname = "bad host" }
    MailOnRails::Setting.smtp_helo_hostname = ""
    assert_nil MailOnRails::Setting.smtp_helo_hostname_override
    refute_empty MailOnRails::Setting.effective_smtp_helo_hostname
  end
end
