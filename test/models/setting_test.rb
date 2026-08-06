require "test_helper"

class SettingTest < ActiveSupport::TestCase
  test "trash retention defaults to 30 days with no row" do
    assert_empty Setting.where(key: "trash_retention_days")
    assert_equal 30, Setting.trash_retention_days
  end

  test "trash retention round-trips and updates in place" do
    Setting.trash_retention_days = 7
    assert_equal 7, Setting.trash_retention_days

    Setting.trash_retention_days = "14"
    assert_equal 14, Setting.trash_retention_days
    assert_equal 1, Setting.where(key: "trash_retention_days").count
  end

  test "trash retention rejects junk and non-positive values" do
    assert_raises(ArgumentError) { Setting.trash_retention_days = "soon" }
    assert_raises(ArgumentError) { Setting.trash_retention_days = 0 }
    assert_raises(ArgumentError) { Setting.trash_retention_days = -3 }
    assert_raises(TypeError) { Setting.trash_retention_days = nil }
    assert_equal 30, Setting.trash_retention_days
  end

  # -- SMTP HELO hostname ----------------------------------------------------

  teardown do
    ENV.delete("SMTP_HELO_HOST")
  end

  test "smtp helo hostname precedence: setting, then env, then system hostname" do
    assert_nil Setting.smtp_helo_hostname
    assert_equal Socket.gethostname, Setting.effective_smtp_helo_hostname

    ENV["SMTP_HELO_HOST"] = "Env.Example.Test"
    assert_equal "env.example.test", Setting.smtp_helo_hostname

    Setting.smtp_helo_hostname = "mail.example.test"
    assert_equal "mail.example.test", Setting.smtp_helo_hostname
    assert_equal "mail.example.test", Setting.effective_smtp_helo_hostname
  end

  test "smtp helo hostname setter normalizes and blank clears the override" do
    Setting.smtp_helo_hostname = "  MX.Example.Test "
    assert_equal "mx.example.test", Setting.smtp_helo_hostname_override

    Setting.smtp_helo_hostname = ""
    assert_nil Setting.smtp_helo_hostname_override
    assert_empty Setting.where(key: "smtp_helo_hostname")
  end

  test "smtp helo hostname rejects non-hostnames" do
    [ "mail host", "-bad.example", "bad-.example", "mail..example", "mail.example/25", "a" * 256 ].each do |bad|
      assert_raises(ArgumentError, bad) { Setting.smtp_helo_hostname = bad }
    end
    assert_nil Setting.smtp_helo_hostname_override
  end
end
