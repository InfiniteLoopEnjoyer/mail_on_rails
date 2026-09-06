# frozen_string_literal: true

require_relative "test_helper"

# auth_log_passwords: with the setting on, a failed plaintext login to an
# address that exists here keeps the rejected password (encrypted) so the
# operator can tell a breached old password from a fresh guess. Off by
# default; never for unknown addresses, throttled attempts or SCRAM.
class AuthLogPasswordsTest < DbSuite::TestCase
  ENV_KEY = "MAIL_ON_RAILS_AUTH_LOG_PASSWORDS"

  def setup
    super
    ENV.delete(ENV_KEY)
    MailOnRails::EmailAccount.create!(email: "bob@example.test", password: "correct-horse-battery")
  end

  def teardown
    ENV.delete(ENV_KEY)
  end

  def store = @store ||= MailOnRails::Store::Base.new

  def enable = ENV[ENV_KEY] = "1"

  def fail_login(email: "bob@example.test", password: "hunter2", ip: "203.0.113.9", source: "imap")
    store.authenticate(email, password, ip: ip, source: source)
  end

  def rows = MailOnRails::AuthAttempt.order(:id).pluck(:username, :outcome, :password)

  test "off by default: the attempt is logged without its password" do
    fail_login

    assert_equal [ [ "bob@example.test", "bad_credentials", nil ] ], rows
  end

  test "on: a bad password for a real address is kept" do
    enable
    fail_login

    assert_equal [ [ "bob@example.test", "bad_credentials", "hunter2" ] ], rows
  end

  test "on: the column holds ciphertext, not the password" do
    enable
    fail_login(password: "hunter2")

    raw = ActiveRecord::Base.connection.select_value(
      "SELECT password FROM mail_on_rails_auth_attempts"
    )
    refute_nil raw
    refute_includes raw, "hunter2"
  end

  test "on: a guess at an unknown address keeps nothing" do
    enable
    fail_login(email: "nobody@example.test")

    assert_equal [ [ "nobody@example.test", "unknown_account", nil ] ], rows
  end

  test "on: a throttled attempt keeps nothing - it was never checked" do
    enable
    MailOnRails::AuthThrottle.block_ip!("203.0.113.9", seconds: 600)
    result = fail_login

    assert result[:throttled]
    assert_equal [ [ "bob@example.test", "throttled", nil ] ], rows
  end

  test "on: a SCRAM failure has no password to keep" do
    enable
    store.record_auth_failure("bob@example.test", ip: "203.0.113.9", source: "smtp")

    assert_equal [ [ "bob@example.test", "bad_credentials", nil ] ], rows
  end

  test "on: raw SASL bytes are scrubbed and long pastes are cut" do
    enable
    fail_login(password: "p\xFFss" + ("x" * 500))

    kept = MailOnRails::AuthAttempt.sole.password
    assert kept.valid_encoding?
    assert_equal "p�ss", kept.first(4)
    assert_equal MailOnRails::AuthAttempt::MAX_PASSWORD_LENGTH, kept.length
  end

  test "on: an empty password is kept as nothing" do
    enable
    fail_login(password: "")

    assert_equal [ [ "bob@example.test", "bad_credentials", nil ] ], rows
  end

  test "a successful login is still not recorded at all" do
    enable
    result = store.authenticate("bob@example.test", "correct-horse-battery", ip: "203.0.113.9", source: "imap")

    assert result[:account_id]
    assert_empty rows
  end

  test "pruning takes the password with the row" do
    enable
    fail_login
    MailOnRails::AuthAttempt.update_all(occurred_at: 400.days.ago)
    MailOnRails::AuthAttempt.prune!

    assert_empty rows
  end
end
