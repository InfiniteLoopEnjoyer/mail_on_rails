# frozen_string_literal: true

require_relative "test_helper"

# auth_auto_ban: a failed SMTP/IMAP login writes a permanent BannedIp for
# its source once the address reaches auth_auto_ban_failures in the
# throttle window. Off by default; no exceptions once on.
class AutoBanTest < DbSuite::TestCase
  def setup
    super
    ENV.delete("MAIL_ON_RAILS_AUTH_AUTO_BAN")
    ENV.delete("MAIL_ON_RAILS_AUTH_AUTO_BAN_FAILURES")
    MailOnRails::EmailAccount.create!(email: "bob@example.test", password: "correct-horse-battery")
  end

  def teardown
    ENV.delete("MAIL_ON_RAILS_AUTH_AUTO_BAN")
    ENV.delete("MAIL_ON_RAILS_AUTH_AUTO_BAN_FAILURES")
  end

  def store = @store ||= MailOnRails::Store::Base.new

  def enable(failures: nil)
    ENV["MAIL_ON_RAILS_AUTH_AUTO_BAN"] = "1"
    ENV["MAIL_ON_RAILS_AUTH_AUTO_BAN_FAILURES"] = failures.to_s if failures
  end

  def fail_login(ip: "203.0.113.9", email: "bob@example.test", source: "imap")
    store.authenticate(email, "wrong-password", ip: ip, source: source)
  end

  def bans = MailOnRails::BannedIp.order(:cidr).pluck(:cidr, :source, :note)

  test "off by default: a failed login is throttled and logged but never banned" do
    5.times { fail_login }

    assert_empty bans
    assert MailOnRails::AuthAttempt.where(outcome: "bad_credentials").exists?, "still logged"
    assert MailOnRails::AuthThrottle.ip_failures("203.0.113.9").positive?, "still throttled"
  end

  test "on: the first failure bans the address permanently" do
    enable
    result = fail_login

    assert_nil result[:account_id]
    assert_equal [ [ "203.0.113.9", "auth_failure", "auto: failed imap login as bob@example.test" ] ], bans
    assert MailOnRails::BannedIp.covering("203.0.113.9")
    assert_includes store.banned_cidrs, "203.0.113.9"
  end

  test "a higher threshold bans on the nth failure in the window" do
    enable(failures: 3)

    2.times { fail_login }
    assert_empty bans

    fail_login
    assert_equal [ "203.0.113.9" ], bans.map(&:first)
  end

  test "an already-covered address gets no second row" do
    enable
    MailOnRails::BannedIp.create!(cidr: "203.0.113.0/24", note: "manual")

    fail_login
    assert_equal [ "203.0.113.0/24" ], bans.map(&:first)
  end

  test "a successful login never bans" do
    enable
    result = store.authenticate("bob@example.test", "correct-horse-battery", ip: "203.0.113.9", source: "imap")

    assert result[:account_id]
    assert_empty bans
  end

  test "a failure the daemon adjudicated (SCRAM) bans the same way" do
    enable
    store.record_auth_failure("bob@example.test", ip: "203.0.113.9", source: "smtp")

    assert_equal [ [ "203.0.113.9", "auth_failure", "auto: failed smtp login as bob@example.test" ] ], bans
  end

  test "an ipv6 source is banned as its /64, like the throttle keys it" do
    enable
    fail_login(ip: "2001:db8:1:2::7")

    assert_equal [ "2001:db8:1:2::/64" ], bans.map(&:first)
    assert MailOnRails::BannedIp.covering("2001:db8:1:2::8")
    assert_nil MailOnRails::BannedIp.covering("2001:db8:1:3::7")
  end

  # L9: behind a userland proxy, a TCP load balancer without proxy protocol
  # or a Docker bridge without ip6tables, every client is the gateway
  # address; one stale password must not ban them all. Loud, so the
  # operator learns their listener sits behind such a hop.
  test "a local source address is never banned, loudly" do
    enable
    log = StringIO.new
    logger_before = MailOnRails.logger
    MailOnRails.logger = Logger.new(log)
    begin
      [ "172.18.0.1", "127.0.0.1", "10.0.0.4", "fd46:7ac3:4fd7::1", "::ffff:192.168.1.9", "169.254.10.1" ].each do |ip|
        fail_login(ip: ip)
        store.record_auth_failure("bob@example.test", ip: ip, source: "smtp")
      end
    ensure
      MailOnRails.logger = logger_before
    end

    assert_empty bans
    assert MailOnRails::AuthThrottle.ip_failures("172.18.0.1").positive?, "still throttled"
    assert MailOnRails::AuthAttempt.where(outcome: "bad_credentials").exists?, "still logged"
    assert_match(/refusing to auto-ban local address 172\.18\.0\.1 \(auth_failure: auto: failed imap login/, log.string)
    assert_match(/every client/, log.string)
  end

  test "no source address, no ban" do
    enable
    fail_login(ip: nil)

    assert_empty bans
  end

  test "the note keeps an attacker-supplied username printable and short" do
    enable
    fail_login(email: "x\r\nInjected: y" + ("a" * 200))

    note = MailOnRails::BannedIp.sole.note
    refute_match(/[\r\n]/, note)
    assert_operator note.length, :<=, 120
    assert_match(/\Aauto: failed imap login as xInjected:y/, note)
  end

  test "the throttle's failure count feeds the threshold" do
    assert_equal 0, MailOnRails::AuthThrottle.ip_failures("203.0.113.9")
    2.times { fail_login }
    assert_equal 2, MailOnRails::AuthThrottle.ip_failures("203.0.113.9")
    assert_equal 0, MailOnRails::AuthThrottle.ip_failures("203.0.113.9", now: 1.day.from_now), "a lapsed window reads as zero"
  end
end
