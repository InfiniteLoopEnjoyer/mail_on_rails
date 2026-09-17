# frozen_string_literal: true

require_relative "test_helper"
require "fake_resolver"

# idle_auto_ban: an address that keeps connecting and never does any mail
# work gets a permanent BannedIp - but only after a grace period, and never
# when it is allowlisted, local, has logged in or delivered lately (closed
# or still open), or has forward-confirmed reverse DNS under
# idle_auto_ban_exempt_ptr. Off by default.
class IdleBanTest < DbSuite::TestCase
  SCANNER = "203.0.113.9"
  ENV_KEYS = %w[MAIL_ON_RAILS_IDLE_AUTO_BAN MAIL_ON_RAILS_IDLE_AUTO_BAN_SESSIONS
                MAIL_ON_RAILS_IDLE_AUTO_BAN_WINDOW MAIL_ON_RAILS_IDLE_AUTO_BAN_EXEMPT_PTR
                MAIL_ON_RAILS_HONEYPOT_ALLOWLIST MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP].freeze

  def setup
    super
    ENV_KEYS.each { |key| ENV.delete(key) }
    ActiveJob::Base.queue_adapter = :test
    enqueued.clear
  end

  def teardown
    ENV_KEYS.each { |key| ENV.delete(key) }
  end

  def store = @store ||= MailOnRails::Store::Base.new

  def enable(sessions: nil)
    ENV["MAIL_ON_RAILS_IDLE_AUTO_BAN"] = "1"
    ENV["MAIL_ON_RAILS_IDLE_AUTO_BAN_SESSIONS"] = sessions.to_s if sessions
  end

  def enqueued
    ActiveJob::Base.queue_adapter.enqueued_jobs.select { |job| job["job_class"] == "MailOnRails::IdleBanJob" }
  end

  # One closed connection, the way Server#report_closed hands it over.
  def close(ip: SCANNER, protocol: "smtp", idle: "silent", closed_at: Time.current, **extra)
    store.record_closed_connection({ protocol: protocol, ip: ip, port: 25, connected_at: closed_at - 1,
                                     closed_at: closed_at, duration_seconds: 1, idle: idle }.merge(extra).compact)
  end

  def decide(ip: SCANNER, protocol: "smtp", reason: "silent", resolver: FakeResolver.new)
    MailOnRails::BannedIp.auto_ban_for_idle(ip: ip, protocol: protocol, reason: reason, resolver: resolver)
  end

  def bans = MailOnRails::BannedIp.order(:cidr).pluck(:cidr, :source, :note)

  test "off by default: idle connections are counted but nothing is scheduled or banned" do
    5.times { close }

    assert_equal 5, MailOnRails::ClosedConnection.idle_strikes(SCANNER, since: 1.day.ago)
    assert_empty enqueued
    assert_nil decide
    assert_empty bans
  end

  test "the history row carries the shape; a connection that did something carries none" do
    close(idle: "tls_only")
    close(idle: nil, messages: 1)

    rows = MailOnRails::ClosedConnection.order(:id).pluck(:idle_reason, :idle_count)
    assert_equal [ [ "tls_only", 1 ], [ nil, 0 ] ], rows
  end

  test "on: the third idle connection schedules a decision after the grace, not a ban" do
    enable
    2.times { close }
    assert_empty enqueued

    close(protocol: "imap", idle: "no_auth")

    assert_equal 1, enqueued.size, "smtp and imap strikes count together"
    job = enqueued.first
    assert_equal [ SCANNER, "imap", "no_auth" ], job["arguments"]
    assert_in_delta MailOnRails::BannedIp::IDLE_BAN_GRACE.from_now.to_f, job["scheduled_at"].to_time.to_f, 5
    assert_empty bans, "nothing is banned on the connection thread"
  end

  test "connections that did mail work are not strikes" do
    enable
    5.times { close(idle: nil) }

    assert_empty enqueued
    assert_nil decide
  end

  test "a port sweep closing at once cannot step over the threshold; a hammering source is bounded" do
    enable
    12.times { close }

    # strikes 3, 4, 5 (the first band) then the multiples 6, 9, 12
    assert_equal 6, enqueued.size
  end

  test "the decision bans the address permanently with a note naming the last shape" do
    enable
    3.times { close }

    row = decide(reason: "tls_only")

    assert_equal [ [ SCANNER, "idle_scanner", "auto: 3 idle sessions in 24h (last: tls only on smtp)" ] ], bans
    assert_equal row, MailOnRails::BannedIp.covering(SCANNER)
    assert_includes store.banned_cidrs, SCANNER
    assert_includes MailOnRails::BannedIp::AUTOMATIC_SOURCES, "idle_scanner"
  end

  test "a failed TLS handshake's note says what else looks like that" do
    enable
    3.times { close(idle: "tls_handshake_failed", port: 993, protocol: "imap") }

    decide(protocol: "imap", reason: "tls_handshake_failed")

    assert_match(/last: tls handshake failed on imap\) - an expired certificate or a mail client/, bans.first.last)
  end

  test "the job hands its arguments to the decision" do
    seen = nil
    original = MailOnRails::BannedIp.method(:auto_ban_for_idle)
    MailOnRails::BannedIp.define_singleton_method(:auto_ban_for_idle) { |**args| seen = args }

    MailOnRails::IdleBanJob.perform_now(SCANNER, "smtp", "silent")

    assert_equal({ ip: SCANNER, protocol: "smtp", reason: "silent" }, seen)
  ensure
    MailOnRails::BannedIp.define_singleton_method(:auto_ban_for_idle, original)
  end

  test "strikes outside the window no longer count" do
    enable
    2.times { close(closed_at: 2.days.ago) }
    close

    assert_empty enqueued
    assert_nil decide
  end

  test "switched off during the grace: the decision bans nothing" do
    enable
    3.times { close }
    ENV.delete("MAIL_ON_RAILS_IDLE_AUTO_BAN")

    assert_nil decide
    assert_empty bans
  end

  test "an address a ban already covers is left alone" do
    enable
    MailOnRails::BannedIp.create!(cidr: "203.0.113.0/24")
    3.times { close }

    assert_empty enqueued
    assert_nil decide
    assert_equal 1, MailOnRails::BannedIp.count
  end

  test "IPv6 strikes and the ban key on the /64" do
    enable
    close(ip: "2001:db8:1:2::a")
    close(ip: "2001:db8:1:2::b")
    close(ip: "2001:db8:1:2::c")

    assert_equal 1, enqueued.size
    decide(ip: "2001:db8:1:2::c")
    assert_equal [ "2001:db8:1:2::/64" ], bans.map(&:first)
  end

  test "no address, nothing to ban" do
    enable
    3.times { close(ip: nil) }

    assert_empty enqueued
    assert_nil decide(ip: nil)
  end

  test "a local address is never banned: behind a proxy it is everyone" do
    enable
    [ "172.18.0.1", "127.0.0.1", "fd46:7ac3:4fd7::1", "::ffff:10.0.0.4" ].each do |ip|
      3.times { close(ip: ip) }
      assert_nil decide(ip: ip), ip
    end

    assert_empty enqueued
    assert_empty bans
  end

  test "the honeypot allowlist is honored" do
    enable
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = "203.0.113.0/24"
    3.times { close }

    assert_empty enqueued
    assert_nil decide
    assert_empty bans
  end

  test "an address that logged in lately is not a scanner" do
    enable
    close(idle: nil, user: "bob@example.test", protocol: "imap")
    3.times { close(protocol: "imap", idle: "no_auth") }

    assert_nil decide
    assert_empty bans
  end

  test "the login may land during the grace: account setup probes the ports first" do
    enable
    3.times { close(protocol: "imap", idle: "silent") }
    assert_equal 1, enqueued.size

    close(idle: nil, user: "bob@example.test", protocol: "imap")

    assert_nil decide
    assert_empty bans
  end

  test "an MX peer that delivered lately is not a scanner" do
    enable
    close(idle: nil, messages: 2)
    3.times { close(idle: "tls_only") }

    assert_nil decide
    assert_empty bans
  end

  test "work older than the lookback no longer protects" do
    enable
    close(idle: nil, user: "bob@example.test", closed_at: 30.days.ago)
    3.times { close }

    assert decide
  end

  test "a canary login is not mail work" do
    enable
    MailOnRails::EmailAccount.create!(email: "canary@example.test", password: "correct-horse-battery", honeypot: true)
    close(idle: nil, user: "canary@example.test", protocol: "imap")
    3.times { close }

    assert decide
  end

  test "a session that is logged in right now protects its address" do
    enable
    3.times { close(protocol: "imap", idle: "silent") }
    listener = MailOnRails::Listener.create!(listener_id: "imap-test", protocol: "imap",
                                              started_at: 2.hours.ago, heartbeat_at: 1.hour.ago)
    MailOnRails::OpenConnection.replace_for!(listener.listener_id, "imap",
                                             [ { connection_id: 1, peer_ip: SCANNER, port: 993,
                                                 connected_at: Time.current, user: "bob@example.test" } ])

    assert_nil decide, "even under a stale listener: a stale row errs toward not banning"
    assert_empty bans

    MailOnRails::OpenConnection.delete_all
    assert decide
  end

  test "forward-confirmed reverse DNS under an exempt suffix is not banned" do
    enable
    3.times { close(idle: "tls_only") }
    resolver = FakeResolver.new(ptr: { SCANNER => [ "mail-yw1-f169.Google.com." ] },
                                a: { "mail-yw1-f169.google.com" => [ SCANNER ] })

    assert_nil decide(resolver: resolver)
    assert_empty bans
  end

  test "a PTR that does not resolve back is the scanner's own claim" do
    enable
    3.times { close }
    resolver = FakeResolver.new(ptr: { SCANNER => [ "mail.google.com" ] },
                                a: { "mail.google.com" => [ "198.51.100.1" ] })

    assert decide(resolver: resolver)
  end

  test "a suffix must match on a label boundary" do
    enable
    3.times { close }
    resolver = FakeResolver.new(ptr: { SCANNER => [ "scanner.notgoogle.com" ] },
                                a: { "scanner.notgoogle.com" => [ SCANNER ] })

    assert decide(resolver: resolver)
  end

  test "a configured exempt list replaces the default" do
    enable
    ENV["MAIL_ON_RAILS_IDLE_AUTO_BAN_EXEMPT_PTR"] = "monitor.example"
    3.times { close }
    google = FakeResolver.new(ptr: { SCANNER => [ "mail.google.com" ] }, a: { "mail.google.com" => [ SCANNER ] })
    monitor = FakeResolver.new(ptr: { SCANNER => [ "probe1.monitor.example" ] },
                                a: { "probe1.monitor.example" => [ SCANNER ] })

    assert_nil decide(resolver: monitor)
    assert decide(resolver: google)
  end

  test "a resolver failure puts the ban off rather than deciding blind" do
    enable
    3.times { close }

    assert_nil decide(resolver: FakeResolver.new(ptr: { SCANNER => :temperror }))
    assert_nil decide(resolver: FakeResolver.new(ptr: { SCANNER => [ "mail.google.com" ] },
                                a: { "mail.google.com" => :temperror }))
    assert_empty bans
  end

  test "past the per-address cap idle connections still count, through the rollup row" do
    enable(sessions: 4)
    ENV["MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP"] = "1"
    4.times { close }

    rollup = MailOnRails::ClosedConnection.find_by(rollup: true)
    assert_equal [ 3, 3 ], [ rollup.connection_count, rollup.idle_count ]
    assert_equal 4, MailOnRails::ClosedConnection.idle_strikes(SCANNER, since: 1.day.ago)
    assert_equal 1, enqueued.size
  end

  test "a rolled-up connection that did something does not add an idle strike" do
    ENV["MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP"] = "0"
    close
    close(idle: nil)

    rollup = MailOnRails::ClosedConnection.find_by(rollup: true)
    assert_equal [ 2, 1 ], [ rollup.connection_count, rollup.idle_count ]
  end

  test "top sources reports each address's idle share" do
    2.times { close }
    close(idle: nil)

    row = MailOnRails::ClosedConnection.top_sources("smtp", since: 1.day.ago).first
    assert_equal [ 3, 2 ], [ row[:connections], row[:idle] ]
  end
end
