# frozen_string_literal: true

require_relative "test_helper"

# The rollup dedup key is a partial unique index on postgres/sqlite and a
# generated-column unique index on mysql; both must behave identically:
# rollup rows are unique per (key, window), non-rollup rows are
# unconstrained.
class RollupTest < DbSuite::TestCase
  def teardown
    ENV.delete("MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP")
  end

  def create_attempt(rollup:, occurred_at:, ip: "203.0.113.9")
    MailOnRails::AuthAttempt.create!(ip: ip, source: "imap", outcome: "unknown_account",
                                     rollup: rollup, occurred_at: occurred_at)
  end

  test "rollup rows are unique per window but non-rollup rows are unconstrained" do
    at = Time.current.change(usec: 0)
    2.times { create_attempt(rollup: false, occurred_at: at) }
    create_attempt(rollup: true, occurred_at: at)
    assert_raises(ActiveRecord::RecordNotUnique) { create_attempt(rollup: true, occurred_at: at) }
  end

  test "closed connection rollup key behaves the same way" do
    at = Time.current.change(usec: 0)
    attributes = { protocol: "imap", ip: "203.0.113.9", closed_at: at }
    2.times { MailOnRails::ClosedConnection.create!(**attributes, rollup: false) }
    MailOnRails::ClosedConnection.create!(**attributes, rollup: true)
    assert_raises(ActiveRecord::RecordNotUnique) do
      MailOnRails::ClosedConnection.create!(**attributes, rollup: true)
    end
  end

  test "dictionary noise past the cap collapses into one rollup row" do
    ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"] = "2"
    now = Time.current
    5.times do |i|
      MailOnRails::AuthAttempt.record(ip: "203.0.113.9", username: "ghost#{i}@example.test",
                                      source: "imap", outcome: "bad_credentials", now: now)
    end
    rollups = MailOnRails::AuthAttempt.where(rollup: true)
    assert_equal 1, rollups.count
    assert_equal 3, rollups.first.attempt_count
    assert_equal 2, MailOnRails::AuthAttempt.where(rollup: false).count
  end

  test "ipv6 noise rolls up per /64: rotating the host bits buys no extra rows" do
    ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"] = "2"
    now = Time.current
    6.times do |i|
      MailOnRails::AuthAttempt.record(ip: "2001:db8:1:2::#{i + 1}", username: "ghost#{i}@example.test",
                                      source: "imap", outcome: "bad_credentials", now: now)
    end
    MailOnRails::AuthAttempt.record(ip: "2001:db8:1:3::1", username: "ghost@example.test",
                                    source: "imap", outcome: "bad_credentials", now: now)

    individual = MailOnRails::AuthAttempt.where(rollup: false)
    assert_equal %w[2001:db8:1:2::1 2001:db8:1:2::2 2001:db8:1:3::1], individual.pluck(:ip).sort,
                 "two rows for the /64 (the cap), then the neighbouring /64's first row"
    rollup = MailOnRails::AuthAttempt.where(rollup: true)
    assert_equal 1, rollup.count
    assert_equal "2001:db8:1:2::/64", rollup.first.ip
    assert_equal 4, rollup.first.attempt_count
  end

  test "closed connections roll up per /64 the same way" do
    ENV["MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP"] = "1"
    begin
      3.times do |i|
        MailOnRails::ClosedConnection.record(protocol: "smtp", ip: "2001:db8:1:2::#{i + 1}", closed_at: Time.current)
      end
      assert_equal [ "2001:db8:1:2::1" ], MailOnRails::ClosedConnection.where(rollup: false).pluck(:ip)
      rollup = MailOnRails::ClosedConnection.find_by!(rollup: true)
      assert_equal "2001:db8:1:2::/64", rollup.ip
      assert_equal 2, rollup.connection_count
    ensure
      ENV.delete("MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP")
    end
  end

  test "top_ranges groups ipv6 by /64 and range_detail lists the /64's members" do
    now = Time.current
    { "2001:db8:1:2::1" => 3, "2001:db8:1:2::2" => 2, "2001:db8:1:3::1" => 1, "203.0.113.9" => 4 }.each do |ip, n|
      MailOnRails::AuthAttempt.create!(ip: ip, source: "imap", outcome: "unknown_account",
                                       username: "ghost@example.test", occurred_at: now, attempt_count: n)
    end
    MailOnRails::AuthAttempt.create!(ip: "2001:db8:1:2::/64", source: "imap", outcome: "unknown_account",
                                     rollup: true, occurred_at: now, attempt_count: 10)

    ranges = MailOnRails::AuthAttempt.top_ranges(since: 1.day.ago)
    assert_equal [ [ "2001:db8:1:2::/64", 15 ], [ "203.0.113.0/24", 4 ], [ "2001:db8:1:3::/64", 1 ] ], ranges

    detail = MailOnRails::AuthAttempt.range_detail("2001:db8:1:2::/64", since: 1.day.ago)
    assert_equal %w[2001:db8:1:2::/64 2001:db8:1:2::1 2001:db8:1:2::2], detail.map(&:ip).sort
    assert_equal [ "203.0.113.9" ], MailOnRails::AuthAttempt.range_detail("203.0.113.0/24", since: 1.day.ago).map(&:ip)
  end

  test "range_detail aggregates the boolean CASE expression on every adapter" do
    now = Time.current
    MailOnRails::AuthAttempt.create!(ip: "203.0.113.9", source: "imap", outcome: "bad_credentials",
                                     username: "real@example.test", account_exists: true,
                                     occurred_at: now)
    MailOnRails::AuthAttempt.create!(ip: "203.0.113.10", source: "smtp", outcome: "unknown_account",
                                     username: "ghost@example.test", account_exists: false,
                                     occurred_at: now)
    rows = MailOnRails::AuthAttempt.range_detail("203.0.113.0/24")
    assert_equal %w[203.0.113.10 203.0.113.9], rows.map(&:ip).sort
    assert_equal({ "203.0.113.9" => true, "203.0.113.10" => false },
                 rows.to_h { |row| [ row.ip, row.real_account ] })
  end
end
