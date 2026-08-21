# frozen_string_literal: true

require_relative "test_helper"

# ClosedConnection.top_sources - the repeat-offender aggregation behind
# the live connection pages' Top sources table. Its contract: one row per
# address, totals that count rollup connection_count and individual rows
# alike, busiest address first, scoped to protocol and window.
class TopSourcesTest < DbSuite::TestCase
  def create_row(ip:, closed_at: 1.hour.ago, protocol: "smtp", **attributes)
    MailOnRails::ClosedConnection.create!(protocol: protocol, ip: ip, closed_at: closed_at, **attributes)
  end

  test "totals combine individual rows and rollup counters, busiest first" do
    3.times { create_row(ip: "203.0.113.9") }
    create_row(ip: "203.0.113.9", rollup: true, connection_count: 40)
    create_row(ip: "198.51.100.7", username: "carol@example.com")

    rows = MailOnRails::ClosedConnection.top_sources("smtp", since: 1.day.ago)

    assert_equal [ "203.0.113.9", "198.51.100.7" ], rows.map { |r| r[:ip] }
    assert_equal 43, rows.first[:connections]
    assert_equal 0, rows.first[:authenticated]
    assert_equal 1, rows.last[:connections]
    assert_equal 1, rows.last[:authenticated]
  end

  test "scoped to protocol and window, capped at limit, nil ips skipped" do
    create_row(ip: "203.0.113.9", protocol: "imap")
    create_row(ip: "203.0.113.9", closed_at: 3.days.ago)
    create_row(ip: nil)
    create_row(ip: "198.51.100.7")
    create_row(ip: "198.51.100.8")

    rows = MailOnRails::ClosedConnection.top_sources("smtp", since: 1.day.ago, limit: 1)

    assert_equal 1, rows.size
    assert_includes [ "198.51.100.7", "198.51.100.8" ], rows.first[:ip]
  end

  test "last_seen is the newest closed_at as a Time" do
    newest = 10.minutes.ago.change(usec: 0)
    create_row(ip: "203.0.113.9", closed_at: 2.hours.ago)
    create_row(ip: "203.0.113.9", closed_at: newest)

    row = MailOnRails::ClosedConnection.top_sources("smtp", since: 1.day.ago).first

    assert_kind_of Time, row[:last_seen]
    assert_in_delta newest.to_f, row[:last_seen].to_f, 1
  end
end
