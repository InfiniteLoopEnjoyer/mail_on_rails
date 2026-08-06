require "test_helper"

class ClosedConnectionTest < ActiveSupport::TestCase
  IP = "203.0.113.9"

  def with_cap(rows)
    previous = ENV["MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP"]
    ENV["MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP"] = rows.to_s
    yield
  ensure
    previous ? ENV["MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP"] = previous
             : ENV.delete("MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP")
  end

  # The payload shape Server#report_closed assembles.
  def record(overrides = {})
    ClosedConnection.record({
      protocol: "smtp", ip: IP, port: 1025, role: :mx,
      connected_at: 30.seconds.ago, closed_at: Time.current,
      duration_seconds: 30.0, user: nil, helo: "client.test",
      messages: 0, tls: true
    }.merge(overrides))
  end

  # -- what gets written -----------------------------------------------------

  test "records a closed connection with its session facts" do
    record(user: "carol@example.com", messages: 2, state: nil)
    row = ClosedConnection.sole

    assert_equal "smtp", row.protocol
    assert_equal IP, row.ip
    assert_equal 1025, row.port
    assert_equal "mx", row.role
    assert_equal "carol@example.com", row.username
    assert_equal "client.test", row.helo
    assert_equal 2, row.messages
    assert row.tls?
    assert_in_delta 30.0, row.duration_seconds
    assert_not row.rollup?
  end

  test "records IMAP state and never raises on bad input" do
    record(protocol: "imap", role: nil, helo: nil, messages: nil, state: "IDLE INBOX")

    assert_equal "IDLE INBOX", ClosedConnection.sole.final_state

    assert_nil ClosedConnection.record(nil) # logged, not raised
  end

  # -- roll-up ---------------------------------------------------------------

  test "collapses anonymous noise past the per-ip cap" do
    with_cap(2) do
      3.times { record }
    end

    rows = ClosedConnection.order(:id).to_a
    assert_equal 3, rows.size
    assert_equal [ false, false, true ], rows.map(&:rollup?)
    assert_equal 1, rows.last.connection_count

    with_cap(2) { record }
    assert_equal 2, rows.last.reload.connection_count
  end

  test "authenticated and delivering connections bypass the cap" do
    with_cap(1) do
      record
      record(user: "carol@example.com")
      record(messages: 1)
    end

    assert_equal 0, ClosedConnection.where(rollup: true).count
    assert_equal 3, ClosedConnection.count
  end

  test "rollup counters are kept per protocol" do
    with_cap(1) do
      2.times { record }
      2.times { record(protocol: "imap", role: nil) }
    end

    rollups = ClosedConnection.where(rollup: true).order(:protocol)
    assert_equal %w[imap smtp], rollups.map(&:protocol)
  end

  # -- queries ---------------------------------------------------------------

  test "recent_list filters by protocol and window, newest first" do
    record(closed_at: 2.days.ago)
    record
    record(protocol: "imap", role: nil)

    rows = ClosedConnection.recent_list("smtp", since: 1.day.ago)
    assert_equal 1, rows.size
    assert_equal "smtp", rows.first.protocol

    assert_equal 2, ClosedConnection.recent_list("smtp", since: 3.days.ago).size
  end

  test "prune! enforces retention" do
    record(closed_at: (ClosedConnection.retention_days + 1).days.ago)
    record

    ClosedConnection.prune!

    assert_equal 1, ClosedConnection.count
  end
end
