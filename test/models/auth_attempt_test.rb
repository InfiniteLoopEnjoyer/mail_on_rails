require "test_helper"

class AuthAttemptTest < ActiveSupport::TestCase
  IP = "92.118.39.228"
  REAL = "carol@example.com"

  setup do
    @account = EmailAccount.create!(email: REAL, password: "secret123")
  end

  def with_cap(rows)
    previous = ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"]
    ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"] = rows.to_s
    yield
  ensure
    previous ? ENV["MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP"] = previous
             : ENV.delete("MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP")
  end

  def record(username: "cyrus", ip: IP, source: "smtp", outcome: "unknown_account", now: Time.current)
    AuthAttempt.record(ip: ip, username: username, source: source, outcome: outcome, now: now)
  end

  # -- what gets written -----------------------------------------------------

  test "records an attempt with its source and outcome" do
    record(username: "postgres", outcome: "unknown_account")
    row = AuthAttempt.sole

    assert_equal IP, row.ip
    assert_equal "postgres", row.username
    assert_equal "smtp", row.source
    assert_equal "unknown_account", row.outcome
    assert_equal 1, row.attempt_count
    assert_not row.account_exists
    assert_not row.rollup
  end

  test "flags attempts against an address that exists here" do
    record(username: REAL, outcome: "bad_credentials")
    assert AuthAttempt.sole.account_exists
  end

  test "an alias counts as a real address" do
    EmailAlias.create!(email_account: @account, email: "sales@example.com")

    record(username: "sales@example.com")
    assert AuthAttempt.sole.account_exists
  end

  test "the web surface resolves against users, not mailboxes" do
    user = users(:one)
    record(username: user.email_address, source: "web")
    assert AuthAttempt.sole.account_exists

    record(username: REAL, source: "web")
    assert_not AuthAttempt.where(username: REAL).sole.account_exists,
               "a mailbox address is not a web login"
  end

  test "usernames are normalized so case cannot split the analysis" do
    record(username: "  CYRUS  ")
    assert_equal "cyrus", AuthAttempt.sole.username
  end

  # No password field exists, and none should ever be added - see the class
  # comment. This is the test that fails loudly if someone tries.
  test "no column holds password material" do
    suspicious = AuthAttempt.column_names.grep(/pass|secret|credential|token|digest/i)
    assert_empty suspicious, "AuthAttempt must never store password material"
  end

  # -- the write cap ---------------------------------------------------------

  # The attacker sets the write rate here, so the table has to stop growing
  # row-per-attempt at some point or the audit log becomes the outage.
  test "noise past the cap collapses into a single rollup row" do
    with_cap(3) do
      6.times { record }

      assert_equal 4, AuthAttempt.count, "3 rows plus one rollup"
      rollup = AuthAttempt.find_by(rollup: true)
      assert_equal 3, rollup.attempt_count
      assert_equal IP, rollup.ip
    end
  end

  test "a whole window of noise from one source collapses to one rollup row" do
    with_cap(2) do
      200.times { record }
      assert_equal 3, AuthAttempt.count
      assert_equal 198, AuthAttempt.find_by(rollup: true).attempt_count
    end
  end

  # The cap exists to shed dictionary noise. Attempts against an address
  # that exists are the signal the table is kept for, so they must survive
  # a flood aimed at burying them.
  test "attempts against real addresses are never collapsed" do
    with_cap(2) do
      10.times { record }
      5.times { record(username: REAL, outcome: "bad_credentials") }

      real_rows = AuthAttempt.against_real_accounts
      assert_equal 5, real_rows.count
      assert real_rows.none?(&:rollup)
    end
  end

  test "the cap is per source address" do
    with_cap(2) do
      4.times { record(ip: IP) }
      4.times { record(ip: "203.0.113.7") }

      assert_equal 2, AuthAttempt.where(rollup: true).count, "one rollup per address"
    end
  end

  test "an attempt with no source address is not collapsed" do
    with_cap(1) do
      3.times { record(ip: nil) }
      assert_equal 3, AuthAttempt.count
      assert_equal 0, AuthAttempt.where(rollup: true).count
    end
  end

  test "a later window starts a fresh rollup row" do
    with_cap(1) do
      3.times { record }
      3.times { record(now: 2.hours.from_now) }
      assert_equal 2, AuthAttempt.where(rollup: true).count
    end
  end

  # Logging is an audit trail hanging off the auth path; it must never be
  # able to break a login, or it becomes a way to deny service.
  test "a write failure is swallowed rather than raised" do
    patch = Module.new do
      def create!(*) = raise(ActiveRecord::StatementInvalid, "boom")
    end
    AuthAttempt.singleton_class.prepend(patch)
    begin
      assert_nothing_raised { record }
      assert_equal 0, AuthAttempt.count
    ensure
      # Dropping the override from the prepended module puts the real
      # create! back in the lookup chain for every later test.
      patch.send(:remove_method, :create!)
    end
  end

  # -- retention -------------------------------------------------------------

  test "prune drops rows past the retention window and keeps the rest" do
    record(now: 40.days.ago)
    record(now: 1.day.ago)

    AuthAttempt.prune!
    assert_equal 1, AuthAttempt.count
  end

  # -- analysis --------------------------------------------------------------

  test "targeted_accounts surfaces only addresses that exist" do
    3.times { record(username: REAL, outcome: "bad_credentials") }
    5.times { record(username: "cyrus") }

    assert_equal({ REAL => 3 }, AuthAttempt.targeted_accounts)
  end

  # A spray reads as noise one address at a time and as one campaign when
  # grouped by the range it arrived from.
  test "top_ranges groups ipv4 sources into 24s" do
    %w[92.118.39.204 92.118.39.211 92.118.39.228].each { |ip| record(ip: ip) }
    record(ip: "203.0.113.7")

    assert_equal [ [ "92.118.39.0/24", 3 ], [ "203.0.113.0/24", 1 ] ], AuthAttempt.top_ranges
  end

  test "top_ranges leaves non-ipv4 sources alone" do
    record(ip: "2001:db8::1")
    assert_equal [ [ "2001:db8::1", 1 ] ], AuthAttempt.top_ranges
  end

  test "rollup counts carry into the analysis totals" do
    with_cap(1) do
      10.times { record }
      assert_equal 10, AuthAttempt.totals[:attempts]
      assert_equal 9, AuthAttempt.totals[:collapsed]
    end
  end

  test "totals break down by source" do
    record(source: "smtp")
    record(source: "imap")
    record(source: "imap")

    assert_equal({ "smtp" => 1, "imap" => 2 }, AuthAttempt.totals[:by_source])
  end

  test "analysis windows exclude older rows" do
    record(now: 30.days.ago)
    record(now: 1.hour.ago)

    assert_equal 1, AuthAttempt.totals(since: 7.days.ago)[:attempts]
    assert_equal 2, AuthAttempt.totals(since: 60.days.ago)[:attempts]
  end

  test "range_detail aggregates one /24's addresses and nothing else" do
    2.times { record(ip: "92.118.39.204", username: "cyrus") }
    record(ip: "92.118.39.204", username: "postgres", source: "imap")
    record(ip: "92.118.39.211", username: REAL, outcome: "bad_credentials")
    record(ip: "92.118.3.9", username: "lookalike-prefix")
    record(ip: "203.0.113.7", username: "elsewhere")

    rows = AuthAttempt.range_detail("92.118.39.0/24")

    assert_equal %w[92.118.39.204 92.118.39.211], rows.map(&:ip)
    top = rows.first
    assert_equal 3, top.attempts
    assert_equal 2, top.usernames
    assert_equal %w[imap smtp], top.sources
    assert_not top.real_account
    assert rows.last.real_account
  end

  test "range_detail treats a non-IPv4 range as a single address" do
    record(ip: "2001:db8::5")
    record(ip: "2001:db8::6")

    rows = AuthAttempt.range_detail("2001:db8::5")
    assert_equal [ "2001:db8::5" ], rows.map(&:ip)
  end
end
