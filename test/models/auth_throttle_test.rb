require "test_helper"

class AuthThrottleTest < ActiveSupport::TestCase
  IP = "203.0.113.9"
  EMAIL = "throttle@example.test"

  # Thresholds are env-tunable; pin small ones so the tests state their
  # intent instead of looping twenty times.
  def with_limits(ip: 3, account: 2, window: 900, ip_block: 900, account_block: 300)
    vars = {
      "MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES" => ip.to_s,
      "MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES" => account.to_s,
      "MAIL_ON_RAILS_AUTH_WINDOW" => window.to_s,
      "MAIL_ON_RAILS_AUTH_IP_BLOCK" => ip_block.to_s,
      "MAIL_ON_RAILS_AUTH_ACCOUNT_BLOCK" => account_block.to_s
    }
    previous = vars.keys.to_h { |k| [ k, ENV[k] ] }
    vars.each { |k, v| ENV[k] = v }
    yield
  ensure
    previous.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  # Only ever fail the account scope, by using a distinct IP each time.
  def fail_account(times, email: EMAIL)
    times.times { |i| AuthThrottle.record_failure(ip: "198.51.100.#{i}", email: email) }
  end

  # Only ever fail the IP scope, by using a distinct account each time.
  def fail_ip(times, ip: IP)
    times.times { |i| AuthThrottle.record_failure(ip: ip, email: "user#{i}@example.test") }
  end

  test "a fresh ip and account are not throttled" do
    assert_nil AuthThrottle.check(ip: IP, email: EMAIL)
  end

  test "failures below the limit do not block" do
    with_limits(ip: 3) do
      fail_ip(2)
      assert_nil AuthThrottle.check(ip: IP, email: "someone@example.test")
    end
  end

  test "the ip scope blocks once its limit is reached" do
    with_limits(ip: 3, ip_block: 900) do
      fail_ip(3)
      blocked = AuthThrottle.check(ip: IP, email: "someone@example.test")
      assert blocked, "expected the ip to be blocked"
      assert_equal "ip", blocked[:scope]
      assert_in_delta 900, blocked[:retry_after], 5
    end
  end

  test "the account scope blocks once its limit is reached, from any ip" do
    with_limits(account: 2, account_block: 300) do
      fail_account(2)
      # A brand new IP is still refused: the block follows the account.
      blocked = AuthThrottle.check(ip: "192.0.2.77", email: EMAIL)
      assert blocked
      assert_equal "account", blocked[:scope]
      assert_in_delta 300, blocked[:retry_after], 5
    end
  end

  test "an account block does not touch other accounts on the same ip" do
    with_limits(ip: 100, account: 2) do
      2.times { AuthThrottle.record_failure(ip: IP, email: EMAIL) }
      assert AuthThrottle.check(ip: IP, email: EMAIL)
      assert_nil AuthThrottle.check(ip: IP, email: "bystander@example.test")
    end
  end

  test "an ip block does not touch the same account from another ip" do
    with_limits(ip: 3, account: 100) do
      fail_ip(3)
      assert AuthThrottle.check(ip: IP, email: "someone@example.test")
      assert_nil AuthThrottle.check(ip: "192.0.2.5", email: "someone@example.test")
    end
  end

  test "when both scopes are blocked the longer block is reported" do
    with_limits(ip: 2, account: 2, ip_block: 900, account_block: 300) do
      2.times { AuthThrottle.record_failure(ip: IP, email: EMAIL) }
      blocked = AuthThrottle.check(ip: IP, email: EMAIL)
      assert_equal "ip", blocked[:scope]
      assert_in_delta 900, blocked[:retry_after], 5
    end
  end

  test "a block expires on its own" do
    with_limits(account: 2, account_block: 300) do
      fail_account(2)
      assert AuthThrottle.check(ip: IP, email: EMAIL)
      assert_nil AuthThrottle.check(ip: IP, email: EMAIL, now: 301.seconds.from_now)
    end
  end

  # Serving a block must restore the full budget. Otherwise the counter
  # stays at the limit and the first failure after the block re-blocks
  # immediately - an endless lockout for a user whose own device is
  # retrying a stale password.
  test "a lapsed block resets the counter rather than re-blocking on the next failure" do
    with_limits(account: 2, account_block: 300) do
      fail_account(2)
      later = 301.seconds.from_now

      AuthThrottle.record_failure(ip: "198.51.100.200", email: EMAIL, now: later)
      assert_nil AuthThrottle.check(ip: "198.51.100.200", email: EMAIL, now: later),
                 "one failure after a lapsed block must not re-block"

      row = AuthThrottle.find_by(scope: "account", key: EMAIL)
      assert_equal 1, row.failure_count
    end
  end

  test "failures outside the window do not accumulate" do
    with_limits(account: 2, window: 900) do
      AuthThrottle.record_failure(ip: IP, email: EMAIL)
      # The second failure lands after the window; the counter restarts.
      AuthThrottle.record_failure(ip: IP, email: EMAIL, now: 901.seconds.from_now)
      assert_nil AuthThrottle.check(ip: IP, email: EMAIL, now: 901.seconds.from_now)
      assert_equal 1, AuthThrottle.find_by(scope: "account", key: EMAIL).failure_count
    end
  end

  # Attempts made *during* a block must not push its expiry out, or an
  # attacker could pin someone else's account (or a shared NAT) forever.
  test "attempts during a block do not extend it" do
    with_limits(account: 2, account_block: 300) do
      fail_account(2)
      first = AuthThrottle.find_by(scope: "account", key: EMAIL).blocked_until

      10.times { AuthThrottle.record_failure(ip: IP, email: EMAIL, now: 100.seconds.from_now) }
      assert_equal first, AuthThrottle.find_by(scope: "account", key: EMAIL).reload.blocked_until
    end
  end

  test "clear_account resets that account but leaves the ip counter" do
    with_limits(ip: 100, account: 2) do
      2.times { AuthThrottle.record_failure(ip: IP, email: EMAIL) }
      AuthThrottle.clear_account(EMAIL)

      assert_nil AuthThrottle.find_by(scope: "account", key: EMAIL)
      assert_equal 2, AuthThrottle.find_by(scope: "ip", key: IP).failure_count
    end
  end

  test "clear_account normalizes the address" do
    AuthThrottle.record_failure(ip: IP, email: EMAIL)
    AuthThrottle.clear_account("  #{EMAIL.upcase}  ")
    assert_nil AuthThrottle.find_by(scope: "account", key: EMAIL)
  end

  test "the email key is normalized so case cannot split the counter" do
    with_limits(account: 2) do
      AuthThrottle.record_failure(ip: "192.0.2.1", email: EMAIL.upcase)
      AuthThrottle.record_failure(ip: "192.0.2.2", email: " #{EMAIL} ")
      assert AuthThrottle.check(ip: "192.0.2.3", email: EMAIL), "case variants must share one counter"
    end
  end

  test "a missing ip still counts the account scope" do
    with_limits(account: 2) do
      2.times { AuthThrottle.record_failure(ip: nil, email: EMAIL) }
      assert AuthThrottle.check(ip: nil, email: EMAIL)
      assert_nil AuthThrottle.find_by(scope: "ip")
    end
  end

  test "prune drops lapsed rows and keeps live ones" do
    # The block outlives the window, so at t=1000 the row is stale by window
    # but still actively blocking - exactly the row prune must not drop.
    with_limits(window: 900, account: 2, account_block: 1200) do
      AuthThrottle.record_failure(ip: "192.0.2.50", email: "old@example.test")
      fail_account(2, email: EMAIL) # blocked until t=1200

      # Well past the window, but the block on EMAIL is still live.
      AuthThrottle.prune!(now: 1000.seconds.from_now)
      assert_nil AuthThrottle.find_by(key: "old@example.test")
      assert AuthThrottle.find_by(scope: "account", key: EMAIL), "a live block must survive pruning"

      # Once the block lapses too, it goes.
      AuthThrottle.prune!(now: 2000.seconds.from_now)
      assert_nil AuthThrottle.find_by(scope: "account", key: EMAIL)
    end
  end

  test "concurrent failures against one key are all counted" do
    with_limits(ip: 100, account: 100) do
      threads = 5.times.map do
        Thread.new { AuthThrottle.record_failure(ip: IP, email: EMAIL) }
      end
      threads.each(&:join)
      assert_equal 5, AuthThrottle.find_by(scope: "ip", key: IP).failure_count
    end
  end
end
