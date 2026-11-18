# frozen_string_literal: true

require_relative "test_helper"

class AuthThrottleTest < DbSuite::TestCase
  def setup
    super
    ENV["MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES"] = "3"
    ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"] = "2"
  end

  def teardown
    ENV.delete("MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES")
    ENV.delete("MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES")
  end

  test "blocks both scopes past their budgets and clears the account on success" do
    5.times do
      MailOnRails::AuthThrottle.record_failure(ip: "203.0.113.9", email: "bob@example.test")
    end

    assert_equal "ip", MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil)[:scope]
    assert_equal "account", MailOnRails::AuthThrottle.check(ip: nil, email: "bob@example.test")[:scope]

    MailOnRails::AuthThrottle.clear_account("bob@example.test")
    assert_nil MailOnRails::AuthThrottle.check(ip: nil, email: "bob@example.test")
    assert MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil), "the ip block must survive"
  end

  test "block_ip! applies a temporary block directly, without counted failures" do
    MailOnRails::AuthThrottle.block_ip!("203.0.113.9", seconds: 600)

    result = MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil)
    assert_equal "ip", result[:scope]
    assert_operator result[:retry_after], :<=, 600
  end

  test "block_ip! never shortens a longer live block" do
    MailOnRails::AuthThrottle.block_ip!("203.0.113.9", seconds: 3600)
    MailOnRails::AuthThrottle.block_ip!("203.0.113.9", seconds: 60)

    assert_operator MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil)[:retry_after], :>, 600
  end

  test "ipv6 failures are counted per /64, so a fresh /128 buys nothing" do
    MailOnRails::AuthThrottle.record_failure(ip: "2001:db8:1:2::1", email: nil)
    MailOnRails::AuthThrottle.record_failure(ip: "2001:db8:1:2::2", email: nil)
    MailOnRails::AuthThrottle.record_failure(ip: "2001:db8:1:2:dead:beef::3", email: nil)

    assert_equal "ip", MailOnRails::AuthThrottle.check(ip: "2001:db8:1:2::4444", email: nil)[:scope],
                 "an address never seen, inside the locked /64, is blocked"
    assert_nil MailOnRails::AuthThrottle.check(ip: "2001:db8:1:3::1", email: nil), "the next /64 is untouched"
    assert_equal [ "2001:db8:1:2::/64" ], MailOnRails::AuthThrottle.where(scope: "ip").pluck(:key)
  end

  test "block_ip! on an ipv6 address blocks its /64" do
    MailOnRails::AuthThrottle.block_ip!("2001:db8:1:2::7", seconds: 600)

    assert MailOnRails::AuthThrottle.check(ip: "2001:db8:1:2::8", email: nil)
    assert_equal "2001:db8:1:2::/64", MailOnRails::AuthThrottle.find_by!(scope: "ip").key
  end

  test "ipv4 keys are the plain address, v4-mapped spelling included" do
    MailOnRails::AuthThrottle.block_ip!("::ffff:203.0.113.9", seconds: 600)

    assert MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil)
    assert_equal "203.0.113.9", MailOnRails::AuthThrottle.find_by!(scope: "ip").key
  end

  test "block_ip! ignores a blank ip or non-positive duration" do
    MailOnRails::AuthThrottle.block_ip!("", seconds: 600)
    MailOnRails::AuthThrottle.block_ip!("203.0.113.9", seconds: 0)

    assert_equal 0, MailOnRails::AuthThrottle.count
  end

  test "concurrent failure bumps never lose counts" do
    # Keep the budget out of reach - a row that blocks mid-test stops
    # counting by design, which would mask a lost update.
    ENV["MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES"] = "100"
    barrier = Queue.new
    threads = 4.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          barrier.pop
          MailOnRails::AuthThrottle.record_failure(ip: "203.0.113.77", email: nil)
        end
      end
    end
    threads.size.times { barrier << true }
    threads.each(&:join)

    row = MailOnRails::AuthThrottle.find_by!(scope: "ip", key: "203.0.113.77")
    assert_equal 4, row.failure_count
  end

  # -- reserve / refund (the mail stores' check-and-count) ------------------

  test "reserve counts one failure in each scope, or refuses and counts nothing" do
    blocked, holds = MailOnRails::AuthThrottle.reserve(ip: "203.0.113.9", email: "Bob@Example.test ")
    assert_nil blocked
    assert_equal %w[ip account], holds.map(&:first)
    assert_equal 1, MailOnRails::AuthThrottle.ip_failures("203.0.113.9")
    assert_equal 1, MailOnRails::AuthThrottle.find_by!(scope: "account", key: "bob@example.test").failure_count

    MailOnRails::AuthThrottle.reserve(ip: "203.0.113.10", email: "bob@example.test") # the account's second: blocks it
    blocked, holds = MailOnRails::AuthThrottle.reserve(ip: "203.0.113.11", email: "bob@example.test")
    assert_equal "account", blocked[:scope]
    assert_operator blocked[:retry_after], :>, 0
    assert_nil holds
    assert_equal 0, MailOnRails::AuthThrottle.ip_failures("203.0.113.11"), "a refused attempt is not counted"
  end

  test "refund gives back exactly its own count and lifts only the block it tripped" do
    MailOnRails::AuthThrottle.record_failure(ip: "203.0.113.9", email: nil)
    MailOnRails::AuthThrottle.record_failure(ip: "203.0.113.9", email: nil)
    _, holds = MailOnRails::AuthThrottle.reserve(ip: "203.0.113.9", email: nil) # the third: trips the ip block
    assert MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil)

    MailOnRails::AuthThrottle.refund(holds)
    assert_nil MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil)
    assert_equal 2, MailOnRails::AuthThrottle.ip_failures("203.0.113.9")

    MailOnRails::AuthThrottle.refund(holds)
    assert_equal 1, MailOnRails::AuthThrottle.ip_failures("203.0.113.9"), "refund is per call; callers refund once"
  end

  test "refund leaves a block someone else applied, and a window that has moved on" do
    _, holds = MailOnRails::AuthThrottle.reserve(ip: "203.0.113.9", email: nil)
    MailOnRails::AuthThrottle.block_ip!("203.0.113.9", seconds: 3600) # a honeypot hit, meanwhile
    MailOnRails::AuthThrottle.refund(holds)
    assert MailOnRails::AuthThrottle.check(ip: "203.0.113.9", email: nil), "a deliberate block is not a counted failure"

    now = Time.current
    _, old = MailOnRails::AuthThrottle.reserve(ip: "203.0.113.20", email: nil, now: now - 2.hours)
    MailOnRails::AuthThrottle.record_failure(ip: "203.0.113.20", email: nil, now: now) # a fresh window: someone's failure
    MailOnRails::AuthThrottle.refund(old)
    assert_equal 1, MailOnRails::AuthThrottle.ip_failures("203.0.113.20", now: now), "not ours to give back"

    MailOnRails::AuthThrottle.where(scope: "ip", key: "203.0.113.20").delete_all
    assert_nil MailOnRails::AuthThrottle.refund(old), "a pruned row is nothing to refund"
    assert_nil MailOnRails::AuthThrottle.refund(nil)
  end

  test "concurrent reservations never admit more than the budget" do
    ENV["MAIL_ON_RAILS_AUTH_MAX_ACCOUNT_FAILURES"] = "3"
    ENV["MAIL_ON_RAILS_AUTH_MAX_IP_FAILURES"] = "100"
    barrier = Queue.new
    admitted = Queue.new
    threads = 8.times.map do |i|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          barrier.pop
          blocked, = MailOnRails::AuthThrottle.reserve(ip: "203.0.113.#{i + 1}", email: "bob@example.test")
          admitted << i unless blocked
        end
      end
    end
    threads.size.times { barrier << true }
    threads.each(&:join)

    assert_equal 3, admitted.size
    assert_equal 3, MailOnRails::AuthThrottle.find_by!(scope: "account").failure_count
  end

  test "an account key is bounded and storable whatever the client sent" do
    key = MailOnRails::AuthThrottle.normalize("  #{'A' * 5000}@Example.test")
    assert_equal MailOnRails::AuthThrottle::MAX_KEY_LENGTH, key.length
    assert_equal "a\u00e9?b?c", MailOnRails::AuthThrottle.normalize("A\xC3\x89\xFFb\0c".b)

    MailOnRails::AuthThrottle.record_failure(ip: nil, email: "x\0y@example.test")
    assert_equal [ "x?y@example.test" ], MailOnRails::AuthThrottle.where(scope: "account").pluck(:key)
  end

  # The web login's way in to the account-scope exemption: evidence of its
  # own, since a mail login says nothing about the web credential.
  test "a caller's own evidence exempts from the account block only, lazily, and fails closed" do
    2.times { |i| MailOnRails::AuthThrottle.record_failure(ip: "203.0.113.#{i + 1}", email: "bob@example.test") }
    asked = 0
    yes = -> { asked += 1; true }

    assert_nil MailOnRails::AuthThrottle.check(ip: "198.51.100.7", email: "bob@example.test", exempt_known_source: yes)
    assert_equal "account", MailOnRails::AuthThrottle.check(ip: "198.51.100.7", email: "bob@example.test",
                                                            exempt_known_source: -> { false })[:scope]
    assert_equal "account", MailOnRails::AuthThrottle.check(ip: "198.51.100.7", email: "bob@example.test",
                                                            exempt_known_source: -> { raise "db down" })[:scope]
    assert_equal 1, asked

    assert_nil MailOnRails::AuthThrottle.check(ip: "198.51.100.7", email: "alice@example.test", exempt_known_source: yes)
    assert_equal 1, asked, "not asked when nothing is blocked"

    MailOnRails::AuthThrottle.block_ip!("198.51.100.7", seconds: 600)
    assert MailOnRails::AuthThrottle.check(ip: "198.51.100.7", email: "bob@example.test", exempt_known_source: yes)
    assert_equal 1, asked, "nor when the ip scope blocks anyway"
  end
end
