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
end
