# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/netserv/account_limiter"

class AccountLimiterTest < Minitest::Test
  Limiter = MailOnRails::Netserv::AccountLimiter

  test "caps sessions per account and frees on release" do
    limiter = Limiter.new(2)

    assert limiter.acquire("a@example.test")
    assert limiter.acquire("a@example.test")
    refute limiter.acquire("a@example.test"), "third session for one account must be refused"
    assert limiter.acquire("b@example.test"), "other accounts are unaffected"
    limiter.release("a@example.test")
    assert limiter.acquire("a@example.test")
  end

  test "nil or zero limit disables the cap but keeps counting" do
    limiter = Limiter.new(0)

    5.times { assert limiter.acquire("a@example.test") }
    assert_equal 5, limiter.count("a@example.test")
  end

  test "callable limit is resolved per check" do
    max = 1
    limiter = Limiter.new(-> { max })

    assert limiter.acquire("a@example.test")
    refute limiter.acquire("a@example.test")
    max = 2
    assert limiter.acquire("a@example.test"), "a raised limit applies to the next login"
  end

  test "release of an unknown key is a no-op and the table does not grow" do
    limiter = Limiter.new(1)
    limiter.release("nobody@example.test")
    assert limiter.acquire("a@example.test")
    limiter.release("a@example.test")
    assert_equal 0, limiter.count("a@example.test")
  end

  test "nil key is never limited" do
    limiter = Limiter.new(1)
    3.times { assert limiter.acquire(nil) }
  end
end
