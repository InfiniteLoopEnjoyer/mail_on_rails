# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/send_quota"

class SendQuotaTest < Minitest::Test
  def quota(limit: 3, window: 60)
    @now = 0.0
    MailOnRails::SendQuota.new(limit: limit, window: window, clock: -> { @now })
  end

  def test_consumes_up_to_the_limit_then_refuses
    q = quota(limit: 3)
    assert q.consume("a@example.test")
    assert q.consume("a@example.test")
    assert q.consume("a@example.test")
    refute q.consume("a@example.test")
  end

  def test_accounts_are_independent
    q = quota(limit: 1)
    assert q.consume("a@example.test")
    refute q.consume("a@example.test")
    assert q.consume("b@example.test"), "one account's exhaustion must not touch another's budget"
  end

  def test_budget_returns_as_the_window_slides
    q = quota(limit: 2, window: 60)
    assert q.consume("a@example.test")
    @now = 30.0
    assert q.consume("a@example.test")
    refute q.consume("a@example.test")
    @now = 61.0 # first slot aged out, second still live
    assert q.consume("a@example.test")
    refute q.consume("a@example.test")
  end

  def test_refused_attempts_do_not_consume
    q = quota(limit: 1, window: 60)
    assert q.consume("a@example.test")
    10.times { refute q.consume("a@example.test") }
    @now = 61.0 # only the one consumed slot had to age out
    assert q.consume("a@example.test")
  end

  def test_nil_limit_disables
    q = quota(limit: nil)
    100.times { assert q.consume("a@example.test") }
  end

  def test_nil_account_is_never_limited
    q = quota(limit: 1)
    3.times { assert q.consume(nil) }
  end

  def test_without_active_record_the_quota_is_in_memory
    refute defined?(::ActiveRecord::Base), "this suite is Rails-free by design"
    assert_equal :memory, quota.backing
    assert_equal :memory, MailOnRails::SendQuota.new(limit: 1, window: 60, durable: false).backing
  end

  def test_an_injected_durable_store_is_used_and_told_the_resolved_limit_and_window
    calls = []
    store = Object.new
    store.define_singleton_method(:consume) { |account, limit:, window:| calls << [ account, limit, window ]; false }
    q = MailOnRails::SendQuota.new(limit: -> { 7 }, window: -> { 120 }, durable: store)

    assert_equal :durable, q.backing
    refute q.consume("a@example.test")
    assert_equal [ [ "a@example.test", 7, 120.0 ] ], calls
    assert q.consume(nil), "a nil account never reaches the store"
    assert_equal 1, calls.size
  end
end
