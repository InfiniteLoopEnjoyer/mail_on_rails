# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/send_quota"

class SendQuotaTest < Minitest::Test
  def quota(limit: 3, window: 60)
    @now = 0.0
    MailOnRails::Smtp::SendQuota.new(limit: limit, window: window, clock: -> { @now })
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
end
