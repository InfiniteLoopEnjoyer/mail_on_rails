# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/send_quota"

# The durable send quota: SendQuotaSlot rows are the one budget every
# process draws on, and SendQuota picks them over its in-memory table
# whenever the database is there. The db suite runs on file-backed SQLite
# (or the CI matrix's PG/MySQL), so the row lock is exercised for real.
class SendQuotaSlotTest < DbSuite::TestCase
  Slot = MailOnRails::SendQuotaSlot

  def setup
    super
    @t0 = Time.zone.at(1_800_000_000) # a bucket boundary
  end

  def consume(account = "alice@example.test", limit: 3, window: 3600, now: @t0)
    Slot.consume(account, limit: limit, window: window, now: now)
  end

  test "consumes up to the limit, then refuses without writing" do
    3.times { assert consume }
    refute consume
    refute consume
    assert_equal 3, Slot.used("alice@example.test", window: 3600, now: @t0)
    assert_equal 1, Slot.count, "one bucket row for one minute"
  end

  test "accounts are independent and keys are normalized" do
    assert consume("Alice@Example.test", limit: 1)
    refute consume("alice@example.test", limit: 1)
    assert consume("bob@example.test", limit: 1)
  end

  test "budget returns as the window slides, in bucket steps" do
    assert consume(limit: 2, window: 600)
    assert consume(limit: 2, window: 600, now: @t0 + 300)
    refute consume(limit: 2, window: 600, now: @t0 + 300)
    # The first slot's bucket [t0, t0+60) leaves the window once now - window passes t0+60.
    refute consume(limit: 2, window: 600, now: @t0 + 650), "a bucket straddling the window edge still counts"
    assert consume(limit: 2, window: 600, now: @t0 + 661)
  end

  test "old buckets are pruned on write, and prune! sweeps every account" do
    consume(now: @t0)
    consume("bob@example.test", now: @t0)
    consume(now: @t0 + 7200)
    assert_equal [ @t0 + 7200 ], Slot.where(account_key: "alice@example.test").pluck(:window_start),
                 "alice's stale bucket goes on her next consume"
    assert_equal 1, Slot.where(account_key: "bob@example.test").count

    Slot.prune!(window: 3600, now: @t0 + 7200)
    assert_equal 0, Slot.where(account_key: "bob@example.test").count
    assert_equal 1, Slot.count
  end

  test "concurrent consumers cannot overspend the budget" do
    barrier = Queue.new
    results = Queue.new
    threads = 8.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          barrier.pop
          results << Slot.consume("alice@example.test", limit: 5, window: 3600)
        end
      end
    end
    threads.size.times { barrier << true }
    threads.each(&:join)

    outcomes = Array.new(threads.size) { results.pop }
    assert_equal 5, outcomes.count(true), "exactly limit slots may be won (got #{outcomes.inspect})"
    assert_equal 5, Slot.used("alice@example.test", window: 3600)
  end

  test "SendQuota uses the rows once the database is reachable, sharing the budget across instances" do
    smtp_listener = MailOnRails::SendQuota.new(limit: 2, window: 3600)
    web_process = MailOnRails::SendQuota.new(limit: 2, window: 3600)

    assert_equal :durable, smtp_listener.backing
    assert smtp_listener.consume("alice@example.test")
    assert web_process.consume("alice@example.test")
    refute smtp_listener.consume("alice@example.test"), "the other process's slot must count here"
    refute web_process.consume("alice@example.test")
    assert web_process.consume("bob@example.test")
  end

  test "SendQuota.shared reads the limit from settings and is durable" do
    MailOnRails::Settings.overrides = { smtp_send_quota: 1 }
    begin
      quota = MailOnRails::SendQuota.shared
      assert_equal :durable, quota.backing
      assert quota.consume("carol@example.test")
      refute quota.consume("carol@example.test")
    ensure
      MailOnRails::Settings.reset!
    end
  end

  test "an explicit durable: false stays in memory" do
    quota = MailOnRails::SendQuota.new(limit: 1, window: 60, durable: false)
    assert_equal :memory, quota.backing
    assert quota.consume("alice@example.test")
    assert_equal 0, Slot.count
  end
end
