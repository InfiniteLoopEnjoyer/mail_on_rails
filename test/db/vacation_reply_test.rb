# frozen_string_literal: true

require_relative "test_helper"

class VacationReplyTest < DbSuite::TestCase
  WINDOW = 1.hour

  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "bob@example.test",
                                                   password: "a-long-test-password")
  end

  test "claims a sender once per window" do
    assert MailOnRails::VacationReply.claim(account, "sender@example.org", window: WINDOW)
    assert_not MailOnRails::VacationReply.claim(account, "sender@example.org", window: WINDOW)
    assert MailOnRails::VacationReply.replied_recently?(account, "sender@example.org", window: WINDOW)
  end

  test "an expired window can be claimed again" do
    assert MailOnRails::VacationReply.claim(account, "sender@example.org", window: WINDOW)
    MailOnRails::VacationReply.update_all(last_sent_at: 2.hours.ago)
    assert MailOnRails::VacationReply.claim(account, "sender@example.org", window: WINDOW)
  end

  test "different senders claim independently" do
    assert MailOnRails::VacationReply.claim(account, "one@example.org", window: WINDOW)
    assert MailOnRails::VacationReply.claim(account, "two@example.org", window: WINDOW)
  end

  # The concurrency contract the old ON CONFLICT upsert provided and the
  # portable rewrite must keep: of N simultaneous deliveries from one
  # sender, exactly one wins the right to auto-reply.
  test "exactly one concurrent claimant wins" do
    account_id = account.id
    barrier = Queue.new
    results = Array.new(4)
    threads = results.each_index.map do |i|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          barrier.pop
          results[i] = MailOnRails::VacationReply.claim(
            MailOnRails::EmailAccount.find(account_id), "burst@example.org", window: WINDOW
          )
        end
      end
    end
    results.size.times { barrier << true }
    threads.each(&:join)
    assert_equal 1, results.count(true), "results: #{results.inspect}"
  end
end
