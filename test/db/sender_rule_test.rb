# frozen_string_literal: true

require_relative "test_helper"

class SenderRuleTest < DbSuite::TestCase
  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "bob@example.test",
                                                   password: "a-long-test-password")
  end

  def verdict_for(address)
    MailOnRails::SenderRule.verdict_for(account, address)
  end

  test "normalizes the address" do
    rule = MailOnRails::SenderRule.record!(account, " Spammer@Example.COM ", "deny", source: "manual")
    assert_equal "spammer@example.com", rule.address
    assert_equal :deny, verdict_for("SPAMMER@example.com")
  end

  test "an exact rule beats the domain wildcard" do
    MailOnRails::SenderRule.record!(account, "@example.com", "deny", source: "manual")
    MailOnRails::SenderRule.record!(account, "friend@example.com", "allow", source: "manual")

    assert_equal :allow, verdict_for("friend@example.com")
    assert_equal :deny, verdict_for("stranger@example.com")
    assert_nil verdict_for("anyone@elsewhere.test")
  end

  test "no verdict for blank or malformed lookups" do
    MailOnRails::SenderRule.record!(account, "@example.com", "deny", source: "manual")

    assert_nil verdict_for(nil)
    assert_nil verdict_for("")
    assert_nil verdict_for("not-an-address")
    assert_nil verdict_for("@example.com")
  end

  test "rules are scoped to their account" do
    other = MailOnRails::EmailAccount.create!(email: "carol@example.test", password: "a-long-test-password")
    MailOnRails::SenderRule.record!(other, "spammer@example.com", "deny", source: "manual")

    assert_nil verdict_for("spammer@example.com")
  end

  test "a repeat flips the verdict and source in place" do
    first = MailOnRails::SenderRule.record!(account, "spammer@example.com", "deny", source: "imap")
    again = MailOnRails::SenderRule.record!(account, "spammer@example.com", "allow", source: "web")

    assert_equal first.id, again.id
    assert_equal 1, MailOnRails::SenderRule.count
    assert_equal "allow", again.reload.verdict
    assert_equal "web", again.source
  end

  test "rejects addresses that are not an address or a domain wildcard" do
    [ "bob", "bob@", "@", "a@b", "bob@example.com\r\nX: y", "Bob <bob@example.com>" ].each do |bad|
      assert_raises(ActiveRecord::RecordInvalid, bad.inspect) do
        MailOnRails::SenderRule.record!(account, bad, "deny", source: "manual")
      end
    end
    assert_raises(ActiveRecord::RecordInvalid) do
      MailOnRails::SenderRule.record!(account, "bob@example.com", "maybe", source: "manual")
    end
  end

  test "deleting the account removes its rules" do
    MailOnRails::SenderRule.record!(account, "spammer@example.com", "deny", source: "manual")
    account.destroy!
    assert_equal 0, MailOnRails::SenderRule.count
  end

  test "concurrent upserts of one address end with one row" do
    account_id = account.id
    barrier = Queue.new
    threads = 4.times.map do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          barrier.pop
          MailOnRails::SenderRule.record!(MailOnRails::EmailAccount.find(account_id),
                                          "burst@example.org", "deny", source: "imap")
        end
      end
    end
    threads.size.times { barrier << true }
    threads.each(&:join)
    assert_equal 1, MailOnRails::SenderRule.where(address: "burst@example.org").count
  end
end
