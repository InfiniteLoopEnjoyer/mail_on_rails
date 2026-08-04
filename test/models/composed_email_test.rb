require "test_helper"
require "mail_on_rails/clamav_scanner"
require_relative "../test_helpers/clamav_stub_helper"

# The web composer delivers local mail itself - no exim edge, no mailroom -
# so it carries the clamav gate for that path: a clean verdict marks the
# recipient's copy scanned (unlocking attachment downloads), an infected
# message is refused outright (the sender is right there, unlike the
# mailroom which has already accepted the bytes), and a down scanner
# degrades to an "unscanned" marking that keeps attachments locked.
class ComposedEmailTest < ActiveSupport::TestCase
  include ClamavStubHelper

  Result = MailOnRails::ClamavScanner::Result

  setup do
    @sender = EmailAccount.create!(email: "alice@example.com", password: "secret123")
    @recipient = EmailAccount.create!(email: "bob@example.com", password: "secret123")
  end

  def composed(to: @recipient.email)
    ComposedEmail.new(email_account_id: @sender.id, to: to, subject: "hello", body: "hi")
  end

  test "a clean verdict marks the local copy scanned" do
    with_scanner(enabled: true, scan: Result.new(:clean, nil)) do
      assert composed.deliver
    end
    assert_equal "clean", @recipient.inbox.email_messages.sole.scan_status
  end

  test "an infected message is refused and delivered nowhere" do
    email = composed(to: "#{@recipient.email}, eve@remote.test")
    with_scanner(enabled: true, scan: Result.new(:infected, "Eicar-Test-Signature")) do
      assert_not email.deliver
    end

    assert_match(/Eicar-Test-Signature/, email.errors.full_messages.to_sentence)
    assert_empty @recipient.inbox.email_messages
    assert_empty @sender.find_mailbox("Sent").email_messages
    assert_equal 0, SmtpOutboundMessage.count
  end

  test "a down scanner delivers the local copy marked unscanned" do
    with_scanner(enabled: true, scan: Result.new(:unavailable, nil)) do
      assert composed.deliver
    end
    assert_equal "unscanned", @recipient.inbox.email_messages.sole.scan_status
  end

  test "scanning disabled leaves the local copy unmarked" do
    with_scanner(enabled: false, scan: ->(_) { raise "must not scan" }) do
      assert composed.deliver
    end
    assert_nil @recipient.inbox.email_messages.sole.scan_status
  end

  # The Sent copy is the owner's own message - no misleading scan banner on
  # it; attachment downloads there rest on authorship, not on a verdict.
  test "the sender's Sent copy stays unmarked" do
    with_scanner(enabled: true, scan: Result.new(:clean, nil)) do
      assert composed.deliver
    end
    assert_nil @sender.find_mailbox("Sent").email_messages.sole.scan_status
  end
end
