require "test_helper"
require "mail_on_rails/clamav_scanner"
require_relative "../test_helpers/clamav_stub_helper"

# The catch-up path for authenticated writes that clamd was down for
# (scan_status "unscanned" via IMAP APPEND, web import or composer
# copies): once clamav is back, every such row gets a real verdict,
# recorded in place - never re-filed, these rows live where their owner
# put them. A scanner that is still down leaves everything pending; the
# owner's own authored copies are swept like anything else (the
# rescannable? exclusion is button policy, not scanning policy).
class RescanUnscannedMessagesJobTest < ActiveSupport::TestCase
  include ClamavStubHelper

  CLEAN = MailOnRails::ClamavScanner::Result.new(:clean, nil)
  INFECTED = MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test")
  UNAVAILABLE = MailOnRails::ClamavScanner::Result.new(:unavailable, nil)

  RAW = <<~MAIL.freeze
    From: sender@example.test\r
    To: user@example.test\r
    Subject: pending scan\r
    Message-ID: <pending@example.test>\r
    \r
    body\r
  MAIL

  setup do
    Domain.create!(name: "example.test")
    @account = EmailAccount.create!(email: "user@example.test", password: "pw-123456")
    @message = EmailMessage.deliver_raw(@account.inbox, RAW, scan_status: "unscanned")
  end

  test "a clean verdict is recorded in place" do
    with_scanner(enabled: true, scan: CLEAN) { RescanUnscannedMessagesJob.perform_now }

    @message.reload
    assert_equal "clean", @message.scan_status
    assert_nil @message.virus_name
    assert_equal @account.inbox, @message.mailbox, "verdicts are recorded in place, never re-filed"
  end

  test "an infected verdict is recorded in place, not re-filed" do
    with_scanner(enabled: true, scan: INFECTED) { RescanUnscannedMessagesJob.perform_now }

    @message.reload
    assert_equal "infected", @message.scan_status
    assert_equal "Eicar-Test", @message.virus_name
    assert_equal @account.inbox, @message.mailbox
  end

  test "an unavailable scanner leaves the batch pending and stops scanning" do
    second = EmailMessage.deliver_raw(@account.inbox, RAW, scan_status: "unscanned")

    calls = 0
    with_scanner(enabled: true, scan: ->(_raw) { calls += 1; UNAVAILABLE }) do
      RescanUnscannedMessagesJob.perform_now
    end

    assert_equal 1, calls, "a down scanner must stop the batch, not be retried per row"
    assert_equal "unscanned", @message.reload.scan_status
    assert_equal "unscanned", second.reload.scan_status
  end

  test "a disabled scanner is a no-op" do
    calls = 0
    with_scanner(enabled: false, scan: ->(_raw) { calls += 1; CLEAN }) do
      RescanUnscannedMessagesJob.perform_now
    end

    assert_equal 0, calls
    assert_equal "unscanned", @message.reload.scan_status
  end

  test "the owner's own authored copies are swept too" do
    sent = @account.find_mailbox("Sent") || @account.mailboxes.create!(name: "Sent")
    authored = EmailMessage.deliver_raw(sent, RAW, authenticated_as: @account.email,
                                              scan_status: "unscanned")
    assert_not authored.rescannable?, "the manual button excludes authored copies - the sweep must not"

    with_scanner(enabled: true, scan: CLEAN) { RescanUnscannedMessagesJob.perform_now }

    assert_equal "clean", authored.reload.scan_status
  end

  test "already-scanned rows are untouched" do
    @message.update!(scan_status: "clean")

    calls = 0
    with_scanner(enabled: true, scan: ->(_raw) { calls += 1; CLEAN }) do
      RescanUnscannedMessagesJob.perform_now
    end

    assert_equal 0, calls
  end
end
