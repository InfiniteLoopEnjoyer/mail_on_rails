require "test_helper"
require "mail_on_rails/store"
require_relative "../../../test_helpers/clamav_stub_helper"

# Virus policy on the IMAP APPEND path (the one write path with no SMTP
# daemon in front): infected uploads are refused with the :infected
# envelope, a scanner outage stores in place flagged "unscanned" (an
# authenticated user's own Sent/Drafts must not vanish into Quarantine),
# copies carry their verdict without a rescan, and Quarantine stays out of
# LIST.
class ImapBackendScanTest < ActiveSupport::TestCase
  include ClamavStubHelper

  RAW = "Message-ID: <up-1@local.test>\r\nFrom: me@example.test\r\nSubject: up\r\n\r\nbody\r\n"

  setup do
    @account = EmailAccount.create!(email: "user@example.test", password: "pw-123456")
    @store = MailOnRails::Store::ImapBackend.new
  end

  def stub_scan(result, &block)
    with_scanner(enabled: true, scan: result, &block)
  end

  test "append refuses an infected upload with the :infected envelope" do
    result = stub_scan(MailOnRails::ClamavScanner::Result.new(:infected, "Eicar-Test-Signature")) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end

    assert_equal :infected, result[:code]
    assert_includes result[:error], "Eicar-Test-Signature"
    assert_empty @account.inbox.email_messages, "an infected upload must not be stored"
  end

  test "append stores clean uploads stamped clean" do
    result = stub_scan(MailOnRails::ClamavScanner::Result.new(:clean, nil)) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end

    assert result[:uid], "expected a successful append, got #{result.inspect}"
    assert_equal "clean", @account.inbox.email_messages.sole.scan_status
  end

  test "append stores in place flagged unscanned when the scanner is down" do
    result = stub_scan(MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end

    assert result[:uid], "expected a successful append, got #{result.inspect}"
    assert_equal "unscanned", @account.inbox.email_messages.sole.scan_status
  end

  test "append skips scanning entirely when no scanner is configured" do
    result = @store.append(@account.id, "INBOX", RAW, [], nil)

    assert result[:uid]
    assert_nil @account.inbox.email_messages.sole.scan_status
  end

  test "copy carries the verdict without invoking the scanner" do
    stub_scan(MailOnRails::ClamavScanner::Result.new(:unavailable, nil)) do
      @store.append(@account.id, "INBOX", RAW, [], nil)
    end
    uid = @account.inbox.email_messages.sole.uid

    with_scanner(enabled: true, scan: ->(*) { raise "copy must not rescan stored bytes" }) do
      @store.copy(@account.inbox.id, [ uid ], "Trash")
    end

    copied = @account.find_mailbox("Trash").email_messages.sole
    assert_equal "unscanned", copied.scan_status
  end

  test "list_mailboxes hides Quarantine" do
    @account.quarantine_mailbox # ensure it exists

    names = @store.list_mailboxes(@account.id)[:mailboxes]
    refute_includes names, Mailbox::QUARANTINE
    assert_includes names, "INBOX"
  end
end
