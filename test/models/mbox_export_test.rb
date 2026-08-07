require "test_helper"

# mbox serialization (RFC 4155, mboxrd dialect): "From " separators,
# reversible >From quoting, and Unix line endings - the format every
# other mail client can import.
class MboxExportTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "export@example.com", password: "secret123")
    @inbox = @account.inbox
  end

  def deliver(subject: "hi", body: "body", from: "sender@remote.test")
    raw = "From: #{from}\r\nSubject: #{subject}\r\n\r\n#{body}\r\n"
    EmailMessage.deliver_raw(@inbox, raw)
  end

  def export
    MboxExport.new(@inbox).to_a.join
  end

  test "each message gets a From separator with sender and asctime date" do
    message = deliver
    stamp = message.internal_date.utc.strftime("%a %b %e %H:%M:%S %Y")

    assert_includes export, "From sender@remote.test #{stamp}\n"
  end

  test "line endings become bare LF and messages are separated by a blank line" do
    deliver(subject: "first")
    deliver(subject: "second")

    text = export
    assert_not_includes text, "\r"
    assert_includes text, "Subject: first\n"
    assert_includes text, "\n\nFrom sender@remote.test", "a blank line must close each message"
  end

  test "body lines that could read as separators get mboxrd quoting" do
    deliver(body: "From the desk of X\n>From before\nnot From here")

    text = export
    assert_includes text, "\n>From the desk of X\n"
    assert_includes text, "\n>>From before\n"
    assert_includes text, "\nnot From here\n"
  end

  test "a sender that would break the separator line falls back to MAILER-DAEMON" do
    deliver(from: "")

    assert_match(/^From MAILER-DAEMON /, export)
  end

  test "filename is the mailbox name reduced to safe characters" do
    assert_equal "INBOX.mbox", MboxExport.new(@inbox).filename
    folder = @account.mailboxes.create!(name: "Receipts/Tax 2026")
    assert_equal "Receipts-Tax-2026.mbox", MboxExport.new(folder).filename
  end

  test "an empty mailbox exports as an empty file" do
    assert_equal "", export
  end
end
