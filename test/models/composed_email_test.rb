require "test_helper"
require "mail_on_rails/clamav_scanner"
require "mail_on_rails/smtp/send_quota"
require_relative "../test_helpers/clamav_stub_helper"
require_relative "../test_helpers/rspamd_stub_helper"

# The web composer delivers local mail itself - no SMTP edge, no mailroom -
# so it carries the clamav gate for that path: a clean verdict marks the
# recipient's copy scanned (unlocking attachment downloads), an infected
# message is refused outright (the sender is right there, unlike the
# mailroom which has already accepted the bytes), and a down scanner
# degrades to an "unscanned" marking that keeps attachments locked.
#
# It also carries the authenticated-submission abuse gates the SMTP edge
# enforces: per-account send quota (one slot per recipient) and rspamd
# scoring of the built message.
class ComposedEmailTest < ActiveSupport::TestCase
  include ClamavStubHelper
  include RspamdStubHelper

  Result = MailOnRails::ClamavScanner::Result
  RspamdResult = MailOnRails::RspamdAnalyzer::Result

  setup do
    @sender = EmailAccount.create!(email: "alice@example.com", password: "secret123")
    @recipient = EmailAccount.create!(email: "bob@example.com", password: "secret123")
  end

  def composed(to: @recipient.email, **attrs)
    ComposedEmail.new(email_account_id: @sender.id, to: to, subject: "hello", body: "hi", **attrs)
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

  def quota(limit:)
    MailOnRails::Smtp::SendQuota.new(limit: limit, window: 3600)
  end

  test "an exhausted send quota refuses the message and delivers nowhere" do
    email = composed(to: "#{@recipient.email}, eve@remote.test", send_quota: quota(limit: 1))
    with_scanner(enabled: false) do
      assert_not email.deliver
    end

    assert_match(/quota exceeded/i, email.errors.full_messages.to_sentence)
    assert_empty @recipient.inbox.email_messages
    assert_empty @sender.find_mailbox("Sent").email_messages
    assert_equal 0, SmtpOutboundMessage.count
  end

  test "each recipient consumes one quota slot, shared across sends" do
    shared = quota(limit: 3)
    with_scanner(enabled: false) do
      assert composed(to: "#{@recipient.email}, eve@remote.test", send_quota: shared).deliver
      assert composed(send_quota: shared).deliver
      assert_not composed(send_quota: shared).deliver
    end
  end

  test "quota slots are keyed by the sending account" do
    shared = quota(limit: 1)
    with_scanner(enabled: false) do
      assert composed(send_quota: shared).deliver
      assert ComposedEmail.new(email_account_id: @recipient.id, to: @sender.email,
                               subject: "re", body: "yo", send_quota: shared).deliver
    end
  end

  test "a disabled quota does not gate delivery" do
    with_scanner(enabled: false) do
      assert composed(send_quota: nil).deliver
    end
  end

  # A local recipient over storage quota rolls back the whole send -
  # partial delivery (Sent copy without the recipient copy) would lie.
  test "a full recipient mailbox refuses the message and delivers nowhere" do
    @recipient.update!(quota_bytes: 1)
    email = composed(send_quota: nil)
    with_scanner(enabled: false) do
      assert_not email.deliver
    end

    assert_match(/storage quota/i, email.errors.full_messages.to_sentence)
    assert_empty @recipient.inbox.email_messages
    assert_empty @sender.find_mailbox("Sent").email_messages
  end

  test "an rspamd reject verdict refuses the message and delivers nowhere" do
    email = composed(to: "#{@recipient.email}, eve@remote.test", send_quota: nil)
    verdict = RspamdResult.new(status: :ok, action: "reject", score: 22.0, required_score: 15.0)
    with_scanner(enabled: false) do
      with_rspamd(enabled: true, analyze: verdict) do
        assert_not email.deliver
      end
    end

    assert_match(/rejected as spam/i, email.errors.full_messages.to_sentence)
    assert_empty @recipient.inbox.email_messages
    assert_empty @sender.find_mailbox("Sent").email_messages
    assert_equal 0, SmtpOutboundMessage.count
  end

  test "an rspamd soft reject defers the message" do
    email = composed(send_quota: nil)
    verdict = RspamdResult.new(status: :ok, action: "soft reject", score: 9.0, required_score: 15.0)
    with_scanner(enabled: false) do
      with_rspamd(enabled: true, analyze: verdict) do
        assert_not email.deliver
      end
    end

    assert_match(/try again later/i, email.errors.full_messages.to_sentence)
    assert_empty @recipient.inbox.email_messages
  end

  # Only rspamd's own refusal actions refuse; milder spam verdicts (add
  # header, rewrite subject) pass, as at the SMTP DATA gate.
  test "a milder rspamd spam verdict does not block delivery" do
    verdict = RspamdResult.new(status: :ok, action: "add header", score: 7.0, required_score: 15.0)
    with_scanner(enabled: false) do
      with_rspamd(enabled: true, analyze: verdict) do
        assert composed(send_quota: nil).deliver
      end
    end
    assert_equal 1, @recipient.inbox.email_messages.count
  end

  test "an unreachable rspamd fails open" do
    with_scanner(enabled: false) do
      with_rspamd(enabled: true, analyze: RspamdResult.new(status: :unavailable)) do
        assert composed(send_quota: nil).deliver
      end
    end
    assert_equal 1, @recipient.inbox.email_messages.count
  end

  test "rspamd disabled means no analysis" do
    with_scanner(enabled: false) do
      with_rspamd(enabled: false, analyze: ->(*) { raise "must not analyze" }) do
        assert composed(send_quota: nil).deliver
      end
    end
  end

  # -- attachments -------------------------------------------------------------

  def upload(filename = "hello.txt", type = "text/plain")
    Rack::Test::UploadedFile.new(file_fixture(filename), type)
  end

  test "attachments become mime parts and the body stays the text part" do
    email = composed(body: "see attached", attachments: [ upload ], send_quota: nil)
    with_scanner(enabled: false) do
      assert email.deliver
    end

    mail = Mail.read_from_string(@recipient.inbox.email_messages.sole.raw)
    assert mail.multipart?
    attachment = mail.attachments.sole
    assert_equal "hello.txt", attachment.filename
    assert_equal "text/plain", attachment.mime_type
    assert_equal file_fixture("hello.txt").read, attachment.decoded
    body_part = mail.parts.find { |part| !part.attachment? }
    assert_includes body_part.decoded, "see attached"
  end

  test "an empty file input is not an attachment" do
    email = composed(attachments: [ "" ], send_quota: nil)
    with_scanner(enabled: false) do
      assert email.deliver
    end
    assert_not Mail.read_from_string(@recipient.inbox.email_messages.sole.raw).multipart?
  end

  # The cap keeps the built message under the 30 MiB APPENDLIMIT the IMAP
  # server enforces on the same mailboxes (base64 inflates by 4/3).
  test "attachments over the total size cap refuse the send outright" do
    oversized = Struct.new(:original_filename, :content_type, :size) do
      def blank? = false
      def read = raise "an oversized upload must be refused before it is read"
    end.new("huge.bin", "application/octet-stream", ComposedEmail::MAX_ATTACHMENT_BYTES + 1)

    email = composed(attachments: [ oversized ], send_quota: nil)
    with_scanner(enabled: false) do
      assert_not email.deliver
    end

    assert_match(/attachments are too large/i, email.errors.full_messages.to_sentence)
    assert_empty @recipient.inbox.email_messages
  end

  # The clamav gate scans the built raw, attachments included - an infected
  # attachment is refused exactly like an infected body.
  test "an infected attachment is refused by the scanner gate" do
    email = composed(attachments: [ upload ], send_quota: nil)
    with_scanner(enabled: true, scan: Result.new(:infected, "Eicar-Test-Signature")) do
      assert_not email.deliver
    end

    assert_match(/Eicar-Test-Signature/, email.errors.full_messages.to_sentence)
    assert_empty @recipient.inbox.email_messages
  end

  # -- rich text ---------------------------------------------------------------

  test "a rich-text send is multipart/alternative with a derived text part" do
    email = composed(body: nil, body_html: "<p>Hello <strong>world</strong></p><p>bye</p>", send_quota: nil)
    with_scanner(enabled: false) do
      assert email.deliver
    end

    mail = Mail.read_from_string(@recipient.inbox.email_messages.sole.raw)
    assert_equal "multipart/alternative", mail.mime_type
    assert_includes mail.html_part.decoded, "<strong>world</strong>"
    assert_includes mail.text_part.decoded, "Hello world"
    assert_includes mail.text_part.decoded, "bye"
  end

  test "outbound HTML passes through the sanitizer" do
    email = composed(body_html: "<p>hi</p><script>alert(1)</script><a href=\"javascript:x\">link</a>",
                     send_quota: nil)
    with_scanner(enabled: false) do
      assert email.deliver
    end

    html = Mail.read_from_string(@recipient.inbox.email_messages.sole.raw).html_part.decoded
    assert_no_match(/script|alert/, html)
    assert_no_match(/javascript:/, html)
    assert_includes html, "<p>hi</p>"
  end

  test "a rich-text send with attachments nests the alternative inside mixed" do
    email = composed(body_html: "<p>see attached</p>", attachments: [ upload ], send_quota: nil)
    with_scanner(enabled: false) do
      assert email.deliver
    end

    mail = Mail.read_from_string(@recipient.inbox.email_messages.sole.raw)
    assert_equal "multipart/mixed", mail.mime_type
    assert_equal "hello.txt", mail.attachments.sole.filename
    assert_includes mail.html_part.decoded, "see attached"
    assert_includes mail.text_part.decoded, "see attached"
  end

  # The gates forward the account as the authenticated sender so rspamd
  # applies its authenticated-sender policy, mirroring the SMTP session.
  test "rspamd receives the sending account as the authenticated user" do
    seen = nil
    analyze = lambda do |_raw, **facts|
      seen = facts
      RspamdResult.new(status: :ok, action: "no action", score: 0.1, required_score: 15.0)
    end
    with_scanner(enabled: false) do
      with_rspamd(enabled: true, analyze: analyze) do
        assert composed(send_quota: nil).deliver
      end
    end
    assert_equal @sender.email, seen[:authenticated_as]
    assert_equal @sender.email, seen[:mail_from]
    assert_equal @recipient.email, seen[:rcpt]
  end
end
