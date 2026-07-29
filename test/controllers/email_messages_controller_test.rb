require "test_helper"

# The received-message view renders an analysis footer (SPF/DKIM/DMARC, the
# virus result, and the rspamd spam score) for mail that went through the
# inbound pipeline, and omits it for messages with no verdicts (e.g. Sent
# copies).
class EmailMessagesControllerTest < ActionDispatch::IntegrationTest
  RAW = "From: sender@remote.test\r\nTo: carol@example.com\r\n" \
        "Subject: hello\r\nMessage-ID: <m1@remote.test>\r\n\r\nbody\r\n"

  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
  end

  def show(message)
    get email_account_mailbox_email_message_url(@account, message.mailbox, message)
  end

  test "renders the analysis footer for an analyzed inbound message" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       auth_results: "mail.test; spf=pass; dkim=fail; dmarc=pass",
                                       scan_status: "clean", spam_score: 2.1, spam_threshold: 6.0,
                                       spam_action: "no action")
    show(message)

    assert_response :success
    assert_select "footer", 1
    footer = css_select("footer").text

    assert_match "spf pass", footer
    assert_match "dkim fail", footer
    assert_match "dmarc pass", footer
    assert_match "✓ No virus", footer
    assert_match "Spam score: 2.1 / 6.0 — no action", footer
  end

  # The scan-status badge is the one part of the footer with a branch per
  # outcome, and its wording is not derived from anything - assert the
  # strings so a template edit can't quietly change what a reader is told
  # about a message's safety.
  def footer_for(scan_status:, virus_name: nil)
    message = EmailMessage.deliver_raw(@account.inbox, RAW,
                                       auth_results: "mail.test; spf=pass",
                                       scan_status: scan_status, virus_name: virus_name)
    show(message)
    assert_response :success
    css_select("footer").text
  end

  test "an infected message names the virus" do
    assert_match "☣ Eicar-Test-Signature", footer_for(scan_status: "infected",
                                                      virus_name: "Eicar-Test-Signature")
  end

  test "a message that arrived while the scanner was down is marked unscanned" do
    assert_match "⚠ Unscanned", footer_for(scan_status: "unscanned")
  end

  test "a message with no scan status is marked not scanned" do
    assert_match "⚠ Not scanned", footer_for(scan_status: nil)
  end

  test "viewing a message marks it as seen" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)
    assert_not message.seen?

    show(message)
    assert_response :success
    assert message.reload.seen?
    assert_select "[data-controller=mark-read]", 0

    show(message)
    assert_response :success
    assert_equal [ "\\Seen" ], message.reload.flags
  end

  test "a hover-prefetch does not mark the message seen" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)

    get email_account_mailbox_email_message_url(@account, message.mailbox, message),
        headers: { "X-Sec-Purpose" => "prefetch" }
    assert_response :success
    assert_not message.reload.seen?
    assert_select "[data-controller=mark-read]", 1
  end

  test "mark_read marks the message seen" do
    message = EmailMessage.deliver_raw(@account.inbox, RAW)

    post mark_read_email_account_mailbox_email_message_url(@account, message.mailbox, message)
    assert_response :no_content
    assert message.reload.seen?
  end

  test "omits the footer for a message with no verdicts" do
    sent = @account.find_mailbox("Sent")
    message = EmailMessage.deliver_raw(sent, RAW)
    show(message)

    assert_response :success
    assert_select "footer", 0
  end
end
