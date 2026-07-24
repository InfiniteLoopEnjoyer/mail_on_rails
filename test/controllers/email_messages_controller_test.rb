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
    assert_select "footer" do
      assert_match "spf pass", response.body
      assert_match "dkim fail", response.body
      assert_match "dmarc pass", response.body
      assert_match "clean", response.body
      assert_match "2.1 / 6.0", response.body
      assert_match "no action", response.body
    end
  end

  test "omits the footer for a message with no verdicts" do
    sent = @account.find_mailbox("Sent")
    message = EmailMessage.deliver_raw(sent, RAW)
    show(message)

    assert_response :success
    assert_select "footer", 0
  end
end
