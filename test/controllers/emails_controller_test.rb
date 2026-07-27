require "test_helper"

class EmailsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", name: "Carol", password: "secret123")
  end

  test "requires authentication" do
    sign_out
    get new_email_url
    assert_redirected_to new_session_url
  end

  test "new lists every account in the from select" do
    EmailAccount.create!(email: "dave@example.com", name: "Dave", password: "secret123")

    get new_email_url

    assert_response :success
    assert_select "select[name='composed_email[email_account_id]'] option", 2
  end

  test "delivers to a local recipient and files a Sent copy" do
    other = EmailAccount.create!(email: "dave@example.com", name: "Dave", password: "secret123")

    assert_no_difference "SmtpOutboundMessage.count" do
      post emails_url, params: { composed_email: {
        email_account_id: @account.id, to: "dave@example.com", subject: "Hi", body: "Hello Dave"
      } }
    end

    sent = @account.find_mailbox("Sent")
    assert_redirected_to email_account_mailbox_url(@account, sent)

    delivered = other.inbox.email_messages.sole
    assert_equal "Hi", delivered.subject
    assert_equal @account.email, delivered.authenticated_as
    assert_includes delivered.text_body, "Hello Dave"

    copy = sent.email_messages.sole
    assert copy.seen?
    assert_equal "Hi", copy.subject
  end

  test "delivers to an alias into its account's inbox" do
    other = EmailAccount.create!(email: "dave@example.com", name: "Dave", password: "secret123")
    other.email_aliases.create!(email: "sales@example.com")

    post emails_url, params: { composed_email: {
      email_account_id: @account.id, to: "sales@example.com", subject: "Hi", body: "Hello"
    } }

    assert_equal 1, other.inbox.email_messages.count
  end

  test "queues remote recipients for the outbound job" do
    assert_difference "SmtpOutboundMessage.count", 1 do
      post emails_url, params: { composed_email: {
        email_account_id: @account.id, to: "someone@remote.example", subject: "Hi", body: "Hello"
      } }
    end

    queued = SmtpOutboundMessage.sole
    assert_equal @account.email, queued.mail_from
    assert_equal "someone@remote.example", queued.recipient
    assert queued.pending?
    assert_match "Subject: Hi", queued.data

    assert_equal 1, @account.find_mailbox("Sent").email_messages.count
  end

  test "rejects an invalid recipient address without sending anything" do
    assert_no_difference [ "SmtpOutboundMessage.count", "EmailMessage.count" ] do
      post emails_url, params: { composed_email: {
        email_account_id: @account.id, to: "not-an-address", subject: "Hi", body: "Hello"
      } }
    end
    assert_response :unprocessable_entity
  end
end
