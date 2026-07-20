require "test_helper"

class MailboxesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @inbox = @account.inbox
    @sent = @account.find_mailbox("Sent")
  end

  test "creates a folder" do
    assert_difference "@account.mailboxes.count", 1 do
      post email_account_mailboxes_url(@account), params: { mailbox: { name: "Archive" } }
    end
    assert_redirected_to email_account_url(@account)
  end

  test "rejects a duplicate folder name" do
    assert_no_difference "Mailbox.count" do
      post email_account_mailboxes_url(@account), params: { mailbox: { name: "Sent" } }
    end
    assert_response :unprocessable_entity
  end

  test "renames a folder" do
    patch email_account_mailbox_url(@account, @sent), params: { mailbox: { name: "Outbox" } }
    assert_redirected_to email_account_mailbox_url(@account, @sent)
    assert_equal "Outbox", @sent.reload.name
  end

  test "refuses to rename INBOX" do
    patch email_account_mailbox_url(@account, @inbox), params: { mailbox: { name: "Inbox2" } }
    assert_response :unprocessable_entity
    assert_equal "INBOX", @inbox.reload.name
  end

  test "destroys a folder" do
    assert_difference "Mailbox.count", -1 do
      delete email_account_mailbox_url(@account, @sent)
    end
    assert_redirected_to email_account_url(@account)
  end

  test "refuses to destroy INBOX" do
    assert_no_difference "Mailbox.count" do
      delete email_account_mailbox_url(@account, @inbox)
    end
    assert_redirected_to email_account_mailbox_url(@account, @inbox)
    assert flash[:alert].present?
  end
end
