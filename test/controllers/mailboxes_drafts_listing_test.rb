require "test_helper"

# The Drafts folder lists unsent messages, and those have to lead into the
# composer rather than into the read view - a draft you can only read is a
# draft you cannot finish.
class MailboxesDraftsListingTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @drafts = @account.find_mailbox("Drafts")
  end

  test "a draft links to the composer and is labelled as a draft" do
    saved = EmailDraft.new(email_account_id: @account.id, to: "bob@remote.test",
                           subject: "Half written", body: "Got this far.").save

    get email_account_mailbox_url(@account, @drafts)
    assert_response :success

    assert_select "a[href=?]", edit_draft_path(saved)
    assert_select "a[href=?]", email_account_mailbox_email_message_path(@account, @drafts, saved), count: 0
    assert_match "Draft", response.body
  end

  test "ordinary mail still links to the read view" do
    message = EmailMessage.deliver_raw(@account.inbox, "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n")

    get email_account_mailbox_url(@account, @account.inbox)
    assert_select "a[href=?]", email_account_mailbox_email_message_path(@account, @account.inbox, message)
  end
end
