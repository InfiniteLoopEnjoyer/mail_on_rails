require "test_helper"

class MailboxesControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @inbox = @account.inbox
    @sent = @account.find_mailbox("Sent")
  end

  test "folder page subscribes to live updates" do
    get email_account_mailbox_url(@account, @inbox)
    assert_response :success
    assert_select "turbo-cable-stream-source", 1
  end

  # -- mbox export -------------------------------------------------------------

  test "export streams the folder as an mbox download" do
    EmailMessage.deliver_raw(@inbox, "From: a@remote.test\r\nSubject: one\r\n\r\nfirst\r\n")
    EmailMessage.deliver_raw(@inbox, "From: b@remote.test\r\nSubject: two\r\n\r\nsecond\r\n")

    get export_email_account_mailbox_url(@account, @inbox)

    assert_response :success
    assert_equal "application/mbox", response.media_type
    assert_match(/attachment; filename="INBOX\.mbox"/, response.headers["Content-Disposition"])
    assert_equal 2, response.body.scan(/^From (?:a|b)@remote\.test /).size
    assert_includes response.body, "Subject: one\n"
    assert_includes response.body, "second\n"
  end

  # -- pagination --------------------------------------------------------------

  def deliver_messages(count)
    count.times do |i|
      EmailMessage.deliver_raw(@inbox, "Subject: msg #{i}\r\n\r\nbody #{i}\r\n")
    end
  end

  test "a folder within one page shows no pagination nav" do
    deliver_messages(3)

    get email_account_mailbox_url(@account, @inbox)

    assert_select "li a span.primary", 3
    assert_select "nav[aria-label='Pagination']", 0
  end

  test "a large folder renders one page at a time, newest first" do
    deliver_messages(MailboxesController::MESSAGES_PER_PAGE + 2)

    get email_account_mailbox_url(@account, @inbox)

    assert_select "li a span.primary", MailboxesController::MESSAGES_PER_PAGE
    assert_select "nav[aria-label='Pagination']" do
      assert_select "a", text: "Older \u2192"
      assert_select "a", text: "\u2190 Newer", count: 0
    end
    assert_match "msg #{MailboxesController::MESSAGES_PER_PAGE + 1}", response.body
    assert_no_match "msg 0", response.body
  end

  test "the last page holds the remainder and links back to newer" do
    deliver_messages(MailboxesController::MESSAGES_PER_PAGE + 2)

    get email_account_mailbox_url(@account, @inbox, page: 2)

    assert_select "li a span.primary", 2
    assert_select "nav[aria-label='Pagination']" do
      assert_select "a", text: "\u2190 Newer"
      assert_select "a", text: "Older \u2192", count: 0
    end
    assert_match "msg 0", response.body
  end

  test "an out-of-range page clamps instead of erroring" do
    deliver_messages(1)

    get email_account_mailbox_url(@account, @inbox, page: 99)
    assert_response :success
    assert_match "msg 0", response.body

    get email_account_mailbox_url(@account, @inbox, page: -1)
    assert_response :success
  end

  # -- threading ---------------------------------------------------------------

  test "a conversation collapses into one row with a count" do
    EmailMessage.deliver_raw(@inbox, "Message-Id: <root@x>\r\nSubject: hi\r\n\r\na\r\n")
    EmailMessage.deliver_raw(@inbox, "Message-Id: <r1@x>\r\nReferences: <root@x>\r\nSubject: Re: hi\r\n\r\nb\r\n")
    EmailMessage.deliver_raw(@inbox, "Message-Id: <o@x>\r\nSubject: lunch\r\n\r\nc\r\n")

    get email_account_mailbox_url(@account, @inbox)

    assert_select "li a span.primary", 2
    assert_select "li a span[title='2 messages in this conversation']", text: "2"
  end

  test "a thread with any unread message shows the unread dot on its row" do
    root = EmailMessage.deliver_raw(@inbox, "Message-Id: <root@x>\r\nSubject: hi\r\n\r\na\r\n")
    reply = EmailMessage.deliver_raw(@inbox, "Message-Id: <r1@x>\r\nReferences: <root@x>\r\nSubject: Re: hi\r\n\r\nb\r\n")
    root.mark_seen!
    reply.mark_seen!
    EmailMessage.deliver_raw(@inbox, "Message-Id: <r2@x>\r\nReferences: <root@x>\r\nSubject: Re: hi\r\n\r\nc\r\n")

    get email_account_mailbox_url(@account, @inbox)

    assert_select "li a span.primary span.bg-accent", 1
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
