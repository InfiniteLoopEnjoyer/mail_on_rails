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

  # A reply sent from the message page carries the id of its autosaved
  # revision so the draft doesn't linger on every device after sending.
  test "sending discards the draft revision it was composed from" do
    drafts = @account.find_mailbox("Drafts")
    draft = EmailDraft.new(email_account_id: @account.id, to: "someone@remote.example",
                           subject: "Hi", body: "Hello")
    saved = draft.save
    assert_equal 1, drafts.email_messages.count

    post emails_url, params: { composed_email: {
      email_account_id: @account.id, to: "someone@remote.example", subject: "Hi",
      body: "Hello", draft_message_id: saved.id
    } }

    assert_response :redirect
    assert_equal 0, drafts.email_messages.count
  end

  # A send that fails validation must not take the draft with it.
  test "a rejected send keeps the draft revision" do
    drafts = @account.find_mailbox("Drafts")
    draft = EmailDraft.new(email_account_id: @account.id, to: "someone@remote.example",
                           subject: "Hi", body: "Hello")
    saved = draft.save

    post emails_url, params: { composed_email: {
      email_account_id: @account.id, to: "not-an-address", subject: "Hi",
      body: "Hello", draft_message_id: saved.id
    } }

    assert_response :unprocessable_entity
    assert_equal 1, drafts.email_messages.count
  end

  test "an attached file is delivered as a mime part on every copy" do
    other = EmailAccount.create!(email: "dave@example.com", password: "secret123")

    post emails_url, params: { composed_email: {
      email_account_id: @account.id, to: "dave@example.com", subject: "Report", body: "attached",
      attachments: [ fixture_file_upload("hello.txt", "text/plain") ]
    } }
    assert_response :redirect

    [ other.inbox, @account.find_mailbox("Sent") ].each do |mailbox|
      mail = Mail.read_from_string(mailbox.email_messages.sole.raw)
      assert_equal "hello.txt", mail.attachments.sole.filename
      assert_equal file_fixture("hello.txt").read, mail.attachments.sole.decoded
    end
  end

  test "a rejected send with an attachment re-renders instead of crashing on EmailDraft" do
    post emails_url, params: { composed_email: {
      email_account_id: @account.id, to: "not-an-address", subject: "Hi", body: "Hello",
      attachments: [ fixture_file_upload("hello.txt", "text/plain") ]
    } }

    assert_response :unprocessable_entity
    assert_select "lexxy-editor[name='composed_email[body_html]'][value*=?]", "Hello"
  end

  test "threading headers survive the send" do
    post emails_url, params: { composed_email: {
      email_account_id: @account.id, to: "someone@remote.example", subject: "Re: Hi",
      body: "Hello", in_reply_to: "orig@remote.test", references: "orig@remote.test"
    } }

    assert_match(/^In-Reply-To: <orig@remote\.test>/, SmtpOutboundMessage.sole.data)
  end

  # -- the composer ----------------------------------------------------------

  test "new renders the shared autosaving composer" do
    get new_email_url

    assert_response :success
    assert_select "[data-controller='draft-autosave']", 1
    assert_select "select[name='composed_email[email_account_id]'][data-draft-field='email_account_id']", 1
    assert_select "lexxy-editor[name='composed_email[body_html]'][data-draft-field='body_html']", 1
  end

  test "?from preselects the sending account" do
    other = EmailAccount.create!(email: "dave@example.com", password: "secret123")

    get new_email_url(from: other.id)
    assert_select "select[name='composed_email[email_account_id]'] option[selected][value=?]", other.id.to_s
  end

  # A rejected send must come back with the text still in the box, and with
  # the id of the autosaved revision so the next save keeps replacing it
  # rather than starting a second draft.
  test "a rejected send re-renders the composer with what was typed" do
    saved = EmailDraft.new(email_account_id: @account.id, to: "someone@remote.example",
                           subject: "Hi", body: "Half written").save

    post emails_url, params: { composed_email: {
      email_account_id: @account.id, to: "not-an-address", subject: "Hi",
      body: "Half written", draft_message_id: saved.id
    } }

    assert_response :unprocessable_entity
    assert_select "lexxy-editor[name='composed_email[body_html]'][value*=?]", "Half written"
    assert_select "input[name='composed_email[draft_message_id]'][value=?]", saved.id.to_s
    assert_select "input[name='composed_email[to]'][value=?]", "not-an-address"
  end
end
