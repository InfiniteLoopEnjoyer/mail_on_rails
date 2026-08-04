require "test_helper"

class DraftsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @drafts = @account.find_mailbox("Drafts")
  end

  def autosave(**attrs)
    post drafts_path, params: {
      draft: { email_account_id: @account.id, to: "bob@remote.test",
               subject: "Hello", body: "Draft body" }.merge(attrs)
    }, as: :json
    response.parsed_body
  end

  test "requires a signed-in user" do
    reset!
    post drafts_path, params: { draft: { email_account_id: @account.id, body: "x" } }, as: :json
    assert_response :redirect
  end

  test "autosaving files the draft and returns its id" do
    body = autosave
    assert_response :success

    assert_equal @drafts.email_messages.sole.id, body["draft_message_id"]
    assert body["message_id"].present?
  end

  # The client carries the returned id into its next save so the server can
  # expunge what it supersedes; without that the mailbox fills with
  # revisions.
  test "a second save replaces the first" do
    first = autosave
    second = autosave(body: "Revised", draft_message_id: first["draft_message_id"],
                      message_id: first["message_id"])

    assert_equal 1, @drafts.email_messages.count
    assert_not_equal first["draft_message_id"], second["draft_message_id"]
  end

  test "an empty draft is accepted but stores nothing" do
    body = autosave(to: "", subject: "", body: "")
    assert_response :success
    assert_nil body["draft_message_id"]
    assert_equal 0, @drafts.email_messages.count
  end

  test "an unknown account is a validation error" do
    post drafts_path, params: { draft: { email_account_id: -1, body: "orphan" } }, as: :json
    assert_response :unprocessable_entity
    assert response.parsed_body["errors"].any?
  end

  # A phone that saved its own revision has already expunged ours. The
  # client's id is stale through no fault of its own, so the save must
  # still succeed.
  test "saving against a superseded revision still saves" do
    first = autosave
    @drafts.email_messages.destroy_all

    body = autosave(body: "From the laptop", draft_message_id: first["draft_message_id"])
    assert_response :success
    assert body["draft_message_id"]
    assert_equal 1, @drafts.email_messages.count
  end

  test "destroy discards the saved revision" do
    first = autosave

    delete draft_path(first["draft_message_id"])
    assert_redirected_to email_account_mailbox_path(@account, @drafts)
    assert_equal 0, @drafts.email_messages.count
  end

  # -- editing a saved draft -------------------------------------------------

  test "edit reads a saved draft back into the composer" do
    draft = EmailDraft.new(email_account_id: @account.id, to: "bob@remote.test",
                           cc: "carbon@remote.test", subject: "Half written",
                           body: "Got this far.", in_reply_to: "orig@remote.test")
    saved = draft.save

    get edit_draft_path(saved)
    assert_response :success

    assert_select "input[name='composed_email[to]'][value=?]", "bob@remote.test"
    assert_select "input[name='composed_email[cc]'][value=?]", "carbon@remote.test"
    assert_select "input[name='composed_email[subject]'][value=?]", "Half written"
    assert_select "textarea[name='composed_email[body]']", /Got this far\./
    # The revision being edited, so the first autosave replaces it rather
    # than adding a second draft.
    assert_select "input[name='composed_email[draft_message_id]'][value=?]", saved.id.to_s
  end

  test "edit carries the threading headers of a saved reply draft" do
    draft = EmailDraft.new(email_account_id: @account.id, to: "bob@remote.test",
                           subject: "Re: Hi", body: "Replying",
                           in_reply_to: "orig@remote.test", references: "orig@remote.test")
    saved = draft.save

    get edit_draft_path(saved)
    assert_select "input[name='composed_email[in_reply_to]'][value=?]", "orig@remote.test"
    assert_select "input[name='composed_email[references]'][value=?]", "orig@remote.test"
  end

  # The id names an EmailMessage, so without a \\Draft check this route
  # would open - and its destroy would delete - any message in any mailbox.
  test "edit refuses a message that is not a draft" do
    received = EmailMessage.deliver_raw(@account.inbox, "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n")

    get edit_draft_path(received)
    assert_response :not_found
  end

  test "destroy refuses a message that is not a draft" do
    received = EmailMessage.deliver_raw(@account.inbox, "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n")

    delete draft_path(received)
    assert_response :not_found
    assert EmailMessage.exists?(received.id), "an ordinary message must survive"
  end

  test "destroy discards the draft and returns to the folder" do
    saved = EmailDraft.new(email_account_id: @account.id, subject: "Bin me", body: "x").save

    delete draft_path(saved)
    assert_redirected_to email_account_mailbox_path(@account, @drafts)
    assert_equal 0, @drafts.email_messages.count
  end
end
