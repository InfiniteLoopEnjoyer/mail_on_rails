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

    delete draft_path(first["draft_message_id"]),
           params: { draft: { email_account_id: @account.id } }, as: :json
    assert_response :no_content
    assert_equal 0, @drafts.email_messages.count
  end
end
