require "application_system_test_case"

# Composing from scratch uses the same composer as replying, so a long
# message written here is recoverable rather than lost on a stray refresh.
class NewEmailAutosaveTest < ApplicationSystemTestCase
  setup do
    @user = users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @drafts = @account.find_mailbox("Drafts")
  end

  test "a new message autosaves into Drafts and can be reopened" do
    sign_in_as(@user)
    visit new_email_url

    compose("to", "bob@remote.test")
    compose("subject", "Thoughts on the proposal")
    compose("body", "Been mulling this over.")
    wait_for_autosave

    saved = @drafts.email_messages.sole
    assert_includes saved.flags, "\\Draft"
    assert_match(/Been mulling this over\./, saved.raw)

    # Navigate away and back in through the folder.
    visit email_account_mailbox_url(@account, @drafts)
    click_on "Thoughts on the proposal"

    assert_selector "h2", text: "Draft"
    assert_selector "lexxy-editor [contenteditable]", text: /Been mulling this over\./
    assert_field "composed_email[to]", with: "bob@remote.test"
  end

  # Changing the sender moves the draft rather than leaving a copy behind in
  # the previous account's folder, where it would show up on that account's
  # devices forever.
  test "switching the sending account moves the draft" do
    other = EmailAccount.create!(email: "dave@example.com", password: "secret123")
    sign_in_as(@user)
    visit new_email_url(from: @account.id)

    compose("body", "Which address should this go from?")
    wait_for_autosave
    assert_equal 1, @drafts.email_messages.count

    wait_for_autosave { select other.email, from: "composed_email[email_account_id]" }

    assert_equal 1, other.find_mailbox("Drafts").email_messages.count, "moved to the new account"
    assert_equal 0, @drafts.email_messages.count, "no orphan left behind"
  end
end
