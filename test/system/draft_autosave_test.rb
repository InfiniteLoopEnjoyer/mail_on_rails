require "application_system_test_case"

# The composer's autosave only exists once JavaScript runs, so this is the
# only level that can tell whether it is actually wired up: a typo in a
# Stimulus target name would leave every request-level test passing and the
# feature silently dead.
class DraftAutosaveTest < ApplicationSystemTestCase
  RAW = "From: sender@remote.test\r\nTo: carol@example.com\r\n" \
        "Subject: hello\r\nMessage-ID: <m1@remote.test>\r\n\r\nbody\r\n"

  setup do
    @user = users(:one)
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @message = EmailMessage.deliver_raw(@account.inbox, RAW)
    @drafts = @account.find_mailbox("Drafts")
  end

  def open_message
    sign_in_as(@user)
    visit email_account_mailbox_email_message_url(@account, @account.inbox, @message)
  end

  test "typing a reply autosaves it into the Drafts mailbox" do
    open_message
    assert_selector "h2", text: "Reply"

    compose("body", "Thanks, that works for me.")

    wait_for_autosave

    saved = @drafts.email_messages.sole
    assert_includes saved.flags, "\\Draft"
    assert_match(/Thanks, that works for me\./, saved.raw)
    assert_match(/^Subject: Re: hello/, saved.raw)
  end

  # Each save replaces the previous revision rather than piling up, which is
  # the behaviour that keeps the mailbox usable on the phone.
  test "editing again replaces the draft instead of adding a second one" do
    open_message

    compose("body", "First pass.")
    wait_for_autosave
    first_id = @drafts.email_messages.sole.id

    second_id = wait_for_autosave { compose("body", "Second pass, revised.") }
    assert_not_equal first_id.to_s, second_id, "a revision is a new message"

    assert_equal 1, @drafts.email_messages.count, "one draft, not a revision history"
    assert_match(/Second pass, revised\./, @drafts.email_messages.sole.raw)
  end

  # Autosave runs on a timer, so an untouched composer must not litter every
  # device with an empty draft.
  test "an untouched composer saves nothing" do
    open_message
    assert_selector "h2", text: "Reply"
    sleep 5

    assert_equal 0, @drafts.email_messages.count
  end

  test "sending the reply leaves nothing behind in Drafts" do
    open_message

    compose("body", "Sending this one.")
    wait_for_autosave

    click_on "Send"
    assert_text "Email sent.", wait: 10
    assert_equal 0, @drafts.email_messages.count
  end

  # The whole point of saving into Drafts: leave the page, come back from
  # the folder, and carry on from where you stopped.
  test "a draft can be reopened from the Drafts folder and carried on" do
    open_message

    compose("body", "Started on the laptop.")
    wait_for_autosave

    visit email_account_mailbox_url(@account, @drafts)
    click_on "Re: hello"

    # The composer, not the read view, prefilled with what was written.
    assert_selector "h2", text: "Draft"
    assert_field "composed_email[body]", with: /Started on the laptop\./
    assert_field "composed_email[to]", with: "sender@remote.test"

    compose("body", "Started on the laptop. Finished here.")
    wait_for_autosave

    assert_equal 1, @drafts.email_messages.count, "still one draft after editing"
    assert_match(/Finished here\./, @drafts.email_messages.sole.raw)
  end

  test "discarding a draft removes it" do
    open_message
    compose("body", "Never mind.")
    wait_for_autosave

    visit edit_draft_url(@drafts.email_messages.sole)
    accept_turbo_confirm "Discard draft"

    assert_text "Draft discarded.", wait: 10
    assert_equal 0, @drafts.email_messages.count
  end
end
