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

    fill_in "composed_email[body]", with: "Thanks, that works for me."

    # The debounce is 3s; the status line is the composer's own signal that
    # the round trip finished.
    assert_selector "[data-draft-autosave-target='status']", text: "Saved to Drafts", wait: 15

    saved = @drafts.email_messages.sole
    assert_includes saved.flags, "\\Draft"
    assert_match(/Thanks, that works for me\./, saved.raw)
    assert_match(/^Subject: Re: hello/, saved.raw)
  end

  # Each save replaces the previous revision rather than piling up, which is
  # the behaviour that keeps the mailbox usable on the phone.
  test "editing again replaces the draft instead of adding a second one" do
    open_message

    fill_in "composed_email[body]", with: "First pass."
    assert_selector "[data-draft-autosave-target='status']", text: "Saved to Drafts", wait: 15
    first_id = @drafts.email_messages.sole.id

    fill_in "composed_email[body]", with: "Second pass, revised."
    # Wait for the id to actually turn over rather than for the status text,
    # which already reads "Saved to Drafts" from the first save.
    assert_no_selector "input[name='composed_email[draft_message_id]'][value='#{first_id}']",
                       visible: :all, wait: 15

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

    fill_in "composed_email[body]", with: "Sending this one."
    assert_selector "[data-draft-autosave-target='status']", text: "Saved to Drafts", wait: 15

    click_on "Send"
    assert_text "Email sent.", wait: 10
    assert_equal 0, @drafts.email_messages.count
  end
end
