require "test_helper"

# Trash is the only folder with a retention limit; the clock is the row's
# created_at (when the message entered Trash), never the received date.
class PurgeTrashJobTest < ActiveSupport::TestCase
  RAW = "From: sender@remote.test\r\nTo: carol@example.com\r\n" \
        "Subject: hello\r\nMessage-ID: <m1@remote.test>\r\n\r\nbody\r\n"

  setup do
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @trash = @account.find_mailbox("Trash")
  end

  def deliver(mailbox, trashed_ago:, received_ago: nil)
    message = EmailMessage.deliver_raw(mailbox, RAW, internal_date: (received_ago || trashed_ago).ago)
    message.update_columns(created_at: trashed_ago.ago)
    message
  end

  test "purges Trash messages past the retention window, keeps recent ones" do
    old = deliver(@trash, trashed_ago: 31.days)
    recent = deliver(@trash, trashed_ago: 29.days)

    PurgeTrashJob.perform_now

    assert_not EmailMessage.exists?(old.id)
    assert EmailMessage.exists?(recent.id)
    # Permanent deletion still leaves the IMAP expunge tombstone.
    assert_equal [ old.uid ], @trash.expunged_messages.pluck(:uid)
  end

  test "ages by time in Trash, not the received date" do
    # Received a year ago but only just moved to Trash: must survive.
    just_trashed = deliver(@trash, trashed_ago: 1.day, received_ago: 365.days)

    PurgeTrashJob.perform_now

    assert EmailMessage.exists?(just_trashed.id)
  end

  test "never touches mail outside Trash, however old" do
    inbox_message = deliver(@account.inbox, trashed_ago: 365.days)
    sent_message = deliver(@account.find_mailbox("Sent"), trashed_ago: 365.days)

    PurgeTrashJob.perform_now

    assert EmailMessage.exists?(inbox_message.id)
    assert EmailMessage.exists?(sent_message.id)
  end

  test "honours the configured retention setting" do
    Setting.trash_retention_days = 7
    week_old = deliver(@trash, trashed_ago: 8.days)
    fresh = deliver(@trash, trashed_ago: 6.days)

    PurgeTrashJob.perform_now

    assert_not EmailMessage.exists?(week_old.id)
    assert EmailMessage.exists?(fresh.id)
  end
end
