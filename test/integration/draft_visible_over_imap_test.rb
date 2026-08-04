require "test_helper"
# lib/mail_on_rails is on the autoload ignore list (config/application.rb).
require "mail_on_rails/store"

# A draft autosaved from the web is only useful if the phone can see it, so
# this drives the same store the IMAP daemon talks to (ImapBackend, behind
# the internal API) rather than asserting against Active Record directly.
class DraftVisibleOverImapTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @store = MailOnRails::Store::ImapBackend.new
  end

  def draft(**attrs)
    EmailDraft.new({ email_account_id: @account.id, to: "bob@remote.test",
                     subject: "Hello", body: "Draft body" }.merge(attrs))
  end

  def drafts_mailbox
    @store.select_mailbox(@account.id, "Drafts")
  end

  def fetch_all(mailbox)
    @store.fetch(mailbox[:mailbox_id], mailbox[:messages].map(&:first), true)[:messages]
  end

  test "Drafts is listed like any other mailbox" do
    assert_includes @store.list_mailboxes(@account.id)[:mailboxes], "Drafts"
  end

  # \Draft is what tells a mail client this is an unsent message to open in
  # the composer rather than a received one to read.
  test "a web-saved draft is visible over the store carrying the draft flag" do
    draft.save

    mailbox = drafts_mailbox
    assert_equal 1, mailbox[:messages].length

    message = fetch_all(mailbox).sole
    assert_includes message[:flags], "\\Draft"
    assert_match(/^Subject: Hello/, message[:raw])
    assert_match(/Draft body/, message[:raw])
  end

  # Every autosave is a new message and an expunge, exactly as REPLACE
  # (RFC 8508) does it, so a syncing client sees one draft with a changing
  # UID rather than a pile of revisions.
  test "re-saving leaves one draft with a new uid" do
    composing = draft
    composing.save
    first_uid = drafts_mailbox[:messages].sole.first

    composing.body = "Revised body"
    composing.save

    mailbox = drafts_mailbox
    assert_equal 1, mailbox[:messages].length
    second_uid = mailbox[:messages].sole.first

    assert_operator second_uid, :>, first_uid, "a revision is a new message, so a new uid"
    assert_match(/Revised body/, fetch_all(mailbox).sole[:raw])
  end

  # The expunge half has to be reported too, or a client that synced the
  # old revision keeps showing a draft the server no longer has.
  test "the superseded revision is reported as expunged for qresync" do
    composing = draft
    composing.save
    mailbox = drafts_mailbox
    first_uid = mailbox[:messages].sole.first
    before = @store.status(@account.id, "Drafts")[:highest_modseq]

    composing.body = "Revised"
    composing.save

    vanished = @store.expunged_since(mailbox[:mailbox_id], before)
    assert_includes vanished[:uids], first_uid
  end

  test "sending clears the draft from the mailbox the phone sees" do
    composing = draft
    composing.save
    assert_equal 1, drafts_mailbox[:messages].length

    composing.deliver
    assert_equal 0, drafts_mailbox[:messages].length
  end

  # A draft is an ordinary message, so the ops a client uses on one have to
  # work - a phone opening the draft will fetch it and may flag it.
  test "a draft can be fetched and flagged like any other message" do
    draft.save
    mailbox = drafts_mailbox
    uid = mailbox[:messages].sole.first

    result = @store.store_flags(mailbox[:mailbox_id], [ uid ], "+", [ "\\Seen" ])
    assert_includes result[:messages].sole[1], "\\Seen"
    assert_includes result[:messages].sole[1], "\\Draft"
  end
end
