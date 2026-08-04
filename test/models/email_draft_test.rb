require "test_helper"

# A draft is a message in the Drafts mailbox carrying \Draft - that is the
# only form an IMAP client can see, so these tests assert against the
# mailbox rather than against any draft-specific storage.
class EmailDraftTest < ActiveSupport::TestCase
  setup do
    @account = EmailAccount.create!(email: "carol@example.com", password: "secret123")
    @drafts = @account.find_mailbox("Drafts")
  end

  def build(**attrs)
    EmailDraft.new({ email_account_id: @account.id, to: "bob@remote.test",
                     subject: "Hello", body: "Draft body" }.merge(attrs))
  end

  # Edits the draft in place and saves the new revision, the way the
  # composer does on each autosave.
  def resave(draft, **attrs)
    attrs.each { |name, value| draft.public_send("#{name}=", value) }
    draft.save
  end

  def received(subject: "Original", from: "sender@remote.test", message_id: "<orig@remote.test>",
               references: nil, body: "First line\nSecond line")
    raw = +"From: #{from}\r\nTo: #{@account.email}\r\nSubject: #{subject}\r\n"
    raw << "Message-ID: #{message_id}\r\n"
    raw << "References: #{references}\r\n" if references
    raw << "\r\n#{body}\r\n"
    EmailMessage.deliver_raw(@account.inbox, raw)
  end

  # -- saving ----------------------------------------------------------------

  test "saving files the draft into Drafts with the draft flag" do
    saved = build.save

    assert_equal @drafts.id, saved.mailbox_id
    assert_includes saved.flags, "\\Draft"
    assert_equal 1, @drafts.email_messages.count
  end

  test "the saved draft is a real message the imap layer can serve" do
    saved = build(to: "bob@remote.test", subject: "Hello", body: "Draft body").save

    assert_match(/^Subject: Hello/, saved.raw)
    assert_match(/^To: bob@remote.test/, saved.raw)
    assert_match(/Draft body/, saved.raw)
    assert_equal saved.raw.bytesize, saved.size
    assert saved.uid.positive?, "a draft needs a UID like any other message"
  end

  # IMAP messages are immutable, so a revision is a new message plus an
  # expunge - the same shape REPLACE (RFC 8508) has. The mailbox must hold
  # one draft, not a pile of revisions.
  test "re-saving replaces the previous revision rather than accumulating" do
    draft = build
    first = draft.save
    second = resave(draft, body: "Revised body")

    assert_equal 1, @drafts.email_messages.count, "one draft, not a revision history"
    assert_nil EmailMessage.find_by(id: first.id)
    assert_match(/Revised body/, second.raw)
  end

  test "each revision gets a new uid" do
    draft = build
    first = draft.save
    second = resave(draft, body: "Revised")

    assert_not_equal first.uid, second.uid
  end

  # The Message-ID is what threads the draft, so it has to survive being
  # rewritten as a new message on every save.
  test "the message id is stable across revisions" do
    draft = build
    first = draft.save
    second = resave(draft, body: "Revised")

    assert_equal first.message_id, second.message_id
    assert first.message_id.present?
  end

  # Autosave fires on a timer, and an empty draft in the mailbox is litter
  # that shows up on every device.
  test "an empty draft is not saved" do
    assert_nil build(to: "", cc: "", subject: "", body: "   ").save
    assert_equal 0, @drafts.email_messages.count
  end

  test "a draft with only a body is saved" do
    assert build(to: "", subject: "", body: "just a thought").save
  end

  test "a draft for an unknown account is not saved" do
    draft = EmailDraft.new(email_account_id: -1, body: "orphan")
    assert_nil draft.save
    assert draft.errors.any?
  end

  # A phone saving its own revision expunges ours. Autosaving on top of a
  # revision that is already gone is ordinary, not an error.
  test "saving over a revision that has already been expunged still works" do
    draft = build
    first = draft.save
    first.destroy # a phone replaced it

    second = resave(draft, body: "Written on the laptop")
    assert second
    assert_equal 1, @drafts.email_messages.count
  end

  # -- discarding ------------------------------------------------------------

  test "discarding removes the saved revision" do
    draft = build
    draft.save

    assert draft.discard
    assert_equal 0, @drafts.email_messages.count
    assert_nil draft.draft_message_id
  end

  test "discarding an already-gone revision is not an error" do
    draft = build
    draft.save
    @drafts.email_messages.destroy_all

    assert draft.discard
  end

  # -- replies ---------------------------------------------------------------

  test "reply_to prefills recipient, subject and threading headers" do
    original = received(subject: "Quarterly report", message_id: "<orig@remote.test>")
    draft = EmailDraft.reply_to(original, account: @account)

    assert_equal "sender@remote.test", draft.to
    assert_equal "Re: Quarterly report", draft.subject
    # Mail normalises ids without angle brackets and re-adds them when it
    # serialises; the wire form is asserted against the raw further down.
    assert_equal "orig@remote.test", draft.in_reply_to
    assert_includes draft.references, "orig@remote.test"
  end

  test "reply_to does not double up an existing Re: prefix" do
    assert_equal "Re: Already", EmailDraft.reply_subject("Re: Already")
    # An existing prefix is left exactly as the sender wrote it rather than
    # being re-cased - rewriting someone else's subject line is worse than
    # a lowercase "re:".
    assert_equal "re: Already", EmailDraft.reply_subject("re: Already")
    assert_equal "Re: (no subject)", EmailDraft.reply_subject("")
  end

  # References carries the whole ancestry, so a reply has to append to it
  # rather than replace it, or the thread breaks at this message.
  test "reply_to extends an existing references chain" do
    original = received(message_id: "<second@remote.test>", references: "<first@remote.test>")
    draft = EmailDraft.reply_to(original, account: @account)

    assert_includes draft.references, "first@remote.test"
    assert_includes draft.references, "second@remote.test"
  end

  test "reply_to quotes the original body" do
    original = received(body: "First line\nSecond line")
    draft = EmailDraft.reply_to(original, account: @account)

    assert_match(/sender@remote\.test wrote:/, draft.body)
    assert_match(/^> First line$/, draft.body)
    assert_match(/^> Second line$/, draft.body)
  end

  test "a saved reply carries its threading headers into the message" do
    original = received(message_id: "<orig@remote.test>")
    draft = EmailDraft.reply_to(original, account: @account)
    saved = draft.save

    assert_match(/^In-Reply-To: <orig@remote\.test>/, saved.raw)
    assert_match(/^References:.*<orig@remote\.test>/, saved.raw)
  end

  # -- sending ---------------------------------------------------------------

  test "delivering a draft removes it from Drafts" do
    draft = build(to: "bob@remote.test")
    draft.save
    assert_equal 1, @drafts.email_messages.count

    assert draft.deliver
    assert_equal 0, @drafts.email_messages.count, "a sent reply must not linger in Drafts"
  end

  test "delivering files a copy into Sent and queues the outbound message" do
    draft = build(to: "bob@remote.test")

    assert_difference -> { SmtpOutboundMessage.count }, 1 do
      assert draft.deliver
    end
    assert_equal 1, @account.find_mailbox("Sent").email_messages.count
  end

  # A failed send must leave the draft where it is, or the user loses what
  # they wrote.
  test "a draft that fails to send stays in Drafts" do
    draft = build(to: "", subject: "")
    draft.body = "unsent"
    draft.save

    assert_not draft.deliver
    assert_equal 1, @drafts.email_messages.count
  end

  test "cc recipients are addressed and receive the message" do
    draft = build(to: "bob@remote.test", cc: "carbon@remote.test")

    assert_difference -> { SmtpOutboundMessage.count }, 2 do
      assert draft.deliver
    end
    assert_equal %w[bob@remote.test carbon@remote.test],
                 SmtpOutboundMessage.order(:id).pluck(:recipient)
  end

  test "a cc header is written into the message" do
    saved = build(cc: "carbon@remote.test").save
    assert_match(/^Cc: carbon@remote\.test/, saved.raw)
  end
end
