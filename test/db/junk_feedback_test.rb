# frozen_string_literal: true

require_relative "test_helper"

# The user's filing decisions as spam verdicts: which moves teach what,
# and that teaching never gets in the way of the move itself.
class JunkFeedbackTest < DbSuite::TestCase
  RAW = "From: Spammer@Remote.TEST\r\nTo: bob@example.test\r\nSubject: hi\r\n\r\nbody\r\n"
  NO_FROM = "To: bob@example.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def setup
    super
    enqueued.clear
  end

  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "bob@example.test",
                                                   password: "a-long-test-password")
  end

  def inbox = account.inbox
  def junk = account.junk_mailbox
  def trash = account.trash_mailbox

  def deliver(mailbox, raw = RAW)
    MailOnRails::EmailMessage.deliver_raw(mailbox, raw)
  end

  def enqueued
    MailOnRails::LearnSpamJob.queue_adapter.enqueued_jobs
  end

  def learn_jobs
    enqueued.select { |job| job[:job] == MailOnRails::LearnSpamJob }.map { |job| job[:args] }
  end

  def rules
    account.sender_rules.order(:address).pluck(:address, :verdict, :source)
  end

  test "move_to! re-delivers the bytes under a new uid and removes the original" do
    original = deliver(inbox)
    moved = original.move_to!(trash)

    assert_equal trash, moved.mailbox
    assert_equal original.email_object_id, moved.email_object_id
    assert_equal RAW, moved.raw
    assert_not MailOnRails::EmailMessage.exists?(original.id)
  end

  test "filing into Junk denies the sender and learns spam" do
    moved = deliver(inbox).move_to!(junk)

    assert_equal [ [ "spammer@remote.test", "deny", "move" ] ], rules
    assert_equal [ [ moved.id, moved.email_object_id, account.id, "spam" ] ], learn_jobs
  end

  test "rescuing out of Junk flips the sender to allow and learns ham" do
    deliver(inbox).move_to!(junk, source: "imap")
    enqueued.clear
    moved = junk.email_messages.sole.move_to!(inbox, source: "web")

    assert_equal [ [ "spammer@remote.test", "allow", "web" ] ], rules
    assert_equal [ [ moved.id, moved.email_object_id, account.id, "ham" ] ], learn_jobs
  end

  test "deleting spam from Junk is not a verdict" do
    deliver(junk).move_to!(trash)

    assert_empty rules
    assert_empty learn_jobs
  end

  test "moves that do not cross the Junk boundary are silent" do
    old = account.mailboxes.create!(name: "Junk/Old")
    archive = account.mailboxes.create!(name: "Archive")

    deliver(junk).move_to!(old)
    deliver(inbox).move_to!(old)
    deliver(inbox).move_to!(trash)
    deliver(inbox).move_to!(archive)
    deliver(old).move_to!(inbox)

    assert_empty rules
    assert_empty learn_jobs
  end

  test "Trash to Junk is still a spam verdict" do
    deliver(trash).move_to!(junk)

    assert_equal [ [ "spammer@remote.test", "deny", "move" ] ], rules
    assert_equal [ "spam" ], learn_jobs.map(&:last)
  end

  test "a message without a From still trains but writes no rule" do
    deliver(inbox, NO_FROM).move_to!(junk)

    assert_empty rules
    assert_equal [ "spam" ], learn_jobs.map(&:last)
  end

  test "the account's own address and aliases never get a rule" do
    account.email_aliases.create!(email: "alias@example.test")
    deliver(inbox, "From: Bob@Example.test\r\n\r\nself\r\n").move_to!(junk)
    deliver(inbox, "From: alias@example.test\r\n\r\nself\r\n").move_to!(junk)

    assert_empty rules
    assert_equal [ "spam", "spam" ], learn_jobs.map(&:last)
  end

  test "the learn job is enqueued only once the enclosing transaction commits" do
    message = deliver(inbox)
    MailOnRails::EmailMessage.transaction do
      message.move_to!(junk)
      assert_empty learn_jobs, "must not enqueue inside the transaction"
    end
    assert_equal [ "spam" ], learn_jobs.map(&:last)
  end

  test "a failing rule write neither breaks the move nor trains" do
    MailOnRails::SenderRule.singleton_class.alias_method(:record_without_failure!, :record!)
    MailOnRails::SenderRule.define_singleton_method(:record!) { |*| raise "boom" }

    moved = nil
    MailOnRails::EmailMessage.transaction { moved = deliver(inbox).move_to!(junk) }

    assert_equal junk, moved.mailbox
    assert_empty rules
    assert_empty learn_jobs
  ensure
    MailOnRails::SenderRule.singleton_class.alias_method(:record!, :record_without_failure!)
    MailOnRails::SenderRule.singleton_class.remove_method(:record_without_failure!)
  end

  test "the classifier on its own" do
    old = account.mailboxes.create!(name: "Junk/Old")

    assert_equal "spam", MailOnRails::JunkFeedback.classify(nil, junk)
    assert_equal "spam", MailOnRails::JunkFeedback.classify(inbox, junk)
    assert_equal "ham", MailOnRails::JunkFeedback.classify(junk, inbox)
    assert_nil MailOnRails::JunkFeedback.classify(junk, trash)
    assert_nil MailOnRails::JunkFeedback.classify(junk, old)
    assert_nil MailOnRails::JunkFeedback.classify(old, junk)
    assert_nil MailOnRails::JunkFeedback.classify(nil, old)
    assert_nil MailOnRails::JunkFeedback.classify(inbox, trash)
  end
end
