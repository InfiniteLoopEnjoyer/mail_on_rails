# frozen_string_literal: true

require_relative "test_helper"

# Mailbox names are written by more than the IMAP edge (the web folder
# forms, a console), so the model repeats the IMAP server's own rules: a
# stored name must be one every IMAP command can address and echo.
class MailboxTest < DbSuite::TestCase
  def account
    @account ||= MailOnRails::EmailAccount.create!(email: "folders@example.test",
                                                   password: "a-long-test-password")
  end

  def build(name)
    account.mailboxes.new(name: name)
  end

  def error_for(name)
    mailbox = build(name)
    mailbox.valid?
    mailbox.errors[:name].join("; ")
  end

  test "ordinary names are valid, hierarchy and non-ASCII included" do
    [ "Archive", "Archive/2026", "Receipts & Bills", "Résumés", "日本語", "a b", "INBOX/Lists",
      "[Gmail]/All Mail", "x" * 1024, (%w[a] * 20).join("/") ].each do |name|
      mailbox = build(name)
      assert mailbox.valid?, "#{name[0, 40].inspect}: #{mailbox.errors.full_messages.to_sentence}"
    end
  end

  test "the default and on-demand system folders are valid names" do
    assert_equal %w[Drafts INBOX Junk Sent Trash], account.mailboxes.order(:name).pluck(:name)
    assert account.quarantine_mailbox.persisted?
    account.find_mailbox("Junk").destroy!
    assert account.junk_mailbox.persisted?, "Junk must be recreatable on demand"
  end

  test "control characters are refused - CR/LF, NUL, TAB, DEL and C1" do
    [ "Evil\r\n* BYE injected", "x\u0000y", "tab\there", "bell\a", "del\u007f", "nel\u0085" ].each do |name|
      assert_match(/control characters/, error_for(name), name.inspect)
    end
  end

  test "a NUL byte is a validation error, not an exception from the uniqueness lookup" do
    mailbox = build("x\u0000y")
    assert_not mailbox.save
    assert_equal 1, mailbox.errors.count
  end

  test "a name that is not valid UTF-8 is a validation error, not an exception" do
    mailbox = build("bad\xFFname".dup.force_encoding(Encoding::UTF_8))
    assert_not mailbox.valid?
    assert_match(/not valid UTF-8/, mailbox.errors[:name].join)
  end

  test "names are capped at the IMAP server's byte and depth limits" do
    assert_match(/too long/, error_for("x" * 1025))
    assert_match(/too long/, error_for("é" * 513), "the cap is bytes, not characters")
    assert_match(/too deeply/, error_for((%w[a] * 21).join("/")))
  end

  test "leading or trailing whitespace is refused, inner whitespace is fine" do
    [ "Sent ", " Sent", "Sent ", "　Sent" ].each do |name|
      assert_match(/whitespace/, error_for(name), name.inspect)
    end
    assert_equal "", error_for("Sent Items")
  end

  test "names IMAP could never address are refused: leading slash, empty level" do
    assert_match(/empty level/, error_for("/top"))
    assert_match(/empty level/, error_for("a//b"))
  end

  test "INBOX is reserved in every letter case" do
    %w[inbox Inbox iNbOx].each do |name|
      assert_match(/reserved/, error_for(name), name)
    end
    # The exact spelling is the account's own INBOX: taken, not reserved.
    assert_match(/taken/, error_for("INBOX"))
  end

  test "blank and duplicate names keep their ordinary errors" do
    assert_match(/blank/, error_for(""))
    assert_match(/blank/, error_for(nil))
    assert_match(/taken/, error_for("Sent"))
  end

  test "a row that predates the rules still loads, saves and claims UIDs" do
    legacy = build("Old\tname ")
    legacy.uid_validity = 1 # set by a before_validation hook, which validate: false skips
    legacy.save!(validate: false)
    legacy = MailOnRails::Mailbox.find(legacy.id)

    assert legacy.valid?, legacy.errors.full_messages.to_sentence
    assert legacy.save
    assert_equal 1, legacy.claim_uid!
    assert legacy.update(uid_validity: legacy.uid_validity + 1)

    # ...and can be renamed out of it, but not into another bad name.
    assert_not legacy.update(name: "Still bad\r\n")
    assert legacy.update(name: "Old name")
  end

  test "system? names the folders the system files into, by exact name" do
    %w[INBOX Sent Drafts Trash Junk Quarantine].each { |name| assert build(name).system?, name }
    [ "Archive", "Junk/2026", "sent", "Trash2" ].each { |name| assert_not build(name).system?, name }
  end

  test "INBOX still cannot be renamed or deleted" do
    inbox = account.inbox
    assert_not inbox.update(name: "Elsewhere")
    assert_not inbox.reload.destroy
    assert account.inbox
  end
end
