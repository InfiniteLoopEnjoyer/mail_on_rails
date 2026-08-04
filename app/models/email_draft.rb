# A draft being composed in the web UI.
#
# There is no separate drafts table: a draft *is* an EmailMessage in the
# account's Drafts mailbox carrying the \Draft flag, which is the only way
# an IMAP client will ever see it. That makes the mailbox the single source
# of truth, and the web UI a peer of the phone rather than a second store
# that has to be reconciled with one.
#
# Saving follows the same shape as IMAP's own REPLACE (RFC 8508), because
# it is the only shape available: messages are immutable, so a revision is
# a *new* message plus an expunge of the one it supersedes. Every save
# therefore mints a new id and a new UID - callers must carry the id
# forward rather than assume it is stable. The same is true in reverse: a
# phone editing this draft replaces the message out from under us, so a
# save against a superseded revision is expected, not exceptional (see
# #save, which treats a missing previous revision as "already gone").
class EmailDraft
  include ActiveModel::Model

  # \Seen alongside \Draft: it is the user's own message, so showing it as
  # unread in the folder list (and in the account's unread badge) is noise.
  FLAGS = [ "\\Draft", "\\Seen" ].freeze
  MAILBOX = "Drafts"

  attr_accessor :email_account_id, :to, :cc, :subject, :body,
                :in_reply_to, :references, :message_id

  # The saved revision this draft supersedes, if any.
  attr_accessor :draft_message_id

  validate :account_chosen

  def account
    @account ||= EmailAccount.find_by(id: email_account_id)
  end

  # Prefills a reply to +message+: recipient, "Re:" subject, threading
  # headers, and the quoted original.
  def self.reply_to(message, account: message.mailbox.email_account)
    new(
      email_account_id: account.id,
      to: message.from_address,
      subject: reply_subject(message.subject),
      body: quoted(message),
      in_reply_to: message.message_id.presence,
      references: [ message.references, message.message_id ].compact_blank.join(" ").presence
    )
  end

  # Reads a saved draft back out of its message so the composer can carry
  # on from it. The message is the only record of the draft, so everything
  # comes off the wire form - including message_id, which keeps the thread
  # intact across the revisions this editing session will produce.
  def self.from_message(message)
    mail = message.parsed
    new(
      email_account_id: message.mailbox.email_account_id,
      to: Array(mail.to).join(", ").presence,
      cc: Array(mail.cc).join(", ").presence,
      subject: mail.subject.to_s.presence,
      body: message.text_body,
      in_reply_to: Array(mail.in_reply_to).first,
      references: Array(mail.references).join(" ").presence,
      message_id: message.message_id.presence,
      draft_message_id: message.id
    )
  end

  def self.reply_subject(subject)
    subject = subject.to_s.strip
    return "Re: (no subject)" if subject.empty?

    subject.match?(/\Are:\s/i) ? subject : "Re: #{subject}"
  end

  # Attribution line plus the original quoted with "> ", the convention
  # every mail client renders as a quote.
  def self.quoted(message)
    quoted_body = message.text_body.to_s.lines.map { |line| "> #{line.chomp}" }.join("\n")
    "\n\n#{message.from_address} wrote:\n#{quoted_body}\n"
  end

  def drafts_mailbox
    account&.find_mailbox(MAILBOX)
  end

  # True once there is anything worth persisting. Autosave fires on a timer,
  # and an empty draft in the mailbox is worse than no draft at all - it
  # shows up on every device as a piece of litter to clean up.
  def blank?
    [ to, cc, subject ].all?(&:blank?) && body.to_s.strip.blank?
  end

  # Writes this revision and expunges the one it supersedes, returning the
  # new EmailMessage (or nil when there is nothing to save). Both halves run
  # in one transaction so a draft can never be lost between them.
  def save
    return nil unless valid?
    return nil if blank?

    mailbox = drafts_mailbox
    errors.add(:base, "no Drafts mailbox") and return nil if mailbox.nil?

    self.message_id ||= new_message_id
    ApplicationRecord.transaction do
      saved = EmailMessage.deliver_raw(mailbox, build_raw, flags: FLAGS.dup,
                                                          authenticated_as: account.email)
      discard_previous(mailbox)
      self.draft_message_id = saved.id
      saved
    end
  end

  # Removes the saved revision, if it is still there. Used when a draft is
  # sent or abandoned.
  def discard
    mailbox = drafts_mailbox
    discard_previous(mailbox) if mailbox
    self.draft_message_id = nil
    true
  end

  # Hands this draft to the sending path. The Drafts copy is dropped only
  # once delivery has committed, so a failed send leaves the draft intact.
  def deliver
    composed = ComposedEmail.new(email_account_id: email_account_id, to: to, cc: cc,
                                 subject: subject, body: body, message_id: message_id,
                                 in_reply_to: in_reply_to, references: references)
    return false unless composed.deliver

    discard
    true
  end

  def build_raw
    ComposedEmail.new(email_account_id: email_account_id, to: to, cc: cc, subject: subject,
                      body: body, in_reply_to: in_reply_to, references: references,
                      message_id: message_id).build_raw
  end

  private

  # A stable Message-ID across revisions, so a threading client (and our
  # own In-Reply-To handling) sees one draft being revised rather than a
  # string of unrelated messages.
  def new_message_id
    "<#{SecureRandom.uuid}@#{account.email.to_s.split("@").last}>"
  end

  # The previous revision may already be gone - expunged by a phone that
  # saved its own revision, or by a concurrent autosave. That is ordinary,
  # so a miss is silent.
  def discard_previous(mailbox)
    return if draft_message_id.blank?

    mailbox.email_messages.find_by(id: draft_message_id)&.destroy
  end

  def account_chosen
    errors.add(:email_account_id, "must be chosen") if account.nil?
  end
end
