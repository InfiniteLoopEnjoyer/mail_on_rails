require "mail_on_rails/clamav_scanner"

# An email composed in the web UI. deliver builds the RFC822 message and
# routes each recipient the same way the SMTP edge would: local addresses
# (accounts or aliases) go straight into their account's INBOX, remote ones
# are queued as SmtpOutboundMessages for DeliverSmtpOutboundJob. A \Seen
# copy is filed into the sender's Sent folder.
class ComposedEmail
  include ActiveModel::Model

  attr_accessor :email_account_id, :to, :cc, :subject, :body,
                :in_reply_to, :references, :message_id

  validates :to, :subject, presence: true
  validate :account_chosen
  validate :recipients_are_addresses

  def account
    @account ||= EmailAccount.find_by(id: email_account_id)
  end

  # Everyone the message is addressed to, To and Cc alike - the envelope
  # makes no distinction, only the headers do.
  def recipients
    (addresses(to) + addresses(cc)).uniq
  end

  def addresses(field)
    field.to_s.split(/[,;]+/).map { |address| address.strip.downcase }.reject(&:empty?)
  end

  def deliver
    return false unless valid?

    raw = build_raw
    # The web composer is its own submission edge: mail it puts straight into
    # a local INBOX never crosses exim or the mailroom, so it must run the
    # same clamav scan itself. Unlike the mailroom (which has already
    # accepted the message and can only quarantine), the sender is right
    # here - an infected message is simply refused.
    verdict = MailOnRails::ClamavScanner.scan(raw) if MailOnRails::ClamavScanner.enabled?
    if verdict&.infected?
      errors.add(:base, "Virus detected (#{verdict.virus}) - the message was not sent")
      return false
    end

    scan_status = verdict && (verdict.clean? ? "clean" : "unscanned")
    ApplicationRecord.transaction do
      recipients.each do |recipient|
        if (inbox = local_inbox(recipient))
          EmailMessage.deliver_raw(inbox, raw, authenticated_as: account.email, scan_status: scan_status)
        else
          SmtpOutboundMessage.create!(mail_from: account.email, recipient: recipient,
                                      data: raw, next_attempt_at: Time.current)
        end
      end
      if (sent = account.find_mailbox("Sent"))
        EmailMessage.deliver_raw(sent, raw, flags: [ "\\Seen" ], authenticated_as: account.email)
      end
    end
    true
  end

  # Public so EmailDraft can render the same bytes it will eventually send -
  # a draft that serialises differently from its sent form is a draft of a
  # different message.
  def build_raw
    mail = Mail.new
    mail.from    = account.name.present? ? "#{account.name} <#{account.email}>" : account.email
    mail.to      = addresses(to)
    mail.cc      = addresses(cc) if addresses(cc).any?
    mail.subject = subject
    mail.date    = Time.current
    mail.message_id = message_id if message_id.present?
    # RFC 5322 threading: In-Reply-To names the parent, References carries
    # the whole ancestry, which is what clients group a conversation by.
    mail.in_reply_to = in_reply_to if in_reply_to.present?
    mail.references  = references if references.present?
    mail.body    = body.to_s
    mail.to_s
  end

  private

  def local_inbox(recipient)
    local = EmailAccount.find_by(email: recipient) ||
            EmailAlias.find_by(email: recipient)&.email_account
    local&.inbox
  end

  def account_chosen
    errors.add(:email_account_id, "must be chosen") if account.nil?
  end

  def recipients_are_addresses
    recipients.each do |recipient|
      unless recipient.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
        errors.add(:to, "contains an invalid address: #{recipient}")
      end
    end
  end
end
