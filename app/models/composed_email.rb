# An email composed in the web UI. deliver builds the RFC822 message and
# routes each recipient the same way the SMTP edge would: local addresses
# (accounts or aliases) go straight into their account's INBOX, remote ones
# are queued as SmtpOutboundMessages for DeliverSmtpOutboundJob. A \Seen
# copy is filed into the sender's Sent folder.
class ComposedEmail
  include ActiveModel::Model

  attr_accessor :email_account_id, :to, :subject, :body

  validates :to, :subject, presence: true
  validate :account_chosen
  validate :recipients_are_addresses

  def account
    @account ||= EmailAccount.find_by(id: email_account_id)
  end

  def recipients
    to.to_s.split(/[,;]+/).map { |address| address.strip.downcase }.reject(&:empty?)
  end

  def deliver
    return false unless valid?

    raw = build_raw
    ApplicationRecord.transaction do
      recipients.each do |recipient|
        if (inbox = local_inbox(recipient))
          EmailMessage.deliver_raw(inbox, raw, authenticated_as: account.email)
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

  private

  def build_raw
    mail = Mail.new
    mail.from    = account.name.present? ? "#{account.name} <#{account.email}>" : account.email
    mail.to      = recipients
    mail.subject = subject
    mail.date    = Time.current
    mail.body    = body.to_s
    mail.to_s
  end

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
