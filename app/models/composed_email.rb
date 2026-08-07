require "mail_on_rails/clamav_scanner"
require "mail_on_rails/rspamd_analyzer"
require "mail_on_rails/smtp/send_quota"

# An email composed in the web UI. deliver builds the RFC822 message and
# routes each recipient the same way the SMTP edge would: local addresses
# (accounts or aliases) go straight into their account's INBOX, remote ones
# are queued as SmtpOutboundMessages for DeliverSmtpOutboundJob. A \Seen
# copy is filed into the sender's Sent folder.
#
# The composer is a submission edge in its own right, so it carries the
# same anti-abuse gates as authenticated SMTP: each recipient consumes a
# slot from the account's shared send quota (what bounds a stolen
# password's worth), and the built message is scored by rspamd before
# anything is queued.
class ComposedEmail
  include ActiveModel::Model

  # Attachment budget, sized so the built message stays under the 30 MiB
  # the IMAP server advertises as APPENDLIMIT (and accepts as a literal):
  # base64 inflates the parts by 4/3, so 22 MiB of raw file bytes encode
  # to ~29.4 MiB, leaving headroom for headers and the text part.
  MAX_ATTACHMENT_BYTES = 22 * 1024 * 1024

  attr_accessor :email_account_id, :to, :cc, :subject, :body,
                :in_reply_to, :references, :message_id
  # Uploaded files (ActionDispatch::Http::UploadedFile) to send along.
  attr_writer :attachments
  # Test seam: an injected quota instance overrides, explicit nil disables.
  attr_writer :send_quota

  validates :to, :subject, presence: true
  validate :account_chosen
  validate :recipients_are_addresses
  validate :attachments_fit

  # A browser submits an empty multiple-file input as [""] - drop the
  # blanks so "no attachments" and "empty input" are the same thing.
  def attachments
    Array(@attachments).reject(&:blank?)
  end

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

    # Same accounting as the SMTP edge's RCPT-time check: one slot per
    # recipient, consumed whether or not the send later completes, and a
    # temporary-sounding refusal because the budget refills as the window
    # slides. Slots taken before the budget ran out stay consumed - an
    # over-quota burst costing quota punishes only abuse.
    unless consume_send_quota
      Rails.logger.warn("Composer send refused for #{account.email}: send quota exhausted")
      errors.add(:base, "Sending quota exceeded - try again later")
      return false
    end

    raw = build_raw
    # The web composer is its own submission edge: mail it puts straight into
    # a local INBOX never crosses the SMTP server or the mailroom, so it must run the
    # same clamav scan itself. Unlike the mailroom (which has already
    # accepted the message and can only quarantine), the sender is right
    # here - an infected message is simply refused.
    verdict = MailOnRails::ClamavScanner.scan(raw) if MailOnRails::ClamavScanner.enabled?
    if verdict&.infected?
      errors.add(:base, "Virus detected (#{verdict.virus}) - the message was not sent")
      return false
    end

    # The composer's spam gate, mirroring the SMTP DATA gate for
    # authenticated submissions: only rspamd's own refusal actions refuse,
    # milder verdicts pass, and an unreachable rspamd fails open (spam
    # scoring is advisory; blocking every send on a scorer outage punishes
    # the user, not the bot). Runs after the quota consume, as at SMTP
    # where RCPT slots are spent before DATA is judged.
    spam = spam_verdict(raw)
    if spam&.reject? || spam&.soft_reject?
      Rails.logger.warn("Composer send refused for #{account.email}: rspamd action=#{spam.action} " \
                        "score=#{spam.score}/#{spam.required_score}")
      errors.add(:base, spam.reject? ? "Message rejected as spam - it was not sent" :
                        "Message deferred by the content filter - try again later")
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
  rescue EmailMessage::OverQuota => e
    # A full mailbox - the sender's own (Sent copy) or a local
    # recipient's. The transaction rolled back, so nothing was sent.
    Rails.logger.warn("Composer send refused: #{e.message}")
    errors.add(:base, "Message not sent: #{e.message}")
    false
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
    if attachments.none?
      mail.body = body.to_s
    else
      # With attachments the message is multipart/mixed and the body must
      # be an explicit text part - Mail silently drops a plain `body=`
      # once attachments are added. The built raw then passes through the
      # same clamav and rspamd gates in #deliver as any other send, so an
      # infected attachment is refused.
      text = body.to_s
      mail.text_part = Mail::Part.new do
        content_type "text/plain; charset=UTF-8"
        body text
      end
      attachments.each do |file|
        options = { content: file.read }
        options[:mime_type] = file.content_type if file.content_type.present?
        mail.attachments[file.original_filename] = options
      end
    end
    mail.to_s
  end

  private

  # The process-wide quota unless a test injected its own (or nil). Keyed
  # by the account email - the same key authenticated SMTP sessions use -
  # so web and SMTP submission draw from one budget.
  def send_quota
    defined?(@send_quota) ? @send_quota : MailOnRails::Smtp::SendQuota.shared
  end

  def consume_send_quota
    quota = send_quota
    return true unless quota

    recipients.all? { quota.consume(account.email) }
  end

  # rspamd's verdict for this send, nil when rspamd is not configured.
  # The account is forwarded as the authenticated user so rspamd applies
  # its authenticated-sender policy; transport failure comes back as an
  # :unavailable Result (never raises), which the caller passes.
  def spam_verdict(raw)
    return nil unless MailOnRails::RspamdAnalyzer.enabled?

    verdict = MailOnRails::RspamdAnalyzer.analyze(raw, mail_from: account.email, rcpt: recipients.first,
                                                  authenticated_as: account.email)
    if verdict.unavailable?
      Rails.logger.warn("Composer send from #{account.email} accepted unscored: rspamd unavailable")
    else
      Rails.logger.info("Composer rspamd action=#{verdict.action} score=#{verdict.score} for #{account.email}")
    end
    verdict
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

  def attachments_fit
    if attachments.sum(&:size) > MAX_ATTACHMENT_BYTES
      errors.add(:base, "Attachments are too large - #{MAX_ATTACHMENT_BYTES / 1_048_576} MB total at most")
    end
  end
end
