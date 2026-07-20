# Delivers inbound mail into the INBOX of every local account that appears
# as a recipient (To/Cc/Bcc or the X-Original-To envelope headers stamped
# by the SMTP daemon via MailOnRails::Smtp::IngressClient).
class MailroomMailbox < ApplicationMailbox
  def process
    recipients.each do |recipient|
      account = EmailAccount.find_by(email: recipient.strip.downcase)
      next unless account

      EmailMessage.deliver_raw(account.inbox, inbound_email.source,
                               authenticated_as: authenticated_as, auth_results: auth_results)
      Rails.logger.info "[mail_on_rails] delivered inbound message to #{account.email} INBOX"
    end
  end

  private

  def recipients
    envelope = header_values("X-Original-To")
    (Array(mail.recipients) + envelope).map(&:to_s).uniq
  end

  # Read from the authoritative header stamped by MailOnRails::Smtp::IngressClient
  # (any forged copy in the submitted DATA was stripped there). "no" /
  # absent means the sender did not authenticate.
  def authenticated_as
    value = header_values("X-MailOnRails-Authenticated").first.to_s.strip
    value.presence unless value.casecmp?("no")
  end

  # SPF/DKIM/DMARC verdicts stamped by the SMTP server (same trusted
  # X-MailOnRails-* channel as above). Nil for authenticated submissions.
  def auth_results
    header_values("X-MailOnRails-Auth-Results").first.to_s.strip.presence
  end

  def header_values(name)
    mail.header.fields.select { |field| field.name.casecmp?(name) }.map(&:value)
  end
end
