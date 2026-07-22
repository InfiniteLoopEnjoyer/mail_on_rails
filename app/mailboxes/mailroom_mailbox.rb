require "mail_on_rails/clamav_scanner"

# Delivers inbound mail into the INBOX of every local account that appears
# as a recipient (To/Cc/Bcc or the X-Original-To envelope headers stamped
# by the SMTP daemon via MailOnRails::Smtp::IngressClient).
#
# Virus policy: the SMTP daemon scans at DATA time and stamps the trusted
# X-MailOnRails-Scan header ("clean" skips re-scanning here). Stampless mail
# (scanning disabled daemon-side, or a deploy gap) is scanned locally when
# SMTP_CLAMAV_ADDR is set. Anything not clean is filed into the
# account's Quarantine mailbox for review instead of INBOX - the daemon
# already refused the sender (550 infected / 451 unscanned), so these copies
# exist purely for the admin, deduped by Message-ID because a 451 makes the
# sender retry the same message for days.
class MailroomMailbox < ApplicationMailbox
  def process
    verdict = scan_verdict
    recipients.each do |recipient|
      account = EmailAccount.find_by(email: recipient.strip.downcase)
      next unless account

      if verdict && verdict[:status] != "clean"
        quarantine(account, verdict)
      else
        EmailMessage.deliver_raw(account.inbox, inbound_email.source,
                                 authenticated_as: authenticated_as, auth_results: auth_results,
                                 scan_status: verdict&.dig(:status))
        sweep_stale_unscanned(account)
        Rails.logger.info "[mail_on_rails] delivered inbound message to #{account.email} INBOX"
      end
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

  # The daemon's stamped verdict (same trusted channel as authenticated_as),
  # else a local scan when one is configured. Nil = scanning off everywhere.
  def scan_verdict
    stamped = header_values("X-MailOnRails-Scan").first.to_s.strip.downcase
    if stamped.present?
      { status: stamped, virus: header_values("X-MailOnRails-Virus").first.to_s.strip.presence }
    elsif MailOnRails::ClamavScanner.enabled?
      result = MailOnRails::ClamavScanner.scan(inbound_email.source)
      # :unavailable degrades to a quarantined "unscanned" copy rather than
      # raising: a retrying routing job would delay every recipient, and the
      # flagged row keeps the message reviewable either way.
      { status: result.infected? ? "infected" : (result.clean? ? "clean" : "unscanned"),
        virus: result.virus }
    end
  end

  def quarantine(account, verdict)
    mid = mail.message_id.to_s.presence
    mailbox = account.quarantine_mailbox
    if mid && mailbox.email_messages.exists?(message_id: mid)
      Rails.logger.info "[mail_on_rails] skipped duplicate quarantine copy for #{account.email} (#{mid})"
      return
    end

    EmailMessage.deliver_raw(mailbox, inbound_email.source,
                             authenticated_as: authenticated_as, auth_results: auth_results,
                             scan_status: verdict[:status], virus_name: verdict[:virus])
    Rails.logger.warn "[mail_on_rails] quarantined #{verdict[:status]} message for #{account.email}" \
                      "#{" (#{verdict[:virus]})" if verdict[:virus]}"
  end

  # A clean delivery supersedes "unscanned" review copies of the same
  # message left behind by 451 tempfails (clamd was down, the sender
  # retried, the retry scanned clean). Never touches "infected" rows.
  def sweep_stale_unscanned(account)
    mid = mail.message_id.to_s.presence
    return unless mid

    mailbox = account.find_mailbox(Mailbox::QUARANTINE)
    return unless mailbox

    swept = mailbox.email_messages.where(message_id: mid, scan_status: "unscanned").delete_all
    Rails.logger.info "[mail_on_rails] swept #{swept} stale unscanned quarantine copies for #{account.email}" if swept.positive?
  end

  def header_values(name)
    mail.header.fields.select { |field| field.name.casecmp?(name) }.map(&:value)
  end
end
