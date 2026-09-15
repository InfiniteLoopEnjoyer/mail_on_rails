require "mail_on_rails/aggregate_report"

# What SendDmarcReportsJob and SendTlsRptReportsJob share once a report
# is built: who it is from, which rua addresses are worth trying, how it
# is queued, and the Sent copy that keeps a record of it in the mailbox
# it went out under.
#
# Reports come from the dmarc@ / tls-rpt@ account of our primary hosted
# domain, so replies and bounces land in an account that exists. Outbound
# delivery puts them on the wire under a VERP return path (see
# OutboundDeliverer#verp_return_path), so an asynchronous hard bounce
# comes back to bounce@ and IngestBounceJob suppresses the rua address
# for this sender; a synchronous 5xx does the same from
# DeliverSmtpOutboundJob. Either way the next report skips the address
# until the cooldown lapses - a full mailbox or a blocklist listing is
# not forever, and a report a month later is a fresh, cheap attempt.
module MailOnRails
  class AggregateReportJob < BaseJob
    BOUNCE_COOLDOWN = 30.days

    private

    # Subclasses define KIND (an AggregateReport::KINDS entry) and
    # LOCAL_PART (the sending account's local part).

    def queue_report(domain, raw, recipients)
      recipients.each do |recipient|
        SmtpOutboundMessage.create!(mail_from: from_address, recipient: recipient,
                                    data: raw, next_attempt_at: Time.current)
      end
      file_sent_copy(raw)
      Rails.logger.info "[mail_on_rails] #{self.class::KIND} report for #{domain} queued to #{recipients.join(", ")}"
    end

    # The rua addresses minus any that bounced a recent report. Cooled-off
    # bounce rows are removed first (the delivery job enforces the same
    # table, so a stale row would otherwise fail the retry without a
    # network attempt); complaint and unsubscribe rows are untouched.
    def deliverable(recipients)
      SuppressedRecipient.expire_bounces!(sender: from_address, before: BOUNCE_COOLDOWN.ago)
      recipients.reject do |recipient|
        next false unless SuppressedRecipient.suppressed?(recipient, sender: from_address)

        Rails.logger.info "[mail_on_rails] #{self.class::KIND} report to #{recipient} skipped: " \
                          "a recent report to it bounced (retried after #{BOUNCE_COOLDOWN.inspect})"
        true
      end
    end

    # The sending account's Sent folder gets the same bytes the queue
    # holds, read-flagged like a composer copy - the outbox page shows
    # delivery state, the mailbox shows what was said. A missing account
    # or folder, or a full mailbox, costs the record and not the report.
    def file_sent_copy(raw)
      sent = EmailAccount.find_by(email: from_address)&.find_mailbox(Mailbox::SENT)
      return unless sent

      EmailMessage.deliver_raw(sent, raw, flags: [ "\\Seen" ], authenticated_as: from_address)
    rescue StandardError => e
      Rails.logger.error "[mail_on_rails] #{self.class::KIND} report Sent copy for #{from_address} failed: " \
                         "#{e.class}: #{e.message}"
    end

    def message_id(report_id)
      AggregateReport.message_id(self.class::KIND, report_id, submitter)
    end

    def from_address
      "#{self.class::LOCAL_PART}@#{report_domain}"
    end

    def report_domain
      @report_domain ||= Domain.order(:id).first&.name || Setting.effective_smtp_helo_hostname
    end

    def submitter
      report_domain
    end

    def dns
      MailOnRails::SenderAuth::Dns.shared
    end
  end
end
