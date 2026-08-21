require "mail_on_rails/clamav_scanner"

# Catch-up scanner for the dmarc@ and tls-rpt@ ingestion mailboxes
# (recurring, see config/recurring.yml). Mail delivered while virus
# scanning was disabled sits there with scan_status nil and deliberately
# unparsed; once clamav is back, this job scans those rows, then ingests
# the clean ones - keeping the invariant that no report is ever parsed
# without a clean scan. Infected ones are re-filed into Quarantine like
# the mailroom would have; unavailable scans stay pending for the next
# run.
module MailOnRails
  class ScanPendingReportsJob < BaseJob
    queue_as :default

    BATCH = 100

    def perform
      return unless MailOnRails::ClamavScanner.enabled?

      pending.limit(BATCH).each do |message|
        result = MailOnRails::ClamavScanner.scan(message.raw.to_s)
        next unless result.infected? || result.clean?

        if result.infected?
          quarantine(message, result.virus)
        else
          message.update!(scan_status: "clean")
          Domain.ingestion_job_for(message.mailbox.email_account.email)&.perform_later(message)
          Rails.logger.info "[mail_on_rails] late-scanned report #{message.id} clean; ingesting"
        end
      end
    end

    private

    def pending
      addresses = Domain.pluck(:name).flat_map do |name|
        [ "#{Domain::DMARC_LOCAL_PART}@#{name}", "#{Domain::TLS_RPT_LOCAL_PART}@#{name}" ]
      end
      inbox_ids = EmailAccount.where(email: addresses).filter_map(&:inbox).map(&:id)
      EmailMessage.where(mailbox_id: inbox_ids, scan_status: nil).order(:id)
    end

    def quarantine(message, virus)
      account = message.mailbox.email_account
      mailbox = account.quarantine_mailbox
      message.update!(mailbox: mailbox, uid: mailbox.claim_uid!, scan_status: "infected", virus_name: virus)
      Rails.logger.warn "[mail_on_rails] late scan quarantined report message #{message.id} for #{account.email} (#{virus})"
    end
  end
end
