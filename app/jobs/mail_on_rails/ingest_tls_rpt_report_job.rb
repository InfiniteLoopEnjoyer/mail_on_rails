# Parses the TLS-RPT aggregate report(s) attached to a message delivered
# to a domain's tls-rpt@ ingestion account (see MailroomMailbox). Runs
# after delivery so a malformed report never delays or bounces mail -
# the raw message stays in the mailbox either way.
#
# Only verified senders are parsed: the report mail itself must have
# passed DMARC (real reporters like Google/Microsoft sign their reports)
# or come from an authenticated local submitter. Anyone can mail a
# well-formed fake report to tls-rpt@ - without this gate they could
# fabricate TLS failures and send an admin chasing a downgrade attack
# that never happened (or bury a real one under noise).
module MailOnRails
  class IngestTlsRptReportJob < BaseJob
    queue_as :default

    discard_on ActiveJob::DeserializationError

    def perform(email_message)
      unless email_message.sender_verified?
        Rails.logger.warn "[mail_on_rails] tls-rpt report from #{email_message.from_address.inspect} " \
                          "not ingested: sender unverified (report mail must itself pass DMARC)"
        return
      end

      mail = Mail.read_from_string(email_message.raw.to_s)
      ingested = payloads(mail).sum do |filename, bytes|
        TlsRptReportParser.ingest(bytes, filename: filename) || 0
      end
      return if ingested.positive?

      Rails.logger.info "[mail_on_rails] no tls-rpt report ingested from message #{email_message.id} " \
                        "(#{mail.subject.to_s.byteslice(0, 120).inspect})"
    end

    private

    # Attachments for multipart mail; for the single-part form some
    # reporters use, the whole decoded body is the payload. The parser
    # content-sniffs, so over-collecting here is harmless.
    def payloads(mail)
      if mail.multipart?
        mail.attachments.map { |part| [ part.filename, part.decoded ] }
      else
        [ [ mail.header[:content_disposition]&.filename, mail.decoded ] ]
      end
    end
  end
end
