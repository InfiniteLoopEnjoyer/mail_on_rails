# Parses the DMARC aggregate report(s) attached to a message delivered to
# a domain's dmarc@ ingestion account (see MailroomMailbox). Runs after
# delivery so a malformed report never delays or bounces mail - the raw
# message stays in the mailbox either way.
class IngestDmarcReportJob < ApplicationJob
  queue_as :default

  discard_on ActiveJob::DeserializationError

  def perform(email_message)
    mail = Mail.read_from_string(email_message.raw.to_s)
    ingested = payloads(mail).sum do |filename, bytes|
      DmarcReportParser.ingest(bytes, filename: filename) || 0
    end
    return if ingested.positive?

    Rails.logger.info "[mail_on_rails] no dmarc report ingested from message #{email_message.id} " \
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
