# Parses the ARF complaint report delivered to a domain's fbl@ account
# (or its jmrp@ alias - see MailroomMailbox) and suppresses future
# outbound mail to each complainant. Runs after delivery so a malformed
# report never delays or bounces mail - the raw message stays in the
# mailbox either way.
#
# Only verified senders are parsed: the report mail itself must have
# passed DMARC (real FBL providers like Microsoft sign their reports) or
# come from an authenticated local submitter. Anyone can mail a
# well-formed fake ARF report to fbl@ - without this gate they could
# suppress delivery to an arbitrary address.
module MailOnRails
  class IngestFblReportJob < BaseJob
    queue_as :default

    discard_on ActiveJob::DeserializationError

    def perform(email_message)
      unless email_message.sender_verified?
        Rails.logger.warn "[mail_on_rails] FBL report from #{email_message.from_address.inspect} " \
                          "not ingested: sender unverified (report mail must itself pass DMARC)"
        return
      end

      report = FblReportParser.parse(email_message.raw.to_s)
      unless report
        Rails.logger.info "[mail_on_rails] no ARF complaint ingested from message #{email_message.id}"
        return
      end

      report.complainants.each do |address|
        # A complaint names the remote recipient of mail we sent; an
        # address in a hosted domain here means a confused (or hostile)
        # report, and suppressing local delivery is never the feature.
        if Domain.exists?(name: address.partition("@").last)
          Rails.logger.warn "[mail_on_rails] FBL complaint names local address #{address}: not suppressed"
          next
        end

        record = SuppressedRecipient.record_complaint!(address, feedback_type: report.feedback_type,
                                                                reporter: report.user_agent)
        Rails.logger.warn "[mail_on_rails] FBL complaint (#{report.feedback_type}) suppressed <#{address}> " \
                          "(#{record.complaints_count} complaint(s))"
      end
    end
  end
end
