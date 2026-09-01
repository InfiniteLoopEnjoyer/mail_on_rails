# Parses the ARF complaint report delivered to a domain's fbl@ account
# (or its jmrp@ alias - see MailroomMailbox) and suppresses future
# outbound mail to each complainant. Runs after delivery so a malformed
# report never delays or bounces mail - the raw message stays in the
# mailbox either way.
#
# Only trusted reporters are parsed: the report mail must itself pass
# DMARC AND come from a From: domain on report_reporter_allowlist (real
# FBL providers like Microsoft sign their reports). A bare DMARC pass is
# not enough - anyone can pass DMARC for their own domain and mail a
# well-formed fake ARF to fbl@, and without the allowlist that would
# suppress delivery to an arbitrary address (audit H1). A report from an
# untrusted domain stays in the mailbox; only the suppression is skipped.
module MailOnRails
  class IngestFblReportJob < BaseJob
    queue_as :default

    discard_on ActiveJob::DeserializationError

    def perform(email_message)
      if (reason = report_reporter_untrusted_reason(email_message))
        Rails.logger.warn "[mail_on_rails] FBL report from #{email_message.from_address.inspect} " \
                          "not ingested: #{reason}"
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
