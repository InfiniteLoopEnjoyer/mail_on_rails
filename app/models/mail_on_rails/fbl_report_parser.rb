# Turns one ARF complaint report (RFC 5965 - the format provider feedback
# loops like Microsoft's JMRP send) into the complained-about recipient
# addresses. A report is a multipart/report with a machine-readable
# message/feedback-report part and (usually) the original message
# attached; the complainant is taken from, in order of preference:
#   1. the report part's Original-Rcpt-To field(s),
#   2. the X-HmXmrOriginalRecipient header Microsoft stamps on the
#      attached original (JMRP omits Original-Rcpt-To),
#   3. the attached original's To addresses (last resort).
# Payloads without a feedback-report part aren't complaints and return
# nil, never raise - parsing runs against whatever lands in an fbl@
# mailbox.
module MailOnRails
  class FblReportParser
    # One complaint concerns one delivery; a report naming dozens of
    # recipients is malformed or hostile, and must not be able to
    # suppress an unbounded set of addresses.
    MAX_COMPLAINANTS = 10
    # Enough for any real address (RFC 5321 caps a path at 256), tight
    # enough that a hostile-but-verified reporter can't store junk.
    MAX_ADDRESS_LENGTH = 254
    ADDRESS = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/

    Report = Struct.new(:feedback_type, :user_agent, :complainants, keyword_init: true)

    def self.parse(raw)
      new(raw).parse
    end

    def initialize(raw)
      @raw = raw.to_s
    end

    # Returns a Report, or nil when the message is not an ARF complaint
    # (or names no usable complainant).
    def parse
      mail = Mail.read_from_string(@raw)
      report_fields = feedback_report_fields(mail)
      return nil if report_fields.nil?

      original = original_message(mail)
      complainants = extract_complainants(report_fields, original)
      return nil if complainants.empty?

      Report.new(feedback_type: field_value(report_fields, "Feedback-Type")&.downcase,
                 user_agent: field_value(report_fields, "User-Agent"),
                 complainants: complainants)
    rescue StandardError => e
      Rails.logger.warn "[mail_on_rails] ARF parse failed: #{e.class}: #{e.message}"
      nil
    end

    private

    # The machine-readable part's fields, parsed with the header parser
    # (the part body is header syntax per RFC 5965 s3); nil when the
    # message has no feedback-report part - i.e. is not ARF.
    def feedback_report_fields(mail)
      part = ([ mail ] + mail.all_parts).find { |candidate| candidate.mime_type == "message/feedback-report" }
      Mail::Header.new(part.body.decoded).fields if part
    end

    def original_message(mail)
      part = mail.all_parts.find { |candidate| %w[message/rfc822 text/rfc822-headers].include?(candidate.mime_type) }
      Mail.read_from_string(part.body.decoded) if part
    end

    def extract_complainants(report_fields, original)
      addresses = field_values(report_fields, "Original-Rcpt-To")
      addresses = header_values(original, "X-HmXmrOriginalRecipient") if addresses.empty? && original
      addresses = Array(original.to) if addresses.empty? && original
      addresses.filter_map { |address| clean_address(address) }
               .uniq.first(MAX_COMPLAINANTS)
    end

    # Field values arrive as "user@host" or "<user@host>" (some reporters
    # send a full name-addr); anything that doesn't reduce to one valid
    # address is dropped rather than guessed at.
    def clean_address(value)
      address = value.to_s[/<([^<>]+)>/, 1] || value.to_s
      address = address.strip.downcase
      address if address.length <= MAX_ADDRESS_LENGTH && address.match?(ADDRESS)
    end

    def field_values(fields, name)
      fields.select { |field| field.name.casecmp?(name) }.map { |field| field.value.to_s }
    end

    def field_value(fields, name)
      field_values(fields, name).first&.strip&.byteslice(0, 200)
    end

    def header_values(message, name)
      message.header.fields.select { |field| field.name.casecmp?(name) }.map { |field| field.value.to_s }
    end
  end
end
