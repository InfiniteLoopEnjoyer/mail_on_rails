# Builds RFC 3464 delivery status notifications for one outbound queue
# row: the multipart/report (delivery-status) structure that mail clients
# and automated tooling parse, replacing free-text bounce notes. Three
# kinds, matching the sender's RFC 3461 NOTIFY request (or its defaults):
#
#   failure - the message was permanently rejected or retries exhausted;
#   delayed - still queued past the smtp_delay_warning_seconds threshold;
#   success - final delivery ("delivered") or handoff to a next hop that
#             could not take over DSN responsibility ("relayed").
#
# The report is a Mail object; the caller delivers it (locally, into the
# author's INBOX - our senders are always local accounts, so no DSN ever
# rides the outbound path and none can backscatter). Structure:
#
#   text/plain               - the human explanation
#   message/delivery-status  - per-message and per-recipient fields
#   message/rfc822 or text/rfc822-headers - the original (full content
#     only on failure of a RET=FULL request; headers otherwise, RFC 3464
#     section 3)
module MailOnRails
  class DeliveryStatusNotification
    HEADER_SAMPLE_BYTES = 8_192

    def self.failure(message:, error:)
      new(message).build(action: "failed", error: error,
                         subject: "Undelivered Mail Returned to Sender",
                         explanation: "could not be delivered after #{message.attempts} attempt(s). " \
                                      "Delivery has been abandoned.")
    end

    def self.delayed(message:, error:)
      new(message).build(action: "delayed", error: error,
                         subject: "Delayed Mail (still being retried)",
                         explanation: "has not been delivered yet. Delivery keeps being retried; you do " \
                                      "not need to resend the message. If it cannot be delivered by " \
                                      "#{message.retry_deadline.rfc2822}, it will be returned to you.")
    end

    # +action+ is "delivered" when this host made the final delivery,
    # "relayed" when it handed off to a hop that could not take over the
    # DSN request (RFC 3464 2.3.3).
    def self.success(message:, action: "relayed")
      new(message).build(action: action, subject: "Successful Mail Delivery Report",
                         explanation: action == "relayed" ? "was relayed toward the recipient. The next " \
                                      "mail system accepted responsibility for it but cannot confirm final " \
                                      "delivery." : "was successfully delivered.")
    end

    def initialize(message)
      @message = message
    end

    def build(action:, subject:, explanation:, error: nil)
      notice = Mail.new
      notice.from    = "Mail Delivery System <mailer-daemon@#{sender_domain}>"
      notice.to      = @message.mail_from
      notice.subject = subject
      notice.date    = Time.current
      notice.header["Auto-Submitted"] = "auto-generated"

      notice.add_part(Mail::Part.new.tap do |part|
        part.content_type = "text/plain; charset=utf-8"
        part.body = human_text(action, explanation, error)
      end)
      notice.add_part(Mail::Part.new.tap do |part|
        part.content_type = "message/delivery-status"
        part.body = status_fields(action, error)
      end)
      notice.add_part(original_part(action))
      notice.content_type = "multipart/report; report-type=delivery-status; boundary=#{notice.boundary}"
      notice
    end

    private

    def sender_domain
      @message.mail_from.to_s.split("@").last.presence || Setting.effective_smtp_helo_hostname
    end

    def human_text(action, explanation, error)
      text = +"This is the mail system at #{Setting.effective_smtp_helo_hostname}.\n\n" \
              "Your message to <#{@message.recipient}> #{explanation}\n"
      text << "\nReason:\n  #{single_line(error)}\n" if error
      text
    end

    # RFC 3464 section 2: one per-message field group, then one
    # per-recipient group (this queue holds one recipient per row).
    def status_fields(action, error)
      fields = [ "Reporting-MTA: dns; #{Setting.effective_smtp_helo_hostname}" ]
      fields << "Original-Envelope-Id: #{xtext_decode(@message.dsn_envid)}" if @message.dsn_envid.present?
      fields << "Arrival-Date: #{(@message.created_at || Time.current).rfc2822}"
      fields << ""
      fields << "Original-Recipient: #{xtext_decode(@message.dsn_orcpt)}" if @message.dsn_orcpt.present?
      fields << "Final-Recipient: rfc822; #{@message.recipient}"
      fields << "Action: #{action}"
      fields << "Status: #{status_code(action, error)}"
      fields << "Diagnostic-Code: smtp; #{single_line(error)}" if error
      fields << "Last-Attempt-Date: #{Time.current.rfc2822}"
      fields << "Will-Retry-Until: #{@message.retry_deadline.rfc2822}" if action == "delayed"
      fields.join("\r\n") + "\r\n"
    end

    # The enhanced status code out of the stored SMTP error when the
    # remote server gave one, else the action's generic class.
    def status_code(action, error)
      explicit = error.to_s[/\b([245]\.\d{1,3}\.\d{1,3})\b/, 1]
      generic = { "failed" => "5.0.0", "delayed" => "4.0.0" }.fetch(action, "2.0.0")
      # A stale code of the wrong class (a 4.x.x diagnostic on a now-final
      # failure) would misstate the verdict; only keep a matching one.
      explicit&.start_with?(generic[0]) ? explicit : generic
    end

    # Full content only when a failure returns a RET=FULL request; headers
    # otherwise (RFC 3464 section 3 - and returning megabytes of body on a
    # delay warning would double the queue's storage cost for no signal).
    def original_part(action)
      Mail::Part.new.tap do |part|
        if action == "failed" && @message.dsn_ret == "FULL"
          part.content_type = "message/rfc822"
          part.body = @message.data.to_s
        else
          part.content_type = "text/rfc822-headers"
          part.body = @message.data.to_s.b.partition(/\r?\n\r?\n/).first.byteslice(0, HEADER_SAMPLE_BYTES)
        end
      end
    end

    # RFC 3461 xtext escaping undone (+XX hex escapes).
    def xtext_decode(value)
      value.to_s.gsub(/\+([0-9A-F]{2})/) { Regexp.last_match(1).hex.chr }
    end

    # Stored errors can span lines; a delivery-status field cannot.
    def single_line(error)
      error.to_s.gsub(/\s+/, " ").strip
    end
  end
end
