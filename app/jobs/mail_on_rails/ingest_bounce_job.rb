# Processes mail delivered to a domain's bounce@ account - asynchronous
# bounces coming back to the VERP return paths outbound list mail went
# out under (VerpAddress). The signed sub-address in X-Original-To names
# the exact SmtpOutboundMessage, so no bounce-body heuristics are needed
# for attribution; the body only decides *severity*. Deliberately
# strict: only an RFC 3464 delivery-status part reporting a failed 5.x.x
# recipient suppresses (sender-scoped, like unsubscribes) - transient
# 4.x.x delays, out-of-office autoreplies, and anything unparseable are
# logged and left alone, because a vacation reply to the return path
# must never kill a subscription. Runs after delivery, so the raw bounce
# stays inspectable in the bounce@ mailbox either way.
module MailOnRails
  class IngestBounceJob < BaseJob
    queue_as :default

    discard_on ActiveJob::DeserializationError

    def perform(email_message)
      raw = email_message.raw.to_s
      outbound = verp_message(raw)
      unless outbound
        Rails.logger.info "[mail_on_rails] bounce mail #{email_message.id} carried no valid VERP recipient - ignored"
        return
      end

      verdict = classify(raw)
      case verdict[:kind]
      when :hard
        record = SuppressedRecipient.record_bounce!(outbound.recipient, sender: outbound.mail_from,
                                                    reporter: verdict[:reporter] || "verp")
        Rails.logger.warn "[mail_on_rails] VERP hard bounce (#{verdict[:status]}) for outbound #{outbound.id}: " \
                          "suppressed <#{record.email}> from <#{record.sender}>"
      when :transient
        Rails.logger.info "[mail_on_rails] VERP transient bounce (#{verdict[:status]}) for outbound " \
                          "#{outbound.id} to <#{outbound.recipient}> - not suppressed"
      else
        Rails.logger.info "[mail_on_rails] mail to VERP address for outbound #{outbound.id} is not a " \
                          "delivery-status report (autoreply?) - ignored"
      end
    end

    private

    # The stamped envelope recipients are authoritative (X-Original-To,
    # from the edge); the first valid VERP sub-address wins.
    def verp_message(raw)
      mail = Mail.read_from_string(raw)
      mail.header.fields.select { |f| f.name.casecmp?("X-Original-To") }
          .filter_map { |f| VerpAddress.decode(f.value.to_s.strip) }
          .first
    rescue StandardError
      nil
    end

    # { kind: :hard/:transient/:other, status:, reporter: } from the RFC
    # 3464 delivery-status part, when there is one.
    def classify(raw)
      mail = Mail.read_from_string(raw)
      part = ([ mail ] + mail.all_parts).find { |p| p.mime_type == "message/delivery-status" }
      return { kind: :other } unless part

      fields = part.body.decoded
      action = fields[/^Action:\s*([\w-]+)/i, 1]&.downcase
      status = fields[/^Status:\s*(\d\.\d{1,3}\.\d{1,3})/i, 1]
      reporter = fields[/^Reporting-MTA:\s*[^;]+;\s*(\S+)/i, 1]
      return { kind: :other } unless status

      hard = status.start_with?("5") && [ nil, "failed" ].include?(action)
      { kind: hard ? :hard : :transient, status: status, reporter: reporter }
    rescue StandardError
      { kind: :other }
    end
  end
end
