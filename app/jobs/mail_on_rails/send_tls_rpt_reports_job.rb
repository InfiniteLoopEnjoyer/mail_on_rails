require "zlib"
require "securerandom"
require "mail_on_rails/smtp/sender_auth/dns"

# Rolls the previous day's TlsRptEvents up into RFC 8460 aggregate
# reports and mails one to every recipient domain that publishes a
# TLS-RPT policy (_smtp._tls TXT with a mailto rua) - the sending-side
# counterpart of the tls-rpt@ mailbox we host for our own domains. Runs
# daily from config/recurring.yml; a domain with no TLSRPT record simply
# keeps accumulating (and eventually pruning) events.
module MailOnRails
  class SendTlsRptReportsJob < BaseJob
    queue_as :default

    def perform(date = Date.yesterday)
      TlsRptEvent.on_day(date).distinct.pluck(:policy_domain).each do |domain|
        send_report(domain, date)
      rescue StandardError => e
        Rails.logger.error "[mail_on_rails] TLS-RPT report for #{domain} failed: #{e.class}: #{e.message}"
      end
    end

    private

    def send_report(domain, date)
      recipients = rua_addresses(domain)
      return if recipients.empty?

      events = TlsRptEvent.on_day(date).where(policy_domain: domain).to_a
      return if events.empty?

      report_id = "#{date.beginning_of_day.to_i}.#{domain}.#{SecureRandom.hex(6)}@#{submitter}"
      raw = build_mail(domain, date, report_id, build_report(domain, date, report_id, events))
      recipients.each do |recipient|
        SmtpOutboundMessage.create!(mail_from: from_address, recipient: recipient,
                                    data: raw, next_attempt_at: Time.current)
      end
      Rails.logger.info "[mail_on_rails] TLS-RPT report for #{domain} queued to #{recipients.join(", ")}"
    end

    # mailto: destinations from the domain's TLSRPT record (RFC 8460
    # section 3): "v=TLSRPTv1; rua=mailto:a@x,mailto:b@y". https
    # destinations are not supported. DNS trouble skips the domain - the
    # events stay put and tomorrow's run may reach it.
    def rua_addresses(domain)
      records = dns.txt("_smtp._tls.#{domain}").select { |t| t.strip.start_with?("v=TLSRPTv1") }
      return [] unless records.size == 1

      rua = records.first[/;\s*rua\s*=\s*([^;]+)/, 1].to_s
      rua.split(",").filter_map { |uri| uri.strip[/\Amailto:(.+)\z/, 1] }.first(3)
    rescue MailOnRails::Smtp::SenderAuth::Dns::TempError
      []
    end

    def build_report(domain, date, report_id, events)
      {
        "organization-name" => submitter,
        "date-range" => {
          "start-datetime" => date.beginning_of_day.utc.iso8601,
          "end-datetime" => date.end_of_day.utc.change(usec: 0).iso8601
        },
        "contact-info" => "postmaster@#{report_domain}",
        "report-id" => report_id,
        "policies" => events.group_by(&:policy_type).map do |type, group|
          policy_block(domain, type, group)
        end
      }.to_json
    end

    def policy_block(domain, type, events)
      successes, failures = events.partition { |e| e.result_type.nil? }
      policy = { "policy-type" => type, "policy-domain" => domain }
      if type == "sts" && (sts = MtaStsPolicy.find_by(domain: domain))
        policy["policy-string"] = sts.policy_lines
      end

      block = {
        "policy" => policy,
        "summary" => {
          "total-successful-session-count" => successes.size,
          "total-failure-session-count" => failures.size
        }
      }
      if failures.any?
        block["failure-details"] = failures.group_by { |e| [ e.result_type, e.receiving_mx, e.failure_detail ] }
                                           .map do |(result, mx, detail), group|
          entry = { "result-type" => result, "failed-session-count" => group.size }
          entry["receiving-mx-hostname"] = mx if mx.present?
          entry["failure-reason-code"] = detail if detail.present?
          entry
        end
      end
      block
    end

    def build_mail(domain, date, report_id, json)
      filename = "#{submitter}!#{domain}!#{date.beginning_of_day.to_i}!#{date.end_of_day.to_i}.json.gz"
      mail = Mail.new
      mail.from    = from_address
      mail.subject = "Report Domain: #{domain} Submitter: #{submitter} Report-ID: <#{report_id}>"
      mail.date    = Time.current
      mail.header["TLS-Report-Domain"]    = domain
      mail.header["TLS-Report-Submitter"] = submitter
      mail.header["Auto-Submitted"]       = "auto-generated"
      # RFC 8460 4.1: a report about a broken TLS policy must still get
      # through - RFC 8689's escape hatch tells the deliverer to skip
      # DANE/MTA-STS/verified-TLS enforcement for this one message.
      mail.header["TLS-Required"]         = "No"
      mail.text_part = Mail::Part.new(body: "This is an aggregate TLS report from #{submitter} for #{domain}.\n")
      mail.attachments[filename] = { mime_type: "application/tlsrpt+gzip", content: Zlib.gzip(json) }
      mail.to_s
    end

    # Reports come from the tls-rpt@ mailbox of our primary hosted domain,
    # so replies and bounces land in an account that exists.
    def from_address
      "#{Domain::TLS_RPT_LOCAL_PART}@#{report_domain}"
    end

    def report_domain
      @report_domain ||= Domain.order(:id).first&.name || Setting.effective_smtp_helo_hostname
    end

    def submitter
      report_domain
    end

    def dns
      MailOnRails::Smtp::SenderAuth::Dns.shared
    end
  end
end
