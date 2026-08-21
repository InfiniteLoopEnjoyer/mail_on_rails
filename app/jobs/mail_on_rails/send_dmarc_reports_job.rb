require "zlib"
require "securerandom"
require "mail_on_rails/smtp/sender_auth/dns"
require "mail_on_rails/smtp/sender_auth/dmarc"

# Rolls the previous day's DmarcAggregateEvents up into RFC 7489
# aggregate XML reports and mails one to every policy domain that asks
# for them (rua= mailto addresses on its _dmarc record) - the sending
# side of the DMARC feedback loop, twin of SendTlsRptReportsJob and the
# counterpart of the dmarc@ ingestion we host for our own domains. Runs
# daily from config/recurring.yml; a domain with no rua simply keeps
# accumulating (and eventually pruning) events.
module MailOnRails
  class SendDmarcReportsJob < BaseJob
    queue_as :default

    # RFC 7489 6.2: dkim/spf result tokens the schema allows.
    DKIM_RESULTS = %w[none pass fail policy neutral temperror permerror].freeze
    SPF_RESULTS = %w[none neutral pass fail softfail temperror permerror].freeze

    def perform(date = Date.yesterday)
      return unless MailOnRails::Settings[:smtp_dmarc_reports]

      DmarcAggregateEvent.on_day(date).distinct.pluck(:policy_domain).each do |domain|
        send_report(domain, date)
      rescue StandardError => e
        Rails.logger.error "[mail_on_rails] DMARC report for #{domain} failed: #{e.class}: #{e.message}"
      end
    end

    private

    def send_report(domain, date)
      recipients = rua_addresses(domain)
      return if recipients.empty?

      events = DmarcAggregateEvent.on_day(date).where(policy_domain: domain).to_a
      return if events.empty?

      report_id = "#{date.beginning_of_day.to_i}.#{domain}.#{SecureRandom.hex(6)}"
      raw = build_mail(domain, date, report_id, build_report(domain, date, report_id, events))
      recipients.each do |recipient|
        SmtpOutboundMessage.create!(mail_from: from_address, recipient: recipient,
                                    data: raw, next_attempt_at: Time.current)
      end
      Rails.logger.info "[mail_on_rails] DMARC report for #{domain} queued to #{recipients.join(", ")}"
    end

    # mailto: destinations from the domain's own DMARC record (the same
    # 0-or-1-record rule the verifier applies). URI size suffixes
    # ("mailto:a@x!10m") are stripped; https destinations are not
    # supported. External destinations - a rua host outside the policy
    # domain's organization - must publish the RFC 7489 7.1 authorization
    # record or they are skipped (anti-report-bombing). DNS trouble skips
    # the domain; the events stay put and tomorrow's run may reach it.
    def rua_addresses(domain)
      records = dns.txt("_dmarc.#{domain}").select { |t| t.match?(/\Av=DMARC1(\s*;|\s*\z)/i) }
      return [] unless records.size == 1

      rua = records.first[/;\s*rua\s*=\s*([^;]+)/, 1].to_s
      rua.split(",").filter_map { |uri| uri.strip[/\Amailto:([^!,\s]+)/i, 1] }
         .first(3)
         .select { |recipient| authorized_destination?(domain, recipient) }
    rescue MailOnRails::Smtp::SenderAuth::Dns::TempError
      []
    end

    def authorized_destination?(policy_domain, recipient)
      dest = recipient.split("@").last.to_s.downcase
      return false if dest.empty?

      org = ->(d) { Smtp::SenderAuth::Dmarc.org_domain(d) }
      return true if org.call(dest) == org.call(policy_domain)

      dns.txt("#{policy_domain}._report._dmarc.#{dest}").any? { |t| t.match?(/\Av=DMARC1\b/i) }
    rescue MailOnRails::Smtp::SenderAuth::Dns::TempError
      false
    end

    # RFC 7489 Appendix C feedback document. policy_published comes from
    # the newest event - what we actually evaluated against, not a fresh
    # lookup that may already differ.
    def build_report(domain, date, report_id, events)
      latest = events.max_by(&:occurred_at)
      xml = +%(<?xml version="1.0" encoding="UTF-8"?>\n<feedback>\n)
      xml << "  <report_metadata>\n"
      xml << "    <org_name>#{x(submitter)}</org_name>\n"
      xml << "    <email>#{x(from_address)}</email>\n"
      xml << "    <report_id>#{x(report_id)}</report_id>\n"
      xml << "    <date_range><begin>#{date.beginning_of_day.to_i}</begin>" \
             "<end>#{date.end_of_day.to_i}</end></date_range>\n"
      xml << "  </report_metadata>\n"
      xml << "  <policy_published>\n"
      xml << "    <domain>#{x(domain)}</domain>\n"
      xml << "    <adkim>#{x(latest.policy_adkim.presence || "r")}</adkim>\n"
      xml << "    <aspf>#{x(latest.policy_aspf.presence || "r")}</aspf>\n"
      xml << "    <p>#{x(latest.policy_p.presence || "none")}</p>\n"
      xml << "    <sp>#{x(latest.policy_sp)}</sp>\n" if latest.policy_sp.present?
      xml << "    <pct>#{latest.policy_pct || 100}</pct>\n"
      xml << "  </policy_published>\n"
      rows(events).each { |event, count| xml << record_xml(event, count) }
      xml << "</feedback>\n"
    end

    # One <record> per distinct evaluation shape; identical messages from
    # the same source collapse into a count.
    def rows(events)
      events.group_by do |e|
        [ e.source_ip, e.disposition, e.dkim_aligned, e.spf_aligned, e.override_reason,
          e.from_domain, e.envelope_from, e.spf_result, e.spf_domain, e.dkim_results ]
      end.map { |_key, group| [ group.first, group.size ] }
    end

    def record_xml(event, count)
      xml = +"  <record>\n"
      xml << "    <row>\n"
      xml << "      <source_ip>#{x(event.source_ip)}</source_ip>\n"
      xml << "      <count>#{count}</count>\n"
      xml << "      <policy_evaluated>\n"
      xml << "        <disposition>#{x(event.disposition)}</disposition>\n"
      xml << "        <dkim>#{event.dkim_aligned? ? "pass" : "fail"}</dkim>\n"
      xml << "        <spf>#{event.spf_aligned? ? "pass" : "fail"}</spf>\n"
      if event.override_reason.present?
        xml << "        <reason><type>local_policy</type>" \
               "<comment>#{x(event.override_reason)}</comment></reason>\n"
      end
      xml << "      </policy_evaluated>\n"
      xml << "    </row>\n"
      xml << "    <identifiers>\n"
      if (envelope = event.envelope_from.to_s.split("@").last.to_s.downcase).present?
        xml << "      <envelope_from>#{x(envelope)}</envelope_from>\n"
      end
      xml << "      <header_from>#{x(event.from_domain.presence || event.policy_domain)}</header_from>\n"
      xml << "    </identifiers>\n"
      xml << "    <auth_results>\n"
      dkim_entries(event).each do |dkim_domain, result|
        xml << "      <dkim><domain>#{x(dkim_domain)}</domain><result>#{x(result)}</result></dkim>\n"
      end
      if event.spf_result.present?
        result = SPF_RESULTS.include?(event.spf_result) ? event.spf_result : "neutral"
        xml << "      <spf><domain>#{x(event.spf_domain.presence || event.policy_domain)}</domain>" \
               "<result>#{x(result)}</result></spf>\n"
      end
      xml << "    </auth_results>\n"
      xml << "  </record>\n"
    end

    # The compact "domain=result,..." column back into pairs, results
    # clamped to the schema's token set.
    def dkim_entries(event)
      event.dkim_results.to_s.split(",").filter_map do |entry|
        dkim_domain, result = entry.split("=", 2)
        next if dkim_domain.blank?

        [ dkim_domain, DKIM_RESULTS.include?(result.to_s) ? result : "neutral" ]
      end
    end

    def x(value)
      value.to_s.encode(xml: :text)
    end

    def build_mail(domain, date, report_id, xml)
      filename = "#{submitter}!#{domain}!#{date.beginning_of_day.to_i}!#{date.end_of_day.to_i}.xml.gz"
      mail = Mail.new
      mail.from    = from_address
      mail.subject = "Report Domain: #{domain} Submitter: #{submitter} Report-ID: <#{report_id}>"
      mail.date    = Time.current
      mail.header["Auto-Submitted"] = "auto-generated"
      mail.text_part = Mail::Part.new(body: "This is a DMARC aggregate report from #{submitter} for #{domain}.\n")
      mail.attachments[filename] = { mime_type: "application/gzip", content: Zlib.gzip(xml) }
      mail.to_s
    end

    # Reports come from the dmarc@ mailbox of our primary hosted domain,
    # so replies and bounces land in an account that exists.
    def from_address
      "#{Domain::DMARC_LOCAL_PART}@#{report_domain}"
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
