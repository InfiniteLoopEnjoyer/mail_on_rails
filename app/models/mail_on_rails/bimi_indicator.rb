require "mail_on_rails/smtp/sender_auth/dns"
require "mail_on_rails/smtp/sender_auth/dmarc"

# Receiver-side BIMI (Brand Indicators for Message Identification): the
# per-sender-domain cache of "may we show this domain's logo, and what
# is it". RefreshBimiIndicatorJob evaluates a domain - DMARC gate, then
# the default._bimi TXT, then a guarded fetch and strict sanitization of
# the l= SVG - and the webmail shows the cached logo next to messages
# from that domain that themselves passed DMARC.
#
# Self-asserted BIMI is accepted deliberately (the a= VMC/CMC evidence
# is recorded but not validated): the DMARC-enforcement gate plus the
# per-message dmarc=pass gate is what prevents spoofed logos, and a
# certificate mandate would just hide the logos of every small sender.
# Statuses: pending (never evaluated), pass (logo cached), none (no BIMI
# record), declined (record with an empty l= - the domain opted out),
# fail (gate/fetch/sanitization failure; error says why).
module MailOnRails
  class BimiIndicator < Record
    REFRESH_INTERVAL = 24.hours
    RETENTION = 90.days # rows for domains we no longer hear from

    normalizes :domain, with: ->(domain) { domain.to_s.strip.downcase }

    validates :domain, presence: true, uniqueness: true

    scope :stale, -> { where(checked_at: nil).or(where(checked_at: ...REFRESH_INTERVAL.ago)) }

    def pass? = status == "pass"

    def displayable? = pass? && svg.present?

    # The cached indicator for a message the webmail may decorate, or nil.
    # Only messages that themselves passed DMARC qualify - BIMI's whole
    # promise is "this logo cannot be spoofed", so an unauthenticated
    # message must never borrow it. A missing/stale row enqueues a
    # refresh and shows nothing (or the stale logo) meanwhile.
    def self.for_message(email_message)
      return nil unless MailOnRails::Settings[:bimi]
      return nil unless email_message.auth_result("dmarc") == "pass"

      domain = email_message.from_address.to_s.split("@").last.to_s.strip.downcase
      return nil if domain.empty?

      row = lookup(domain)
      row if row&.displayable?
    end

    # The cached row (possibly stale - yesterday's logo beats a blank
    # while the refresh runs); enqueues a refresh when due. The pending
    # row is created first so racing readers enqueue at most a handful of
    # duplicate jobs, which the job's own freshness check absorbs.
    def self.lookup(domain)
      row = find_or_create_by!(domain: domain)
      RefreshBimiIndicatorJob.perform_later(domain) if row.checked_at.nil? || row.checked_at < REFRESH_INTERVAL.ago
      row
    rescue ActiveRecord::RecordNotUnique
      retry
    rescue StandardError => e
      Rails.logger.error "[mail_on_rails] BIMI lookup for #{domain} failed: #{e.class}: #{e.message}"
      nil
    end

    # The full evaluation, persisted. Injectable DNS/fetcher for tests.
    def self.refresh!(domain, dns: MailOnRails::Smtp::SenderAuth::Dns.shared, fetcher: BimiFetcher)
      row = find_or_create_by!(domain: domain)
      attributes = evaluate(row.domain, dns: dns, fetcher: fetcher)
      row.update!(attributes.merge(checked_at: Time.current))
      row
    rescue ActiveRecord::RecordNotUnique
      retry
    end

    def self.evaluate(domain, dns:, fetcher:)
      unless dmarc_enforced?(domain, dns)
        return { status: "fail", svg: nil, error: "sender domain does not enforce DMARC (BIMI requires p=quarantine pct=100 or p=reject)" }
      end

      record = bimi_record(domain, dns)
      return { status: "none", svg: nil, error: nil } unless record

      tags = parse_tags(record)
      location = tags["l"].to_s.strip
      return { status: "declined", svg: nil, error: nil } if location.empty?

      svg = BimiSvg.sanitize(fetcher.fetch(location))
      { status: "pass", svg: svg, evidence: tags["a"].to_s.strip.present?, error: nil }
    rescue BimiFetcher::Error, BimiSvg::Invalid => e
      { status: "fail", svg: nil, error: e.message.to_s.truncate(200) }
    rescue MailOnRails::Smtp::SenderAuth::Dns::TempError => e
      # DNS trouble is not a verdict: keep whatever we had, try again later.
      { error: "DNS: #{e.message.to_s.truncate(180)}" }
    end

    # The BIMI prerequisite (and its anti-spoofing teeth): the domain's
    # effective DMARC policy must be enforcing - quarantine at pct=100, or
    # reject. Same record-discovery walk as DMARC itself (the domain,
    # then its organizational domain, whose sp= then governs).
    def self.dmarc_enforced?(domain, dns)
      org = MailOnRails::Smtp::SenderAuth::Dmarc.org_domain(domain)
      record = dmarc_txt(domain, dns)
      policy_tag = "p"
      if record.nil? && org != domain
        record = dmarc_txt(org, dns)
        policy_tag = "sp" if record && parse_tags(record)["sp"]
      end
      return false unless record

      tags = parse_tags(record)
      policy = tags[policy_tag] || tags["p"]
      pct = Integer(tags.fetch("pct", "100"), exception: false) || 100
      policy == "reject" || (policy == "quarantine" && pct == 100)
    end

    def self.dmarc_txt(domain, dns)
      records = dns.txt("_dmarc.#{domain}").select { |t| t.match?(/\Av=DMARC1(\s*;|\s*\z)/i) }
      records.size == 1 ? records.first : nil
    end

    # default._bimi at the domain, falling back to its org domain - the
    # BIMI assertion record discovery.
    def self.bimi_record(domain, dns)
      [ domain, MailOnRails::Smtp::SenderAuth::Dmarc.org_domain(domain) ].uniq.each do |candidate|
        records = dns.txt("default._bimi.#{candidate}").select { |t| t.match?(/\Av=BIMI1(\s*;|\s*\z)/i) }
        return records.first if records.size == 1
      end
      nil
    end

    def self.parse_tags(record)
      record.split(";").each_with_object({}) do |pair, tags|
        name, value = pair.split("=", 2)
        tags[name.strip.downcase] = value.strip if value
      end
    end

    # Correspondents come and go; rows nobody refreshed in RETENTION are
    # domains the webmail stopped asking about.
    def self.prune!(now: Time.current)
      where(checked_at: ..(now - RETENTION)).delete_all
    end
  end
end
