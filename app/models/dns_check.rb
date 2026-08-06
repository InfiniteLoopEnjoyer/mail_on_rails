require "resolv"

# Live DNS verification for a hosted domain - is what's actually
# published consistent with what the domain page prescribes? (Ported in
# spirit from Postal's has_dns_checks.) One check per record the page
# lists: MX points at us, an SPF record authorizes this server, the DKIM
# TXT matches the key on disk, a DMARC record exists.
#
# Statuses: :pass, :warn (published but we can't positively confirm it
# authorizes this server), :fail (missing or wrong), :unknown (DNS
# unreachable, or nothing local to compare against). Lookups run live on
# the admin domain page only, with short timeouts; the resolver is
# injectable for tests.
class DnsCheck
  Check = Struct.new(:record, :status, :found, :note, keyword_init: true)

  # Thin Resolv wrapper: nil on DNS failure (=> :unknown), lists otherwise.
  class Resolver
    TIMEOUT = 3

    def txt(name)
      query { |dns| dns.getresources(name, Resolv::DNS::Resource::IN::TXT).map { |r| r.strings.join } }
    end

    def mx(name)
      query { |dns| dns.getresources(name, Resolv::DNS::Resource::IN::MX).map { |r| [ r.preference, r.exchange.to_s.downcase.delete_suffix(".") ] } }
    end

    private

    def query
      Resolv::DNS.open do |dns|
        dns.timeouts = TIMEOUT
        yield dns
      end
    rescue Resolv::ResolvError, Resolv::ResolvTimeout
      nil
    end
  end

  def self.for(domain, resolver: Resolver.new)
    new(domain, resolver)
  end

  # Run the live checks and persist them onto the domain row - the cache
  # behind the index pills (Domain#cached_dns_checks). Refreshed hourly
  # for every domain by DnsCheckRefreshJob, and by each domain-page view.
  def self.refresh!(domain, resolver: Resolver.new)
    dns = new(domain, resolver)
    domain.update!(dns_checks: dns.checks.map(&:to_h), dns_checked_at: Time.current)
    dns
  end

  attr_reader :checks

  def initialize(domain, resolver)
    @domain = domain
    @resolver = resolver
    @checks = [ mx_check, spf_check, dkim_check, dmarc_check ]
  end

  # The published DMARC record, feeding Domain#dmarc_advice.
  attr_reader :dmarc_record

  private

  def mail_host
    Setting.smtp_helo_hostname
  end

  def mx_check
    return check("MX", :unknown, nil, "SMTP hostname is not set (Settings page or SMTP_HELO_HOST)") unless mail_host

    records = @resolver.mx(@domain.name)
    return check("MX", :unknown, nil, "DNS lookup failed") if records.nil?

    found = records.sort.map { |preference, exchange| "#{preference} #{exchange}" }.join(", ")
    if records.any? { |_, exchange| exchange == mail_host }
      check("MX", :pass, found)
    elsif records.empty?
      check("MX", :fail, nil, "no MX records published")
    else
      check("MX", :fail, found, "none of the MX hosts is #{mail_host}")
    end
  end

  def spf_check
    records = @resolver.txt(@domain.name)
    return check("SPF", :unknown, nil, "DNS lookup failed") if records.nil?

    spf = records.find { |r| r.match?(/\Av=spf1\b/i) }
    return check("SPF", :fail, nil, "no v=spf1 record published") unless spf

    tokens = spf.downcase.split
    if tokens.any? { |t| [ "mx", "+mx", "a:#{mail_host}" ].include?(t) }
      check("SPF", :pass, spf)
    else
      check("SPF", :warn, spf, "record exists but does not obviously authorize #{mail_host || "this server"} - verify its mechanisms")
    end
  end

  def dkim_check
    return check("DKIM", :unknown, nil, "no signing key on this server") if @domain.dkim_private_key.blank?

    records = @resolver.txt(@domain.dkim_txt_name)
    return check("DKIM", :unknown, nil, "DNS lookup failed") if records.nil?

    expected_p = @domain.dkim_txt_value[/p=([A-Za-z0-9+\/=]+)/, 1]
    published = records.find { |r| r.match?(/\Av=DKIM1\b/i) || r.include?("p=") }
    return check("DKIM", :fail, nil, "no TXT record at #{@domain.dkim_txt_name}") unless published

    published_p = published.gsub(/[\s"]/, "")[/p=([A-Za-z0-9+\/=]+)/, 1]
    if published_p == expected_p
      check("DKIM", :pass, "key matches")
    else
      check("DKIM", :fail, "key mismatch", "the published p= is not this server's key - re-publish the TXT value below")
    end
  end

  def dmarc_check
    records = @resolver.txt("_dmarc.#{@domain.name}")
    return check("DMARC", :unknown, nil, "DNS lookup failed") if records.nil?

    @dmarc_record = records.find { |r| r.match?(/\Av=DMARC1\b/i) }
    if @dmarc_record
      check("DMARC", :pass, @dmarc_record)
    else
      check("DMARC", :fail, nil, "no _dmarc record published")
    end
  end

  def check(record, status, found, note = nil)
    Check.new(record: record, status: status, found: found, note: note)
  end
end
