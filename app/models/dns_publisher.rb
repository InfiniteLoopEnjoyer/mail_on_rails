# Publishes the domain page's prescribed DNS records to Cloudflare, on
# explicit admin action (the "Publish DNS" button - never automatic).
#
# Deliberately conservative about what it will touch:
#   - creates records that are MISSING (MX, SPF, DKIM TXT, DMARC,
#     MTA-STS TXT + policy-host CNAME, TLS-RPT);
#   - updates only the DKIM TXT when it mismatches the key on disk and
#     the MTA-STS TXT when its id mismatches the policy this app serves -
#     those records are ours to own;
#   - never overwrites an existing MX set, SPF, DMARC, or TLS-RPT record
#     - those may be deliberate (Email Routing MXs, custom SPF
#     mechanisms, a tightened DMARC policy, a different report address),
#     so they are reported as skipped instead.
# DMARC escalation (p=none -> quarantine -> reject) stays a manual edit,
# guided by the monitoring section's advice.
class DnsPublisher
  Result = Struct.new(:actions, :skipped, keyword_init: true)

  TTL = 1 # Cloudflare "auto"

  def self.publish!(domain, client: CloudflareDns.new)
    new(domain, client).publish!
  end

  def initialize(domain, client)
    @domain = domain
    @client = client
  end

  def publish!
    raise CloudflareDns::Error, "SMTP hostname is not set (Settings page or SMTP_HELO_HOST)" if mail_host.blank?

    @zone = @client.zone_id(@domain.name)
    @actions = []
    @skipped = []
    publish_mx
    publish_spf
    publish_dkim
    publish_dmarc
    publish_mta_sts
    publish_tls_rpt
    Result.new(actions: @actions, skipped: @skipped)
  end

  private

  def mail_host
    Setting.smtp_helo_hostname
  end

  def publish_mx
    existing = @client.records(@zone, type: "MX", name: @domain.name)
    if existing.empty?
      @client.create_record(@zone, type: "MX", name: @domain.name, content: mail_host, priority: 10, ttl: TTL)
      @actions << "created MX 10 #{mail_host}"
    elsif existing.any? { |r| r["content"].to_s.downcase.delete_suffix(".") == mail_host }
      @skipped << "MX already points at #{mail_host}"
    else
      found = existing.map { |r| r["content"] }.join(", ")
      @skipped << "MX exists but points elsewhere (#{found}) - remove it (e.g. disable Email Routing) and republish"
    end
  end

  def publish_spf
    spf = txt_records(@domain.name).find { |r| content_of(r).match?(/\Av=spf1\b/i) }
    if spf
      @skipped << "SPF already published (#{content_of(spf)}) - not modifying an existing policy"
    else
      @client.create_record(@zone, type: "TXT", name: @domain.name, content: quoted_txt("v=spf1 mx -all"), ttl: TTL)
      @actions << "created SPF (v=spf1 mx -all)"
    end
  end

  def publish_dkim
    if @domain.dkim_private_key.blank?
      @skipped << "DKIM: no signing key on this server"
      return
    end

    existing = txt_records(@domain.dkim_txt_name)
    expected = @domain.dkim_txt_value
    if existing.empty?
      @client.create_record(@zone, type: "TXT", name: @domain.dkim_txt_name, content: quoted_txt(expected), ttl: TTL)
      @actions << "created DKIM TXT (#{@domain.dkim_txt_name})"
    elsif existing.any? { |r| dkim_p(content_of(r)) == dkim_p(expected) }
      @skipped << "DKIM TXT already matches the key"
    else
      @client.update_record(@zone, existing.first["id"], type: "TXT", name: @domain.dkim_txt_name, content: quoted_txt(expected), ttl: TTL)
      @actions << "updated DKIM TXT to this server's key"
    end
  end

  def publish_dmarc
    name = "_dmarc.#{@domain.name}"
    existing = txt_records(name).find { |r| content_of(r).match?(/\Av=DMARC1\b/i) }
    if existing
      @skipped << "DMARC already published (#{content_of(existing)}) - tighten it manually when the monitoring section says so"
    else
      @client.create_record(@zone, type: "TXT", name: name,
                                   content: quoted_txt("v=DMARC1; p=none; rua=mailto:#{@domain.dmarc_address}"), ttl: TTL)
      @actions << "created DMARC (p=none, reports to #{@domain.dmarc_address})"
    end
  end

  # The _mta-sts TXT carries an id derived from the policy file this app
  # serves (MtaSts), so a mismatch just means the policy changed since the
  # record was published - safe to update in place, unlike SPF/DMARC.
  def publish_mta_sts
    name = "_mta-sts.#{@domain.name}"
    expected = MtaSts.txt_record
    published = txt_records(name).find { |r| content_of(r).match?(/\Av=STSv1\b/i) }
    if published.nil?
      @client.create_record(@zone, type: "TXT", name: name, content: quoted_txt(expected), ttl: TTL)
      @actions << "created MTA-STS TXT (#{expected})"
    elsif content_of(published) == expected
      @skipped << "MTA-STS TXT already matches the policy"
    else
      @client.update_record(@zone, published["id"], type: "TXT", name: name, content: quoted_txt(expected), ttl: TTL)
      @actions << "updated MTA-STS TXT to the current policy id"
    end
    publish_mta_sts_host
  end

  # Senders fetch the policy from https://mta-sts.<domain>/..., so that
  # host must reach this app's web endpoint (and be listed in the kamal
  # proxy hosts so it gets a certificate).
  def publish_mta_sts_host
    host = MtaSts.policy_host(@domain)
    if web_host.blank?
      @skipped << "MTA-STS policy host: MAIL_ON_RAILS_WEB_HOST is not set, cannot point #{host} anywhere"
      return
    end

    existing = @client.records(@zone, type: "CNAME", name: host)
    if existing.empty?
      @client.create_record(@zone, type: "CNAME", name: host, content: web_host, ttl: TTL)
      @actions << "created CNAME #{host} -> #{web_host}"
    elsif existing.any? { |r| r["content"].to_s.downcase.delete_suffix(".") == web_host }
      @skipped << "#{host} already points at #{web_host}"
    else
      found = existing.map { |r| r["content"] }.join(", ")
      @skipped << "#{host} exists but points elsewhere (#{found}) - senders will fetch the MTA-STS policy from there"
    end
  end

  def publish_tls_rpt
    name = "_smtp._tls.#{@domain.name}"
    existing = txt_records(name).find { |r| content_of(r).match?(/\Av=TLSRPTv1\b/i) }
    if existing
      @skipped << "TLS-RPT already published (#{content_of(existing)}) - not modifying an existing report address"
    else
      # The rua target must exist before reporters mail it.
      @domain.ensure_tls_rpt_account!
      @client.create_record(@zone, type: "TXT", name: name,
                                   content: quoted_txt("v=TLSRPTv1; rua=mailto:#{@domain.tls_rpt_address}"), ttl: TTL)
      @actions << "created TLS-RPT (reports to #{@domain.tls_rpt_address})"
    end
  end

  def web_host
    ENV["MAIL_ON_RAILS_WEB_HOST"].to_s.strip.downcase.presence
  end

  def txt_records(name)
    @client.records(@zone, type: "TXT", name: name)
  end

  # Cloudflare requires TXT content in RFC 1035 presentation form:
  # double-quoted, split into 255-character strings (the DKIM value
  # overflows a single one).
  def quoted_txt(content)
    content.scan(/.{1,255}/m).map { |part| %("#{part}") }.join(" ")
  end

  # Cloudflare returns TXT content in that same quoted form; unwrap to
  # the logical value for comparisons.
  def content_of(record)
    raw = record["content"].to_s.strip
    parts = raw.scan(/"([^"]*)"/)
    parts.any? ? parts.join : raw
  end

  def dkim_p(content)
    content.gsub(/[\s"]/, "")[/p=([A-Za-z0-9+\/=]+)/, 1]
  end
end
