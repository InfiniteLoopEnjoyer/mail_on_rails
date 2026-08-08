require "net/http"
require "mail_on_rails/smtp/sender_auth/dns"

# A recipient domain's cached MTA-STS policy (RFC 8461) - the sending
# side of the protocol; MtaSts is our published side. The DB row is the
# cache RFC 8461 requires: once fetched, a policy stays in force for its
# max_age even if the _mta-sts TXT record or the policy host disappear,
# so a DNS-blocking attacker can't downgrade a domain we've seen before.
#
# Refreshes are driven by the TXT record's id: a new id (or an expired
# cache) triggers an HTTPS fetch of
# https://mta-sts.<domain>/.well-known/mta-sts.txt over verified WebPKI
# TLS, with no redirects.
class MtaStsPolicy < ApplicationRecord
  class FetchError < StandardError; end

  serialize :mx_patterns, coder: JSON

  MODES = %w[enforce testing none].freeze
  MAX_POLICY_BYTES = 64 * 1024
  MAX_AGE_CAP = 31_557_600 # RFC 8461 section 3.2
  HTTP_TIMEOUT = 10

  # What a delivery attempt gets: the policy in force (nil when none) and
  # whether the domain advertises a policy we could not obtain - which
  # TLS-RPT reports as sts-policy-fetch-error.
  Lookup = Struct.new(:policy, :fetch_error, keyword_init: true)
  NONE = Lookup.new(policy: nil, fetch_error: false)

  def self.lookup(domain, dns: MailOnRails::Smtp::SenderAuth::Dns.shared)
    domain = domain.to_s.downcase
    cached = find_by(domain: domain)
    cached = nil if cached&.expired?

    begin
      txt_id = published_id(domain, dns)
    rescue MailOnRails::Smtp::SenderAuth::Dns::TempError
      # Resolver trouble: whatever is validly cached stays in force.
      return Lookup.new(policy: cached, fetch_error: false)
    end

    return Lookup.new(policy: cached, fetch_error: false) if txt_id.nil?
    return Lookup.new(policy: cached, fetch_error: false) if cached && cached.sts_id == txt_id

    begin
      Lookup.new(policy: refresh!(domain, txt_id), fetch_error: false)
    rescue FetchError => e
      Rails.logger.warn "[mail_on_rails] MTA-STS policy fetch for #{domain} failed: #{e.message}"
      Lookup.new(policy: cached, fetch_error: true)
    end
  end

  # The id from the domain's _mta-sts TXT record, or nil when the domain
  # publishes none (multiple STSv1 records are invalid and count as none,
  # RFC 8461 section 3.1). Raises Dns::TempError on resolver failure.
  def self.published_id(domain, dns)
    records = dns.txt("_mta-sts.#{domain}").select { |t| t.strip.start_with?("v=STSv1") }
    return nil unless records.size == 1

    records.first[/;\s*id\s*=\s*([A-Za-z0-9]{1,32})\s*(?:;|\z)/, 1]
  end

  def self.refresh!(domain, sts_id)
    fields = parse(fetch_policy_body(domain))
    policy = find_or_initialize_by(domain: domain)
    policy.update!(sts_id: sts_id, mode: fields[:mode], max_age: fields[:max_age],
                   mx_patterns: fields[:mx], fetched_at: Time.current)
    policy
  end

  def self.fetch_policy_body(domain)
    http = Net::HTTP.new("mta-sts.#{domain}", 443)
    http.use_ssl = true # WebPKI-verified by default; a bad cert is a failed fetch
    http.open_timeout = HTTP_TIMEOUT
    http.read_timeout = HTTP_TIMEOUT
    http.max_retries = 0
    body = +""
    http.request_get("/.well-known/mta-sts.txt") do |response|
      raise FetchError, "HTTP #{response.code}" unless response.is_a?(Net::HTTPOK)

      # Stream and cap: Net::HTTP#get would buffer the whole body before any
      # size check, so a hostile mta-sts.<domain> - an attacker's own
      # recipient domain, valid cert and all - could stream gigabytes into a
      # delivery worker before the MAX_POLICY_BYTES gate ever ran. Reading in
      # chunks lets us abort the moment the cap is crossed.
      response.read_body do |chunk|
        body << chunk
        raise FetchError, "policy body too large" if body.bytesize > MAX_POLICY_BYTES
      end
    end
    body
  rescue OpenSSL::SSL::SSLError => e
    raise FetchError, "TLS: #{e.message}"
  rescue Timeout::Error, IOError, SystemCallError, SocketError, Net::ProtocolError => e
    raise FetchError, "#{e.class}: #{e.message}"
  end

  # RFC 8461 section 3.2 key/value lines. Raises FetchError when the
  # policy is malformed - a broken policy must not silently read as
  # "no policy".
  def self.parse(body)
    fields = Hash.new { |h, k| h[k] = [] }
    body.to_s.split(/\r?\n/).each do |line|
      key, _, value = line.partition(":")
      fields[key.strip] << value.strip unless line.strip.empty?
    end

    raise FetchError, "unsupported version #{fields['version'].first.inspect}" unless fields["version"].first == "STSv1"

    mode = fields["mode"].first
    raise FetchError, "invalid mode #{mode.inspect}" unless MODES.include?(mode)

    max_age = Integer(fields["max_age"].first || "", 10) rescue nil
    raise FetchError, "invalid max_age" unless max_age&.positive?

    mx = fields["mx"].map(&:downcase).reject(&:empty?)
    raise FetchError, "no mx patterns" if mx.empty? && mode != "none"

    { mode: mode, max_age: [ max_age, MAX_AGE_CAP ].min, mx: mx }
  end

  def expired?(now: Time.current)
    fetched_at + max_age.seconds <= now
  end

  def enforce?
    mode == "enforce"
  end

  # RFC 8461 section 4.1: a pattern is an exact hostname, or "*.domain"
  # matching exactly one extra left-hand label.
  def mx_match?(host)
    host = host.to_s.downcase.chomp(".")
    mx_patterns.any? do |pattern|
      if pattern.start_with?("*.")
        suffix = pattern[2..]
        host.match?(/\A[^.]+\.#{Regexp.escape(suffix)}\z/)
      else
        host == pattern
      end
    end
  end

  # The policy reconstructed as RFC 8461 lines, for TLS-RPT's
  # policy-string field.
  def policy_lines
    [ "version: STSv1", "mode: #{mode}", *mx_patterns.map { |m| "mx: #{m}" }, "max_age: #{max_age}" ]
  end
end
