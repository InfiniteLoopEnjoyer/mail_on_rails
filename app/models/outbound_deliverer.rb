require "net/smtp"
require "resolv"
require "dkim"
require "mail_on_rails/smtp/sender_auth/dns"

# Delivers one SmtpOutboundMessage to its recipient's mail server:
# resolves MX records, connects on port 25 and speaks SMTP. When
# MAIL_ON_RAILS_SMARTHOST is set (host:port), every delivery is relayed
# through it instead - the way out while the host blocks port 25.
#
# Transport security is policy-driven per destination host:
#
#   - DANE (RFC 7672) when the MX RRset is DNSSEC-secure and the host
#     publishes secure usable TLSA records: TLS is required and the
#     presented chain must match a TLSA record (Dane.verify!). No
#     fallback to unauthenticated TLS or cleartext - failures defer.
#     Needs a DNSSEC-validating resolver (the AD bit is trusted);
#     MAIL_ON_RAILS_DANE=0 turns it off.
#   - MTA-STS (RFC 8461) otherwise, when the recipient domain publishes a
#     policy (MtaStsPolicy caches it): in enforce mode, only
#     policy-matched MX hosts are tried, TLS is required and
#     WebPKI-verified with hostname check. MAIL_ON_RAILS_MTA_STS=0 turns
#     it off.
#   - Opportunistic unverified STARTTLS otherwise, as plain SMTP allows.
#
# Every attempt's TLS outcome lands in TlsRptEvent for the daily RFC 8460
# reports. Raises PermanentError (5xx, no such domain, null MX) or
# TransientError (4xx, timeouts, connection/DNS/TLS-policy failures); the
# caller decides retry/bounce.
class OutboundDeliverer
  class PermanentError < StandardError; end
  class TransientError < StandardError; end

  # A policy demanded TLS the server couldn't or wouldn't do properly.
  class TlsPolicyError < StandardError
    attr_reader :result_type

    def initialize(message, result_type:)
      super(message)
      @result_type = result_type
    end
  end

  OPEN_TIMEOUT = 20
  READ_TIMEOUT = 60

  # How one destination host must be spoken to: :dane (with the usable
  # TLSA records), :sts_enforce, or :opportunistic.
  HostPolicy = Struct.new(:mode, :tlsa_records, keyword_init: true)
  Resolved = Struct.new(:hosts, :secure, :fallback, keyword_init: true)

  # Net::SMTP that DANE-verifies the peer chain right after the TLS
  # handshake, before any SMTP command (or the message) crosses the
  # socket. Raising SSLError here reads as "this host failed TLS" to the
  # delivery loop, which moves on to the next MX.
  class DaneSmtp < Net::SMTP
    attr_accessor :dane_records, :dane_hostname

    private

    def tlsconnect(socket, context)
      ssl = super
      begin
        Dane.verify!(dane_records, ssl.peer_cert, ssl.peer_cert_chain, hostname: dane_hostname)
      rescue Dane::VerifyError => e
        begin
          ssl.close
        rescue StandardError
          nil
        end
        raise OpenSSL::SSL::SSLError, "DANE verification failed for #{dane_hostname}: #{e.message}"
      end
      ssl
    end
  end

  def self.deliver(message)
    new.deliver(message)
  end

  def initialize(dns: MailOnRails::Smtp::SenderAuth::Dns.shared)
    @dns = dns
  end

  def deliver(message)
    return deliver_via_smarthost(message) if smarthost

    domain = message.domain.to_s.downcase
    sts = sts_lookup(domain)
    if sts.fetch_error
      record_event(domain, "sts", result: "sts-policy-fetch-error",
                                  detail: "advertised MTA-STS policy could not be fetched")
    end

    resolved = mx_hosts(domain)
    hosts = resolved.hosts
    if sts.policy&.enforce?
      hosts = hosts.select { |(host, _port)| sts.policy.mx_match?(host) }
      if hosts.empty?
        record_event(domain, "sts", result: "validation-failure",
                                    detail: "no MX host matches the MTA-STS policy")
        raise TransientError, "#{domain}: no MX host matches its MTA-STS enforce policy"
      end
    end

    errors = []
    hosts.each do |(host, port)|
      policy = HostPolicy.new(mode: :opportunistic)
      begin
        policy = host_policy(host, sts, dane_eligible: resolved.secure || resolved.fallback)
        send_via(host, port, message, policy: policy)
        record_outcome(domain, host, policy, sts)
        return true
      rescue Net::SMTPFatalError, Net::SMTPSyntaxError => e
        # A 5xx from a live server is authoritative for this recipient -
        # trying the next MX would just get another rejection.
        raise PermanentError, "#{host}: #{e.message.strip}"
      rescue TlsPolicyError => e
        record_outcome(domain, host, policy, sts, result: e.result_type, detail: e.message)
        errors << "#{host}: #{e.message}"
      rescue OpenSSL::SSL::SSLError => e
        record_outcome(domain, host, policy, sts, result: "validation-failure",
                                                  detail: "#{e.class}: #{e.message.strip}")
        errors << "#{host}: #{e.class}: #{e.message.strip}"
      rescue Net::SMTPServerBusy, Net::SMTPUnknownError, Net::SMTPAuthenticationError,
             IOError, SystemCallError, Timeout::Error => e
        errors << "#{host}: #{e.class}: #{e.message.strip}"
      rescue MailOnRails::Smtp::SenderAuth::Dns::TempError => e
        errors << "#{host}: TLSA lookup failed: #{e.message}"
      end
    end

    raise TransientError, errors.last || "no servers to try"
  end

  private

  def smarthost
    spec = ENV["MAIL_ON_RAILS_SMARTHOST"]
    return nil if spec.blank?

    host, port = spec.split(":")
    [ host, Integer(port || 25) ]
  end

  # The smarthost is our own trusted relay on a private path: policies
  # and TLS-RPT telemetry are about the public destination, so neither
  # applies here.
  def deliver_via_smarthost(message)
    host, port = smarthost
    send_via(host, port, message, policy: HostPolicy.new(mode: :opportunistic), auth: smarthost_auth)
    true
  rescue Net::SMTPFatalError, Net::SMTPSyntaxError => e
    raise PermanentError, "#{host}: #{e.message.strip}"
  rescue Net::SMTPServerBusy, Net::SMTPUnknownError, Net::SMTPAuthenticationError,
         OpenSSL::SSL::SSLError, IOError, SystemCallError, Timeout::Error => e
    raise TransientError, "#{host}: #{e.class}: #{e.message.strip}"
  end

  def smarthost_auth
    return {} unless ENV["MAIL_ON_RAILS_SMARTHOST_USER"].present?

    { user: ENV["MAIL_ON_RAILS_SMARTHOST_USER"],
      secret: ENV["MAIL_ON_RAILS_SMARTHOST_PASSWORD"], authtype: :plain }
  end

  def mx_hosts(domain)
    answer = @dns.mx_answer(domain)
    # Ties are shuffled (rand tiebreaker) so repeated deliveries spread
    # across a destination's equal-preference MX pool per RFC 5321.
    names = answer.records.sort_by { |(preference, _host)| [ preference, rand ] }.map(&:last)

    # RFC 7505 null MX: the domain declares it never accepts mail.
    raise PermanentError, "#{domain} does not accept mail (null MX)" if names == [ "" ] || names == [ "." ]
    # RFC 5321: no MX records means fall back to the domain's own A record.
    fallback = names.empty?
    names = [ domain ] if fallback

    Resolved.new(hosts: names.map { |h| [ h, 25 ] }, secure: answer.secure, fallback: fallback)
  rescue MailOnRails::Smtp::SenderAuth::Dns::TempError => e
    raise TransientError, "DNS lookup for #{domain} failed: #{e.message}"
  end

  def sts_lookup(domain)
    return MtaStsPolicy::NONE if ENV["MAIL_ON_RAILS_MTA_STS"] == "0"

    MtaStsPolicy.lookup(domain, dns: @dns)
  rescue StandardError => e
    # Policy lookup must never take delivery down with it.
    Rails.logger.error "[mail_on_rails] MTA-STS lookup for #{domain} failed: #{e.class}: #{e.message}"
    MtaStsPolicy::NONE
  end

  # DANE eligibility needs a DNSSEC-secure path to the host name: a
  # secure MX RRset, or the implicit A fallback where the host name comes
  # from the recipient address itself rather than DNS. The TLSA answer
  # must then itself be secure. A secure TLSA RRset with only unusable
  # records makes the host undeliverable rather than downgrading
  # (RFC 7671 section 4.1).
  def host_policy(host, sts, dane_eligible:)
    if dane_enabled? && dane_eligible
      answer = @dns.tlsa("_25._tcp.#{host}")
      if answer.secure && answer.records.any?
        usable = Dane.usable_records(answer.records)
        if usable.empty?
          raise TlsPolicyError.new("secure TLSA RRset for #{host} contains no usable records",
                                   result_type: "tlsa-invalid")
        end

        return HostPolicy.new(mode: :dane, tlsa_records: usable)
      end
    end

    return HostPolicy.new(mode: :sts_enforce) if sts.policy&.enforce?

    HostPolicy.new(mode: :opportunistic)
  end

  def dane_enabled?
    ENV["MAIL_ON_RAILS_DANE"] != "0"
  end

  def send_via(host, port, message, policy:, auth: {})
    smtp = build_smtp(host, port, policy)
    smtp.open_timeout = OPEN_TIMEOUT
    smtp.read_timeout = READ_TIMEOUT
    smtp.start(helo: helo_host, **auth) do |session|
      session.send_message(signed(message), message.mail_from, message.recipient)
    end
    true
  rescue Net::SMTPUnsupportedCommand => e
    # Only raised here by starttls: :always, i.e. under a TLS-requiring
    # policy - the server not offering STARTTLS is a policy failure.
    raise TlsPolicyError.new("#{host} does not offer STARTTLS (#{e.message.strip})",
                             result_type: "starttls-not-supported")
  end

  def build_smtp(host, port, policy)
    case policy.mode
    when :dane
      smtp = DaneSmtp.new(host, port, tls_hostname: host)
      smtp.dane_records = policy.tlsa_records
      smtp.dane_hostname = host
      smtp.enable_starttls(dane_ssl_context)
      smtp
    when :sts_enforce
      smtp = Net::SMTP.new(host, port, tls_hostname: host)
      smtp.enable_starttls(pkix_ssl_context)
      smtp
    else
      Net::SMTP.new(host, port, starttls: :auto, tls_verify: false)
    end
  end

  # DANE replaces WebPKI entirely: the handshake accepts any chain and
  # DaneSmtp#tlsconnect enforces the TLSA match itself (name and expiry
  # checks per usage live in Dane, not OpenSSL).
  def dane_ssl_context
    context = OpenSSL::SSL::SSLContext.new
    context.set_params(verify_mode: OpenSSL::SSL::VERIFY_NONE, verify_hostname: false)
    context
  end

  # MTA-STS enforce mode is WebPKI: system trust store, hostname
  # verification against the MX host (SNI is set by net-smtp from
  # tls_hostname).
  def pkix_ssl_context
    context = OpenSSL::SSL::SSLContext.new
    context.set_params # VERIFY_PEER + verify_hostname + default cert store
    context
  end

  # One TlsRptEvent per policy that governed the attempt: a DANE attempt
  # reports under tlsa, a domain with an MTA-STS policy (enforce or
  # testing) under sts, and a bare failure still counts under
  # no-policy-found so the domain owner sees it once they publish a
  # TLSRPT record. result nil is a successful session.
  def record_outcome(domain, host, policy, sts, result: nil, detail: nil)
    types = []
    types << "tlsa" if policy.mode == :dane
    types << "sts" if sts.policy
    types = [ "no-policy-found" ] if types.empty?
    types.each do |type|
      record_event(domain, type, mx: host, result: result, detail: detail)
    end
  end

  def record_event(domain, type, mx: nil, result: nil, detail: nil)
    TlsRptEvent.record!(policy_domain: domain, policy_type: type, mx: mx,
                        result_type: result, detail: detail)
  end

  # DKIM-signs with the From: HEADER domain's key - that is the domain
  # DMARC checks alignment against, so signing with the envelope sender
  # would not align whenever the two differ. Falls back to the envelope
  # domain when the header is missing or unparseable. The key is the
  # domain's encrypted dkim_private_key (minted on domain creation); a
  # missing key sends unsigned, loudly - that usually means the domain
  # was never added as a Domain.
  def signed(message)
    domain = signing_domain(message)
    return message.data if domain.blank?

    record = Domain.find_by(name: domain)
    if record&.dkim_private_key.blank?
      Rails.logger.warn "[mail_on_rails] outbound to <#{message.recipient}> goes out UNSIGNED: " \
                        "no DKIM key for #{domain} - add the domain in the Domains UI to generate one"
      return message.data
    end

    Dkim.sign(message.data,
              domain: domain,
              selector: record.dkim_selector,
              private_key: OpenSSL::PKey.read(record.dkim_private_key))
  rescue StandardError => e
    # A signing failure (malformed message, unreadable key) must not block
    # delivery - retrying would not fix it. Send unsigned and say so.
    Rails.logger.warn "[mail_on_rails] outbound to <#{message.recipient}> goes out UNSIGNED: " \
                      "signing failed (#{e.class}: #{e.message})"
    message.data
  end

  def signing_domain(message)
    header_from = begin
      (Mail.read_from_string(message.data.to_s).from || []).first
    rescue StandardError
      nil
    end
    domain = header_from.to_s.split("@").last.to_s.strip.downcase
    domain = message.mail_from.to_s.split("@").last.to_s.strip.downcase if domain.blank?
    domain.presence
  end

  # What we announce in EHLO. Remote servers check this resolves back to
  # us, so production sets it to the public mail hostname (Settings page
  # or SMTP_HELO_HOST).
  def helo_host
    Setting.effective_smtp_helo_hostname
  end
end
