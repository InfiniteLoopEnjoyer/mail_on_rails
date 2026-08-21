require "net/smtp"
require "resolv"
require "cgi"
require "dkim"
require "mail_on_rails/sender_auth/dns"
require "mail_on_rails/outbound_data"
require "mail_on_rails/idn"

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
#     Needs a resolver whose DNSSEC validation we trust: the AD bit only
#     counts from a loopback resolver or one listed in
#     MAIL_ON_RAILS_DANE_TRUSTED_RESOLVERS (see SenderAuth::Dns);
#     MAIL_ON_RAILS_DANE=0 turns it off.
#   - MTA-STS (RFC 8461) otherwise, when the recipient domain publishes a
#     policy (MtaStsPolicy caches it): in enforce mode, only
#     policy-matched MX hosts are tried, TLS is required and
#     WebPKI-verified with hostname check. MAIL_ON_RAILS_MTA_STS=0 turns
#     it off.
#   - Opportunistic unverified STARTTLS otherwise, as plain SMTP allows -
#     unless SMTP_OUTBOUND_REQUIRE_VERIFIED_TLS=1, which upgrades this
#     tier to required, WebPKI-verified STARTTLS for every host.
#
# Smarthost transport is picked by MAIL_ON_RAILS_SMARTHOST_TLS:
# opportunistic (legacy default), starttls (required + verified), or
# smtps (implicit TLS) - AUTH credentials should never ride the
# opportunistic mode.
#
# Two sender signals modulate all of the above (RFC 8689):
#
#   - REQUIRETLS (message.requiretls, recorded at submission): every hop
#     must be verified TLS - opportunistic tiers are upgraded to required
#     WebPKI STARTTLS - and the next hop must itself advertise REQUIRETLS
#     so the promise survives relaying. A server that cannot satisfy that
#     is never given the message; if no MX can, the delivery fails
#     permanently (5.7.30) and bounces.
#   - "TLS-Required: No" header: the sender prefers delivery over
#     transport policy (e.g. a TLS-RPT report about the policy being
#     broken), so DANE/MTA-STS/verified-TLS enforcement is skipped and
#     the message rides plain opportunistic TLS. Ignored when REQUIRETLS
#     was also requested - the envelope wins.
#
# The sender's DSN requests (RFC 3461: NOTIFY/ORCPT/RET/ENVID on the
# queue row) are forwarded when the next hop advertises DSN - it then
# owns the notifications - and otherwise this host reports "relayed"
# itself (DeliverSmtpOutboundJob). The remote server's advertised SIZE is
# checked before the transfer; an oversize message fails permanently.
#
# Every attempt's TLS outcome lands in TlsRptEvent for the daily RFC 8460
# reports. Raises PermanentError (5xx, no such domain, null MX) or
# TransientError (4xx, timeouts, connection/DNS/TLS-policy failures); the
# caller decides retry/bounce. Successful delivery returns :propagated_dsn
# when the next hop accepted the DSN request, else :delivered.
module MailOnRails
  class OutboundDeliverer
    class PermanentError < StandardError; end
    class TransientError < StandardError; end
    # The next hop cannot uphold a REQUIRETLS promise (no advertisement).
    class RequiretlsUnsupported < StandardError; end
    # The message needs SMTPUTF8 (RFC 6531) and the next hop lacks it -
    # downgrading a UTF-8 envelope is not a thing, so this bounces once
    # every hop has refused.
    class Smtputf8Unsupported < StandardError; end

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

    def initialize(dns: MailOnRails::SenderAuth::Dns.shared)
      @dns = dns
    end

    def deliver(message)
      # "TLS-Required: No" trades policy for deliverability (RFC 8689
      # 4.2.1) - unless the envelope carried REQUIRETLS, which wins.
      relaxed = !message.requiretls? && tls_required_no?(message)
      return deliver_via_smarthost(message) if smarthost

      # DNS wants A-labels; an SMTPUTF8 envelope may carry a U-label.
      domain = MailOnRails::Idn.to_ascii(message.domain.to_s.downcase)
      sts = relaxed ? MtaStsPolicy::NONE : sts_lookup(domain)
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
      requiretls_refusals = 0
      smtputf8_refusals = 0
      hosts.each do |(host, port)|
        policy = HostPolicy.new(mode: :opportunistic)
        begin
          policy = if relaxed
            HostPolicy.new(mode: :relaxed)
          else
            host_policy(host, sts, dane_eligible: resolved.secure || resolved.fallback)
          end
          # REQUIRETLS upgrades the unverified tier: the promise needs an
          # authenticated server, not just an encrypted socket.
          policy = HostPolicy.new(mode: :requiretls) if message.requiretls? && policy.mode == :opportunistic
          outcome = send_via(host, port, message, policy: policy)
          record_outcome(domain, host, policy, sts)
          return outcome
        rescue Net::SMTPFatalError, Net::SMTPSyntaxError => e
          # A 5xx from a live server is authoritative for this recipient -
          # trying the next MX would just get another rejection.
          raise PermanentError, "#{host}: #{e.message.strip}"
        rescue RequiretlsUnsupported => e
          requiretls_refusals += 1
          errors << "#{host}: #{e.message}"
        rescue Smtputf8Unsupported => e
          smtputf8_refusals += 1
          errors << "#{host}: #{e.message}"
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
        rescue MailOnRails::SenderAuth::Dns::TempError => e
          errors << "#{host}: TLSA lookup failed: #{e.message}"
        end
      end

      # Every reachable server refusing the promise is a final answer -
      # retrying cannot conjure REQUIRETLS support (RFC 8689 4.2.1).
      if requiretls_refusals.positive? && requiretls_refusals == errors.size
        raise PermanentError, "5.7.30 REQUIRETLS requested by sender but not supported: #{errors.last}"
      end
      # Same finality for an internationalized envelope: RFC 6531 has no
      # downgrade, so a destination with no SMTPUTF8 hop cannot ever take
      # this message.
      if smtputf8_refusals.positive? && smtputf8_refusals == errors.size
        raise PermanentError, "5.6.7 message requires SMTPUTF8 but no server for #{domain} supports it: #{errors.last}"
      end

      raise TransientError, errors.last || "no servers to try"
    end

    private

    def smarthost
      spec = MailOnRails::Settings.static(:smarthost)
      return nil if spec.blank?

      host, port = spec.split(":")
      [ host, Integer(port || 25) ]
    end

    # The smarthost is our own trusted relay on a private path: public
    # destination policies and TLS-RPT telemetry do not apply, but its
    # transport is still configurable - AUTH credentials over unverified
    # opportunistic TLS invite a credential-stealing MITM, so smarthost_auth
    # withholds them unless the transport verifies the peer.
    SMARTHOST_POLICY_MODES = {
      "opportunistic" => :opportunistic,
      "starttls" => :smarthost_starttls,
      "smtps" => :smarthost_smtps
    }.freeze

    def deliver_via_smarthost(message)
      host, port = smarthost
      mode = SMARTHOST_POLICY_MODES.fetch(MailOnRails::Settings.static(:smarthost_tls), :opportunistic)
      # A REQUIRETLS promise cannot ride an unverified smarthost hop; the
      # transport is operator configuration, so defer until it is fixed
      # (or the queue exhausts and the sender learns via the bounce).
      if message.requiretls? && !verified_smarthost_transport?(mode)
        raise TransientError, "#{host}: REQUIRETLS requested but MAIL_ON_RAILS_SMARTHOST_TLS="                               "#{MailOnRails::Settings.static(:smarthost_tls)} does not verify TLS"
      end

      send_via(host, port, message, policy: HostPolicy.new(mode: mode), auth: smarthost_auth(mode))
    rescue RequiretlsUnsupported => e
      raise TransientError, "#{host}: #{e.message}"
    rescue Smtputf8Unsupported => e
      # The smarthost is operator configuration; defer rather than bounce
      # so an upgrade (or a route change) can still deliver the message.
      raise TransientError, "#{host}: #{e.message}"
    rescue TlsPolicyError => e
      raise TransientError, "#{host}: #{e.message}"
    rescue Net::SMTPFatalError, Net::SMTPSyntaxError => e
      raise PermanentError, "#{host}: #{e.message.strip}"
    rescue Net::SMTPServerBusy, Net::SMTPUnknownError, Net::SMTPAuthenticationError,
           OpenSSL::SSL::SSLError, IOError, SystemCallError, Timeout::Error => e
      raise TransientError, "#{host}: #{e.class}: #{e.message.strip}"
    end

    # Withholding rather than sending turns the misconfiguration into a
    # visible AUTH-required rejection at the smarthost instead of a silent
    # credential leak to whoever sits on the path.
    def smarthost_auth(mode)
      user = MailOnRails::Settings.static(:smarthost_user)
      return {} unless user.present?

      unless verified_smarthost_transport?(mode)
        Rails.logger.error "[mail_on_rails] smarthost AUTH withheld: " \
                           "MAIL_ON_RAILS_SMARTHOST_TLS=opportunistic does not verify TLS " \
                           "(set starttls or smtps)"
        return {}
      end

      { user: user,
        secret: MailOnRails::Settings.static(:smarthost_password), authtype: :plain }
    end

    # Opportunistic mode normally builds an unverified (or absent) TLS
    # session; smtp_outbound_require_verified_tls upgrades even that path
    # to verified STARTTLS in build_smtp, which makes it safe for AUTH.
    def verified_smarthost_transport?(mode)
      mode != :opportunistic || MailOnRails::Settings[:smtp_outbound_require_verified_tls]
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
    rescue MailOnRails::SenderAuth::Dns::TempError => e
      raise TransientError, "DNS lookup for #{domain} failed: #{e.message}"
    end

    def sts_lookup(domain)
      return MtaStsPolicy::NONE unless MailOnRails::Settings[:mta_sts]

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
      MailOnRails::Settings[:dane]
    end

    def send_via(host, port, message, policy:, auth: {})
      data = signed(message)
      smtp = build_smtp(host, port, policy)
      smtp.open_timeout = OPEN_TIMEOUT
      smtp.read_timeout = READ_TIMEOUT
      session = smtp.start(helo: helo_host, **auth)
      begin
        # RFC 8689 4.2.1: the promise must not be handed to a hop that
        # cannot carry it onward.
        if message.requiretls? && !session.capable?("REQUIRETLS")
          raise RequiretlsUnsupported, "#{host} does not advertise REQUIRETLS"
        end

        # RFC 6531 3.7.1: an internationalized message only goes to a hop
        # that advertises SMTPUTF8 - there is no downgrade.
        if needs_smtputf8?(message) && !session.capable?("SMTPUTF8")
          raise Smtputf8Unsupported, "#{host} does not advertise SMTPUTF8"
        end

        # RFC 1870: a message the server has already declared too big
        # earns its 552 without the transfer (and without burning retries
        # - the limit will not shrink).
        limit = Array(session.capabilities["SIZE"]).first.to_i
        if limit.positive? && data.bytesize > limit
          raise PermanentError, "#{host}: message (#{data.bytesize} bytes) exceeds the server's "                                 "advertised SIZE limit (#{limit})"
        end

        propagate_dsn = dsn_requested?(message) && session.capable?("DSN")
        session.send_message(data, envelope_sender(message, propagate_dsn: propagate_dsn,
                                                            address: verp_return_path(message, data)),
                             envelope_recipient(message, propagate_dsn: propagate_dsn))
        propagate_dsn ? :propagated_dsn : :delivered
      ensure
        quietly_finish(smtp)
      end
    rescue Net::SMTPUnsupportedCommand => e
      # Only raised here by starttls: :always, i.e. under a TLS-requiring
      # policy - the server not offering STARTTLS is a policy failure.
      raise TlsPolicyError.new("#{host} does not offer STARTTLS (#{e.message.strip})",
                               result_type: "starttls-not-supported")
    end

    # A message needs SMTPUTF8 when its envelope carries non-ASCII, or
    # when the submitter declared it and the headers actually use it
    # (RFC 6531 3.7.1 lets a relay drop the declaration for mail that is
    # plain ASCII throughout - a client that always declares must not
    # confine its ASCII mail to SMTPUTF8-capable destinations).
    def needs_smtputf8?(message)
      return true unless message.recipient.to_s.ascii_only? && message.mail_from.to_s.ascii_only?
      return false unless message.try(:smtputf8?)

      !message.data.to_s.b.partition(/\r?\n\r?\n/).first.ascii_only?
    end

    # MAIL FROM with its ESMTP parameters: REQUIRETLS rides every hop that
    # advertises it (checked above); RET/ENVID ride when the hop takes
    # over the DSN request. SMTPUTF8 rides when the message needs it
    # (only ever sent to hops that advertise it - see send_via). +address+
    # overrides the return path itself (the VERP rewrite); nil keeps the
    # submitted envelope sender.
    def envelope_sender(message, propagate_dsn:, address: nil)
      sender = address || message.mail_from.to_s
      params = []
      params << "REQUIRETLS" if message.requiretls?
      params << "SMTPUTF8" if needs_smtputf8?(message)
      if propagate_dsn
        params << "RET=#{message.dsn_ret}" if message.dsn_ret.present?
        params << "ENVID=#{message.dsn_envid}" if message.dsn_envid.present?
      end
      params.any? ? Net::SMTP::Address.new(sender, *params) : sender
    end

    # VERP for list mail: the return path becomes a signed per-message
    # bounce+ address at the sender's domain (VerpAddress), so any
    # asynchronous bounce attributes itself no matter how mangled its
    # body. Same gate as the unsubscribe injection - only messages that
    # carry List-ID (composer-set, or stamped for a mailing_list account)
    # - plus the bounce@ account must exist to receive what comes back.
    # Personal mail keeps its normal return path: its bounces belong in
    # the author's inbox, read by a human. nil = no rewrite. Best-effort.
    def verp_return_path(message, data)
      return nil unless MailOnRails::Settings[:smtp_verp]
      return nil unless data.partition("\r\n\r\n").first.split(/\r\n(?![ \t])/)
                            .any? { |h| h.match?(/\AList-ID[ \t]*:/i) }

      sender_domain = message.mail_from.to_s.split("@").last.to_s.strip.downcase
      return nil if sender_domain.blank?
      return nil unless EmailAccount.exists?(email: "#{Domain::BOUNCE_LOCAL_PART}@#{sender_domain}")

      VerpAddress.encode(message)
    rescue StandardError => e
      Rails.logger.error "[mail_on_rails] VERP return path for outbound #{message.id} failed: #{e.class}: #{e.message}"
      nil
    end

    def envelope_recipient(message, propagate_dsn:)
      params = []
      if propagate_dsn
        params << "NOTIFY=#{message.dsn_notify}" if message.dsn_notify.present?
        params << "ORCPT=#{message.dsn_orcpt}" if message.dsn_orcpt.present?
      end
      params.any? ? Net::SMTP::Address.new(message.recipient, *params) : message.recipient
    end

    def dsn_requested?(message)
      message.dsn_ret.present? || message.dsn_envid.present? ||
        message.dsn_notify.present? || message.dsn_orcpt.present?
    end

    # RFC 8689 4.2.1: the sender prefers delivery over TLS policy for this
    # message (typical for TLS-RPT reports about the policy being broken).
    def tls_required_no?(message)
      header_block = message.data.to_s.b.partition(/\r?\n\r?\n/).first
      header_block.split(/\r?\n(?![ \t])/).any? { |h| h.match?(/\ATLS-Required:[ \t]*No[ \t]*\z/i) }
    end

    # A server that rejects the sender often slams the connection right
    # after its 5xx (Microsoft's 5.7.1 block-list rejection does), so the
    # QUIT raises a read error. net-smtp's block form runs that QUIT in an
    # ensure, where the new exception would REPLACE an in-flight
    # SMTPFatalError - the outbox then shows "SSL_read: unexpected eof"
    # and retries forever instead of the 550 that names the real problem.
    # By QUIT time the message's fate is already decided (rejected, or
    # accepted - where a cleanup failure must not trigger a re-send), so
    # cleanup errors are swallowed.
    def quietly_finish(smtp)
      smtp.finish
    rescue StandardError
      nil
    end

    def build_smtp(host, port, policy)
      case policy.mode
      when :requiretls
        # Same verified-WebPKI STARTTLS as MTA-STS enforce - REQUIRETLS
        # needs an authenticated server, not merely an encrypted socket.
        smtp = Net::SMTP.new(host, port, tls_hostname: host)
        smtp.enable_starttls(pkix_ssl_context)
        smtp
      when :relaxed
        # "TLS-Required: No": plain opportunistic, bypassing even the
        # smtp_outbound_require_verified_tls upgrade below.
        Net::SMTP.new(host, port, starttls: :auto, tls_verify: false)
      when :dane
        smtp = DaneSmtp.new(host, port, tls_hostname: host)
        smtp.dane_records = policy.tlsa_records
        smtp.dane_hostname = host
        smtp.enable_starttls(dane_ssl_context)
        smtp
      when :sts_enforce, :smarthost_starttls
        smtp = Net::SMTP.new(host, port, tls_hostname: host)
        smtp.enable_starttls(pkix_ssl_context)
        smtp
      when :smarthost_smtps
        smtp = Net::SMTP.new(host, port, tls_hostname: host)
        smtp.enable_tls(pkix_ssl_context)
        smtp
      else
        if MailOnRails::Settings[:smtp_outbound_require_verified_tls]
          smtp = Net::SMTP.new(host, port, tls_hostname: host)
          smtp.enable_starttls(pkix_ssl_context)
          smtp
        else
          Net::SMTP.new(host, port, starttls: :auto, tls_verify: false)
        end
      end
    end

    # DANE replaces WebPKI entirely: the handshake accepts any chain and
    # DaneSmtp#tlsconnect enforces the TLSA match itself (name and expiry
    # checks per usage live in Dane, not OpenSSL).
    def dane_ssl_context
      context = OpenSSL::SSL::SSLContext.new
      context.set_params(verify_mode: OpenSSL::SSL::VERIFY_NONE, verify_hostname: false)
      harden(context)
    end

    # MTA-STS enforce mode is WebPKI: system trust store, hostname
    # verification against the MX host (SNI is set by net-smtp from
    # tls_hostname).
    def pkix_ssl_context
      context = OpenSSL::SSL::SSLContext.new
      context.set_params # VERIFY_PEER + verify_hostname + default cert store
      harden(context)
    end

    # The same TLS 1.2+ AEAD-only floor the listeners pin (Netserv::Tls
    # .context): a policy-verified session downgraded to a legacy
    # protocol or CBC suite would undercut what DANE/MTA-STS promised.
    # Only these enforcing contexts are pinned - the opportunistic path
    # deliberately takes whatever TLS the destination has, since its
    # alternative is cleartext, not failure.
    def harden(context)
      context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      context.ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20"
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
    # domain when the header is missing or unparseable.
    #
    # Failure policy (smtp_dkim_required, default on): a HOSTED domain -
    # one with a Domain record - whose signing fails (blank/unreadable
    # key, malformed message) defers via TransientError, so the outbound
    # queue retries with backoff and bounces to the author on exhaustion.
    # Sending it unsigned would quietly break DMARC alignment for a
    # domain we promised to align; a bounce tells someone. A domain with
    # NO Domain record still sends unsigned, loudly - that is a setup gap
    # (the domain was never added), not a signing failure, and holding
    # its mail hostage teaches the operator nothing a log line doesn't.
    #
    # Canonicalizes first (strip NUL, CRLF-only line endings) so a stored
    # smuggling probe cannot ride out as a DATA terminator. DKIM covers
    # the bytes we actually put on the wire.
    def signed(message)
      data = ensure_required_headers(OutboundData.canonicalize(message.data), message)
      data = inject_list_id(data, message)
      data = inject_list_unsubscribe(data, message)
      domain = signing_domain(data, message.mail_from)
      return data if domain.blank?

      record = Domain.find_by(name: domain)
      if record.nil?
        Rails.logger.warn "[mail_on_rails] outbound to <#{message.recipient}> goes out UNSIGNED: " \
                          "#{domain} has no Domain record - add it in the Domains UI to generate a DKIM key"
        return data
      end
      if record.dkim_private_key.blank?
        return unsigned_or_defer(data, message, domain, "the Domain record has no DKIM key")
      end

      Dkim.sign(data,
                domain: domain,
                selector: record.dkim_selector,
                private_key: OpenSSL::PKey.read(record.dkim_private_key))
    rescue TransientError
      raise
    rescue StandardError => e
      data ||= OutboundData.canonicalize(message.data)
      unsigned_or_defer(data, message, domain, "signing failed (#{e.class}: #{e.message})")
    end

    # RFC 5322 3.6 requires Date, and mail without a Message-ID is
    # filtered hard at the major providers. As the MSA we may supply both
    # (RFC 6409 8.2/8.3) - before signing, so DKIM covers them. Both are
    # derived from the queue row rather than the clock: a retry (or a
    # redelivery after a lost 250) must carry the same Message-ID and
    # Date as the earlier attempt, or receivers can't collapse the
    # duplicate. A missing From: can't be invented - it just gets a loud
    # log line (DKIM alignment falls back to the envelope domain).
    def ensure_required_headers(data, message)
      headers = data.partition("\r\n\r\n").first.split(/\r\n(?![ \t])/)
      missing_mid = headers.none? { |h| h.match?(/\AMessage-ID[ \t]*:/i) }
      missing_date = headers.none? { |h| h.match?(/\ADate[ \t]*:/i) }
      if headers.none? { |h| h.match?(/\AFrom[ \t]*:/i) }
        Rails.logger.warn "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> has no From: header"
      end
      return data unless missing_mid || missing_date

      injected = +""
      if missing_mid
        digest = OpenSSL::Digest::SHA256.hexdigest(data)[0, 16]
        injected << "Message-ID: <mor-#{message.id}-#{digest}@#{helo_host}>\r\n"
      end
      injected << "Date: #{(message.created_at || Time.current).rfc2822}\r\n" if missing_date
      Rails.logger.info "[mail_on_rails] outbound #{message.id}: injected " \
                        "#{[ (:message_id if missing_mid), (:date if missing_date) ].compact.join(" and ")} " \
                        "header(s) before signing"
      injected + data
    end

    # The unsigned-outbound policy fork for a hosted domain: defer when
    # DKIM is required (the queue's backoff/bounce takes it from there),
    # send unsigned with a loud warning when the operator opted out.
    def unsigned_or_defer(data, message, domain, reason)
      if MailOnRails::Settings[:smtp_dkim_required]
        raise TransientError, "DKIM signing for #{domain} is required but #{reason} - " \
                              "deferring delivery to <#{message.recipient}> (SMTP_DKIM_REQUIRED=0 sends unsigned)"
      end

      Rails.logger.warn "[mail_on_rails] outbound to <#{message.recipient}> goes out UNSIGNED: #{reason}"
      data
    end

    def signing_domain(data, mail_from)
      header_from = begin
        (Mail.read_from_string(data.to_s).from || []).first
      rescue StandardError
        nil
      end
      domain = header_from.to_s.split("@").last.to_s.strip.downcase
      domain = mail_from.to_s.split("@").last.to_s.strip.downcase if domain.blank?
      domain.presence
    end

    # An account flagged mailing_list declares everything it sends to BE
    # list mail: outbound messages without a List-ID get one stamped,
    # derived from the account address (RFC 2919's local.domain
    # convention) - which is exactly the marker inject_list_unsubscribe
    # keys on, so the one-click headers follow automatically. Unflagged
    # senders keep the old contract: the composing client's own List-ID
    # decides. A composer-provided List-ID always wins. Best-effort like
    # the other injections.
    def inject_list_id(data, message)
      sender = message.mail_from.to_s.strip.downcase
      return data if sender.empty?

      # The envelope sender may be an alias of the flagged account.
      account = EmailAccount.find_by(email: sender) || EmailAlias.find_by(email: sender)&.email_account
      return data unless account&.mailing_list?

      headers = data.partition("\r\n\r\n").first.split(/\r\n(?![ \t])/)
      return data if headers.any? { |h| h.match?(/\AList-ID[ \t]*:/i) }

      local, _, domain = sender.partition("@")
      "List-ID: <#{local.gsub(/[^a-z0-9._-]/, "-")}.#{domain}>\r\n" + data
    rescue StandardError => e
      Rails.logger.error "[mail_on_rails] List-ID injection failed for outbound #{message.id}: " \
                         "#{e.class}: #{e.message}"
      data
    end

    # List-Unsubscribe / List-Unsubscribe-Post for outbound list mail -
    # the Gmail/Yahoo bulk-sender mandate (RFC 8058 one-click). Gated hard:
    # only messages that declare themselves list mail (a List-ID header)
    # from a hosted sender domain, and never over headers the composer
    # already provided. Personal mail is never touched. Injected before
    # signing because RFC 8058 requires the headers under the DKIM
    # signature. The https target is the engine's anonymous
    # UnsubscribesController; the mailto: is the domain's unsubscribe@
    # ingestion account - both authorize purely via the signed token.
    # Best-effort: an injection bug must not take delivery down.
    def inject_list_unsubscribe(data, message)
      return data unless MailOnRails::Settings[:smtp_list_unsubscribe]

      headers = data.partition("\r\n\r\n").first.split(/\r\n(?![ \t])/)
      return data unless headers.any? { |h| h.match?(/\AList-ID[ \t]*:/i) }
      return data if headers.any? { |h| h.match?(/\AList-Unsubscribe[ \t]*:/i) }

      sender_domain = message.mail_from.to_s.split("@").last.to_s.strip.downcase
      return data if sender_domain.blank? || !Domain.exists?(name: sender_domain)

      token = CGI.escape(UnsubscribeToken.generate(recipient: message.recipient, sender: message.mail_from))
      targets = []
      targets << "<https://#{web_host}/unsubscribe/#{token}>" if web_host
      targets << "<mailto:#{Domain::UNSUBSCRIBE_LOCAL_PART}@#{sender_domain}?subject=unsubscribe%3A#{token}>"
      injected = +"List-Unsubscribe: #{targets.join(", ")}\r\n"
      # One-click (RFC 8058) is https-only; without a web host the mailto
      # alone still satisfies RFC 2369.
      injected << "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n" if web_host
      injected + data
    rescue StandardError => e
      Rails.logger.error "[mail_on_rails] List-Unsubscribe injection failed for outbound #{message.id}: " \
                         "#{e.class}: #{e.message}"
      data
    end

    # Where the one-click endpoint is reachable - the host serving this
    # app's web UI (same source DnsPublisher uses for the MTA-STS CNAME).
    # Blank means "no https endpoint": mailto-only injection.
    def web_host
      ENV["MAIL_ON_RAILS_WEB_HOST"].to_s.strip.downcase.presence
    end

    # What we announce in EHLO. Remote servers check this resolves back to
    # us, so production sets it to the public mail hostname (Settings page
    # or SMTP_HELO_HOST).
    def helo_host
      Setting.effective_smtp_helo_hostname
    end
  end
end
