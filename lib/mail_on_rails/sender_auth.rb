# frozen_string_literal: true

require_relative "settings"
require_relative "sender_auth/dns"
require_relative "sender_auth/from_header"
require_relative "sender_auth/spf"
require_relative "sender_auth/dkim"
require_relative "sender_auth/dmarc"
require_relative "sender_auth/arc"

module MailOnRails
  # Sender verification for unauthenticated inbound (MX) mail: SPF, DKIM
  # and DMARC, hand-rolled on plain DNS + OpenSSL. The SMTP server runs
  # this after DATA; the outcome is recorded on the stored message (and
  # can reject outright when DMARC enforcement is enabled).
  module SenderAuth
    Result = Struct.new(:spf, :dkim, :dmarc, :arc, keyword_init: true) do
      # Compact Authentication-Results-style value, e.g.
      #   "spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
      # This exact string is stamped on the message and parsed by the UI.
      def summary
        parts = [ "spf=#{spf[:result]}" ]
        parts.last << " smtp.mailfrom=#{spf[:domain]}" unless spf[:domain].to_s.empty?

        passing = dkim.select { |s| s[:result] == :pass }
        parts << "dkim=#{overall_dkim}"
        parts.last << " header.d=#{passing.map { |s| s[:domain] }.uniq.join(",")}" if passing.any?

        parts << "dmarc=#{dmarc[:result]}"
        parts.last << " header.from=#{dmarc[:from_domain]}" unless dmarc[:from_domain].to_s.empty?

        if arc && arc[:result] != :none
          parts << "arc=#{arc[:result]}"
          parts.last << " arc.d=#{arc[:sealer]}" unless arc[:sealer].to_s.empty?
        end
        parts.join("; ")
      end

      # An intact ARC chain (RFC 8617) whose newest sealer the operator
      # listed in smtp_arc_trusted_sealers: the sanctioned local-policy
      # override for a DMARC reject broken by forwarding (RFC 7489 6.7).
      def arc_trusted_pass?
        return false unless arc && arc[:result] == :pass

        sealer = arc[:sealer].to_s
        !sealer.empty? && Settings[:smtp_arc_trusted_sealers].any? { |domain| sealer.casecmp?(domain.to_s.strip) }
      end

      def arc_sealer
        arc&.dig(:sealer)
      end

      # The domain owner published p=reject and nothing aligned.
      def dmarc_reject?
        dmarc[:result] == :fail && dmarc[:policy] == :reject
      end

      # DMARC evaluation could not complete (transient DNS failure), so
      # there is no trustworthy verdict either way. Under fail-closed
      # enforcement the session tempfails these instead of accepting.
      def temperror?
        dmarc[:result] == :temperror
      end

      def from_domain
        dmarc[:from_domain]
      end

      def overall_dkim
        results = dkim.map { |s| s[:result] }
        if results.include?(:pass) then :pass
        elsif results.empty? then :none
        elsif results.include?(:fail) then :fail
        elsif results.include?(:temperror) then :temperror
        else :permerror
        end
      end
    end

    # Master switch for the verifiers, read through the settings schema
    # per message (checked after DATA, so toggling applies to the next
    # message without a restart); per-listener spec[:sender_auth]
    # overrides it (the test seam). On by default - disabling is for
    # local try-outs where live DNS lookups per message are unwanted.
    def self.enabled? = Settings[:smtp_sender_auth]

    # Reject at SMTP time on DMARC p=reject failures? On by default -
    # verdicts are recorded either way; SMTP_DMARC_ENFORCE=0 drops back
    # to log-only while soaking the verifiers against real traffic.
    def self.enforce_dmarc? = Settings[:smtp_dmarc_enforce]

    # Tempfail instead of accept when enforcement is on but a transient
    # DNS error left DMARC without a verdict? On by default - a DNS
    # outage must not become a spoofing window.
    def self.fail_closed? = Settings[:smtp_sender_auth_fail_closed]

    def self.verify(ip:, helo:, mail_from:, data:, resolver: Dns.shared)
      spf = Spf.new(resolver).check(ip: ip, sender: mail_from, helo: helo)
      dkim = Dkim.new(resolver).verify(data)
      dmarc = Dmarc.new(resolver).evaluate(from_domain: from_domain(data), spf: spf, dkim: dkim)
      arc = Arc.new(resolver).evaluate(data)
      Result.new(spf: spf, dkim: dkim, dmarc: dmarc, arc: arc)
    end

    # The visible From: header domain - DMARC's subject. Nil when absent,
    # unparseable, or not exactly one address (DMARC has no defined
    # verdict there, and nil makes evaluate return permerror).
    def self.from_domain(data)
      FromHeader.domain(data)
    rescue StandardError
      nil
    end
  end
end
