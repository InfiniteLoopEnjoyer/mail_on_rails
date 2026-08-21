# frozen_string_literal: true

require "ipaddr"
require "mail_on_rails/sender_auth/dns"

module MailOnRails
  # Dependency-free IP attribution for honeypot events: origin ASN, AS name,
  # country, and reverse DNS. Everything comes over DNS, the same transport the
  # SPF/DKIM/DMARC and DNSBL paths already use - no MaxMind database, no HTTP
  # API, no key. Team Cymru's IP-to-ASN service (cymru.com/BGP/asnlookup.shtml)
  # answers TXT queries:
  #
  #   <reversed-ip>.origin.asn.cymru.com  -> "ASN | prefix | CC | registry | date"
  #   AS<asn>.asn.cymru.com               -> "ASN | CC | registry | date | AS name"
  #
  # Runs off the connection thread (HoneypotEnrichmentJob), so its blocking DNS
  # never touches the live protocol path. Best-effort throughout: any missing or
  # failing lookup leaves that field nil rather than raising.
  #
  # Accepted trade-off: the PTR (and Cymru origin) queries are about the
  # probing IP, so an attacker running their own authoritative DNS for that
  # space can see our resolver's address in their query logs. Inherent to
  # DNS-based enrichment; bounded to one enrichment per honeypot session,
  # with answers cached ~60s.
  class CymruLookup
    Result = Data.define(:asn, :as_name, :country, :prefix, :rdns)

    def self.lookup(ip, resolver: SenderAuth::Dns.shared)
      new(resolver).lookup(ip)
    end

    def initialize(resolver)
      @resolver = resolver
    end

    def lookup(ip)
      origin = origin_record(ip)
      asn = origin&.dig(:asn)
      {
        asn: asn,
        as_name: asn && as_name(asn),
        country: origin&.dig(:country),
        prefix: origin&.dig(:prefix),
        rdns: rdns(ip)
      }
    rescue StandardError
      {}
    end

    private

    # The origin-AS record for +ip+: the first field is the ASN (Cymru may
    # return several space-separated ASNs for multi-origin prefixes; the first
    # is enough for attribution).
    def origin_record(ip)
      name = origin_name(ip)
      return nil unless name

      record = txt(name).first
      return nil if record.nil?

      asn, prefix, country, = record.split("|").map(&:strip)
      { asn: asn.to_s.split(/\s+/).first.presence, prefix: prefix.presence, country: country.presence }
    end

    def as_name(asn)
      record = txt("AS#{asn}.asn.cymru.com").first
      return nil if record.nil?

      # "ASN | CC | registry | allocated | AS name, CC"
      record.split("|").last&.strip.presence
    end

    def origin_name(ip)
      addr = IPAddr.new(ip.to_s)
      zone = addr.ipv6? ? "origin6.asn.cymru.com" : "origin.asn.cymru.com"
      "#{addr.reverse.sub(/\.(in-addr|ip6)\.arpa\z/, "")}.#{zone}"
    rescue IPAddr::InvalidAddressError
      nil
    end

    def rdns(ip)
      @resolver.ptr(ip).first&.chomp(".").presence
    rescue StandardError
      nil
    end

    def txt(name)
      @resolver.txt(name)
    rescue StandardError
      []
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_cymru_lookup, MailOnRails::CymruLookup
