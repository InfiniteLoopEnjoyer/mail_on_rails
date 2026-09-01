# frozen_string_literal: true

require "ipaddr"

module MailOnRails
  module Netserv
    # The one canonical spelling of a peer address, so every per-IP surface
    # (bans, SPF, DNSBL, FCrDNS, limiters, ops rows, kicks) keys on the same
    # string. A dual-stack "::" listener hands IPv4 peers over as v4-mapped
    # IPv6 ("::ffff:203.0.113.5"): IPAddr treats that as an IPv6 address, so
    # left alone it would silently miss every IPv4 ban and ip4: mechanism.
    # Unmapped here, right where accept(2) reports it. Anything that doesn't
    # parse (nil, the "?" placeholder) passes through untouched.
    def self.canonical_ip(ip)
      return ip if ip.nil?

      addr = IPAddr.new(ip.to_s)
      addr.ipv4_mapped? ? addr.native.to_s : addr.to_s
    rescue IPAddr::Error
      ip
    end

    # The key the per-IP abuse controls (ConnLimiter, RateLimiter, the
    # AuthThrottles, the audit-log rollups) count against. IPv4 keys on
    # the canonical address. IPv6 keys on the /64 - spelled "2001:db8::/64"
    # so it can never be mistaken for a host - because a single customer
    # holds at least a /64 (RFC 6177) and can source every connection from
    # a fresh /128 inside it for free: per-address caps on IPv6 bound
    # nothing. Only the CONTROLS key this way; logging, Received headers,
    # the ops UI, bans and kicks keep the full address. Idempotent, and
    # anything unparseable passes through like canonical_ip.
    def self.throttle_key(ip)
      return ip if ip.nil?

      addr = IPAddr.new(ip.to_s)
      addr = addr.native if addr.ipv4_mapped?
      addr.ipv4? ? addr.to_s : "#{addr.mask(64)}/64"
    rescue IPAddr::Error
      ip
    end

    # Address space an outbound connection made on a recipient's say-so
    # (MTA-STS policy hosts, MX/A targets, BIMI logos) must never reach:
    # private, link-local, loopback, CGNAT, documentation, multicast,
    # v4-mapped and the IPv6 ULA range (which is what a container network
    # lives in). TLS verification stops data exfiltration; this stops the
    # blind connect/port-probe primitive.
    NON_ROUTABLE = [
      "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
      "169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16",
      "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
      "::/127", "::ffff:0:0/96", "64:ff9b::/96", "100::/64",
      "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8"
    ].map { |cidr| IPAddr.new(cidr) }.freeze

    # False for anything in NON_ROUTABLE and for anything that is not an
    # address at all.
    def self.routable?(ip)
      addr = ip.is_a?(IPAddr) ? ip : IPAddr.new(ip.to_s)
      NON_ROUTABLE.none? { |net| net.include?(addr) }
    rescue IPAddr::Error
      false
    end
  end
end
