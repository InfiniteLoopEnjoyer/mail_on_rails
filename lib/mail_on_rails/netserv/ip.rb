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
  end
end
