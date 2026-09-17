# frozen_string_literal: true

require "ipaddr"
require_relative "dns"

module MailOnRails
  module SenderAuth
    # Forward-confirmed reverse DNS: the PTR names of an address that
    # resolve back to it. A bare PTR is whatever the owner of the address
    # space wrote - an attacker can point theirs at "mail.google.com" - so
    # only a name whose own A/AAAA records include the address says
    # anything about who is behind it.
    #
    # Unlike the SMTP edge's per-connection FCrDNS (which folds a resolver
    # failure into "no name", fine for a Received header), a failure here
    # raises: the caller is deciding on a permanent ban, and "DNS was down"
    # must not read as "nobody vouches for this address".
    module ConfirmedPtr
      # A PTR RRset can be arbitrarily large; each name costs a forward
      # lookup.
      MAX_NAMES = 5

      # Lowercased names without the trailing dot, [] when the address has
      # no PTR or none confirms. Raises Dns::TempError when the PTR lookup
      # failed, or when no name confirmed and a forward lookup failed (the
      # answer might have been among the ones we could not get).
      def self.names(ip, resolver: Dns.shared)
        addr = IPAddr.new(ip.to_s)
        addr = addr.native if addr.ipv4_mapped?
        failure = nil
        confirmed = resolver.ptr(addr.to_s).first(MAX_NAMES).filter_map do |name|
          name = name.to_s.downcase.chomp(".")
          next if name.empty?

          forward = addr.ipv4? ? resolver.a(name) : resolver.aaaa(name)
          name if forward.any? { |answer| same_address?(answer, addr) }
        rescue Dns::TempError => e
          failure = e
          nil
        end
        raise failure if confirmed.empty? && failure

        confirmed
      rescue IPAddr::Error
        []
      end

      def self.same_address?(answer, addr)
        IPAddr.new(answer.to_s) == addr
      rescue IPAddr::Error
        false
      end
      private_class_method :same_address?
    end
  end
end
