# frozen_string_literal: true

require "ipaddr"
require_relative "../netserv/config"
require_relative "sender_auth/dns"

module MailOnRails
  module Smtp
    # DNSBL (RBL) checks for unauthenticated MX traffic: reverse the peer
    # IP's octets (nibbles for IPv6), append a configured blocklist zone
    # (SMTP_RBLS, comma/space separated, e.g. "zen.spamhaus.org"),
    # and A-query it. An answer inside 127.0.0.0/8 means "listed" (RFC
    # 5782); the session then refuses the MAIL FROM.
    #
    # Fails open on purpose - a DNS timeout, a SERVFAIL, or a decommissioned
    # zone must never refuse the world's mail. Verdicts (including fail-open
    # ones) are cached per IP for CACHE_TTL seconds, so a busy or abusive
    # peer costs one zone walk per TTL, not one per message.
    #
    # One process-wide instance (see .shared): sessions each run on their
    # own short-lived connection thread, so a per-thread cache would never
    # hit - the shared verdict cache is what keeps a busy peer at one zone
    # walk per TTL.
    class Dnsbl
      # Parsed at load - in the app these files load from the Puma plugin,
      # with the environment already set. Empty means disabled.
      ZONES = ENV["SMTP_RBLS"].to_s.split(/[\s,]+/).reject(&:empty?).freeze
      CACHE_TTL = Netserv::Config.int("SMTP_RBL_CACHE_TTL", 600, min: 1)
      SWEEP_THRESHOLD = 10_000 # purge expired verdicts when the cache grows past this

      # The process-wide checker, or nil when no zones are configured.
      SHARED_LOCK = Mutex.new
      def self.shared
        return nil if ZONES.empty?

        SHARED_LOCK.synchronize { @shared ||= new(zones: ZONES) }
      end

      # resolver and clock are injectable for tests; clock must be monotonic.
      def initialize(zones:, resolver: SenderAuth::Dns.shared, ttl: CACHE_TTL,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @zones = zones
        @resolver = resolver
        @ttl = ttl
        @clock = clock
        @cache = {} # ip => [zone or nil, expires_at]
        @cache_lock = Mutex.new
      end

      # The first configured zone listing +ip+, or nil: unlisted, cached
      # fail-open verdict, unparseable/private peer address. Zones are
      # checked in the configured order, so put the broadest first. The
      # instance is shared across connection threads: cache access is
      # locked, the zone walk runs outside the lock (a cache-miss race
      # costs a duplicate walk, never a wrong verdict).
      def listed(ip)
        name = reversed(ip)
        return nil unless name

        cached = :miss
        @cache_lock.synchronize do
          verdict, expires_at = @cache[ip]
          cached = verdict if expires_at && expires_at > @clock.call
        end
        return cached unless cached == :miss

        verdict = @zones.find { |zone| listed_in?(name, zone) }
        @cache_lock.synchronize do
          now = @clock.call
          sweep(now) if @cache.size >= SWEEP_THRESHOLD
          @cache[ip] = [ verdict, now + @ttl ]
        end
        verdict
      end

      private

      def listed_in?(name, zone)
        @resolver.a("#{name}.#{zone}").any? { |addr| listing_code?(addr) }
      rescue SenderAuth::Dns::TempError
        false # fail open: this zone is unreachable, not "everyone is listed"
      end

      # RFC 5782: a listing answers within 127.0.0.0/8; anything else is a
      # wildcard accident (expired domain, captive resolver) and must be
      # ignored. 127.255.255.0/24 is Spamhaus's error band ("you query via
      # a public resolver" / "query limit exceeded"), which likewise must
      # not read as a listing.
      def listing_code?(addr)
        addr.start_with?("127.") && !addr.start_with?("127.255.255.")
      end

      # The DNSBL query labels: the PTR name minus its .in-addr.arpa /
      # .ip6.arpa suffix. Loopback/private/link-local peers are never on a
      # public blocklist and never worth a query.
      def reversed(ip)
        addr = IPAddr.new(ip.to_s)
        return nil if addr.loopback? || addr.private? || addr.link_local?

        addr.reverse.sub(/\.(in-addr|ip6)\.arpa\z/, "")
      rescue IPAddr::InvalidAddressError
        nil # peer address was unavailable ("?") or not an IP
      end

      def sweep(now)
        @cache.delete_if { |_ip, (_verdict, expires_at)| expires_at <= now }
      end
    end
  end
end
