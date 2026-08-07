# frozen_string_literal: true

require "resolv"
require "ipaddr"
require "socket"
require_relative "../../netserv/config"

module MailOnRails
  module Smtp
    module SenderAuth
      # Minimal DNS client for sender verification (SPF/DKIM/DMARC) lookups.
      # Every method returns an array of strings; a name with no matching
      # records is an empty array.
      #
      # Verifiers accept anything with this five-method interface, so tests
      # inject a hash-backed fake and never touch the network.
      #
      # The transport is our own (UDP with TCP fallback on truncation,
      # straight to the resolv.conf nameservers); only Resolv's wire codec
      # is reused. Two reasons over plain Resolv:
      #
      #   - Resolv's query path is not Ractor-safe (@@identifier class
      #     variable in Resolv::DNS::Message, class-level config caches),
      #     and sessions run inside worker Ractors. The codec is safe as
      #     long as message ids are passed explicitly and resolv is
      #     required by the main Ractor at boot (this file's require).
      #   - Resolv cannot distinguish NXDOMAIN from SERVFAIL or a timeout.
      #     Here NXDOMAIN/no-answer is [], while SERVFAIL, malformed
      #     replies, and unreachable/timing-out nameservers raise
      #     TempError, so a DNS outage reads as temperror rather than
      #     silently weakening a verdict to "no record".
      #
      # Answers (including "no record") are cached per name and type for a
      # short TTL - big senders deliver many messages in a burst, each
      # re-fetching the same SPF/DKIM/DMARC records. The cache honors
      # record TTLs below the cap and never caches failures (a resolver
      # blip must not pin temperror verdicts). Use .shared for the
      # process-wide client so every connection thread shares the cache.
      class Dns
        class TempError < StandardError; end

        TIMEOUT = Netserv::Config.int("SMTP_DNS_TIMEOUT", 5, min: 1)
        # Cap in seconds on how long an answer is cached (the records' own
        # TTLs bind below it); 0 disables caching.
        CACHE_TTL = Netserv::Config.int("SMTP_DNS_CACHE_TTL", 60)
        SWEEP_THRESHOLD = 10_000 # purge expired answers when the cache grows past this
        PORT = 53
        MAX_UDP = 4096

        # Parsed once at load and frozen. resolv.conf changes need a
        # process restart, which container deploys do anyway.
        SYSTEM_NAMESERVERS = begin
          servers = File.readlines("/etc/resolv.conf", chomp: true)
                        .filter_map { |line| line[/\Anameserver\s+(\S+)/, 1] }
          servers.empty? ? [ "127.0.0.1" ] : servers.first(3)
        rescue SystemCallError
          [ "127.0.0.1" ]
        end.freeze

        # The process-wide client. Sessions each run on their own
        # short-lived connection thread, so a per-thread cache would never
        # hit; one shared instance with a mutex-guarded cache is what makes
        # the burst-sender caching real.
        SHARED_LOCK = Mutex.new
        def self.shared
          SHARED_LOCK.synchronize { @shared ||= new }
        end

        # port, cache_ttl and clock are injectable so tests can stand up a
        # loopback DNS server and steer expiry; clock must be monotonic.
        def initialize(nameservers: SYSTEM_NAMESERVERS, timeout: TIMEOUT, port: PORT,
                       cache_ttl: CACHE_TTL, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @nameservers = nameservers
          @timeout = timeout
          @port = port
          @cache_ttl = cache_ttl
          @clock = clock
          @cache = {} # "<typeclass> <name>" => [records, expires_at]
          @cache_lock = Mutex.new
        end

        # TXT: each record's character-strings joined, one string per record.
        def txt(name)
          resources(name, Resolv::DNS::Resource::IN::TXT).map { |r| r.strings.join }
        end

        def a(name)
          resources(name, Resolv::DNS::Resource::IN::A).map { |r| r.address.to_s }
        end

        def aaaa(name)
          resources(name, Resolv::DNS::Resource::IN::AAAA).map { |r| r.address.to_s }
        end

        # Hostnames sorted by preference.
        def mx(name)
          resources(name, Resolv::DNS::Resource::IN::MX)
            .sort_by(&:preference).map { |r| r.exchange.to_s }
        end

        def ptr(ip)
          reverse = IPAddr.new(ip.to_s).reverse
          resources(reverse, Resolv::DNS::Resource::IN::PTR).map { |r| r.name.to_s }
        rescue IPAddr::InvalidAddressError
          []
        end

        # DNSSEC-flagged answers for the outbound DANE path. +secure+ is
        # the response's AD bit: it is only meaningful when the configured
        # resolver validates DNSSEC (we request it with the DO bit but
        # trust, not verify, the validation).
        Answer = Struct.new(:records, :secure, keyword_init: true)
        Tlsa = Struct.new(:usage, :selector, :matching_type, :data, keyword_init: true)

        # TLSA (RFC 6698) has no first-class Resolv resource; the generic
        # type carries the raw RDATA which tlsa() unpacks itself.
        TLSA_TYPE = Resolv::DNS::Resource::Generic.create(52, 1)

        # TLSA records for a name like "_25._tcp.mx.example.com".
        def tlsa(name)
          records, secure = answer_with_security(name, TLSA_TYPE)
          parsed = records.filter_map do |record|
            data = record.data.to_s.b
            next if data.bytesize < 4

            Tlsa.new(usage: data.getbyte(0), selector: data.getbyte(1),
                     matching_type: data.getbyte(2), data: data.byteslice(3..))
          end
          Answer.new(records: parsed, secure: secure)
        end

        # MX [preference, exchange] pairs sorted by preference, with the
        # AD flag - DANE only applies below a DNSSEC-secure MX RRset.
        def mx_answer(name)
          records, secure = answer_with_security(name, Resolv::DNS::Resource::IN::MX)
          pairs = records.sort_by(&:preference).map { |r| [ r.preference, r.exchange.to_s ] }
          Answer.new(records: pairs, secure: secure)
        end

        private

        # Like resources(), but queries with the EDNS0 DO bit and returns
        # [records, ad_flag]. Cached under its own key: the same name and
        # type resolved without DNSSEC stores a different value shape.
        def answer_with_security(name, typeclass)
          key = "dnssec #{typeclass.name} #{name.to_s.downcase}"
          if (cached = cache_fetch(key))
            return cached
          end

          reply = exchange(name.to_s, typeclass, dnssec: true)
          secure = reply.instance_variable_get(:@mail_on_rails_ad) || false
          case reply.rcode
          when Resolv::DNS::RCode::NoError
            records = reply.answer.filter_map { |_owner, _ttl, record| record if record.is_a?(typeclass) }
            cache_store(key, [ records, secure ], reply.answer.map { |_owner, ttl, _record| ttl })
          when Resolv::DNS::RCode::NXDomain
            cache_store(key, [ [], secure ], [])
          else
            raise TempError, "DNS rcode #{reply.rcode} for #{name}"
          end
        end

        def resources(name, typeclass)
          key = "#{typeclass.name} #{name.to_s.downcase}"
          if (records = cache_fetch(key))
            return records
          end

          reply = exchange(name.to_s, typeclass)
          case reply.rcode
          when Resolv::DNS::RCode::NoError
            records = reply.answer.filter_map { |_owner, _ttl, record| record if record.is_a?(typeclass) }
            cache_store(key, records, reply.answer.map { |_owner, ttl, _record| ttl })
          when Resolv::DNS::RCode::NXDomain
            cache_store(key, [], [])
          else
            raise TempError, "DNS rcode #{reply.rcode} for #{name}"
          end
        end

        # A cached answer (possibly empty), or nil on miss/expiry. The
        # instance is shared across connection threads, so cache access is
        # locked; queries themselves run outside the lock (a cache-miss
        # race costs one duplicate query, never a wrong answer).
        def cache_fetch(key)
          return nil unless @cache_ttl.positive?

          @cache_lock.synchronize do
            records, expires_at = @cache[key]
            records if expires_at && expires_at > @clock.call
          end
        end

        # Caches for the smaller of the cap and the answer's own record
        # TTLs (a 0-TTL record therefore never effectively caches). Only
        # answers land here - TempError propagates before this point.
        def cache_store(key, records, ttls)
          return records unless @cache_ttl.positive?

          @cache_lock.synchronize do
            now = @clock.call
            sweep(now) if @cache.size >= SWEEP_THRESHOLD
            @cache[key] = [ records, now + [ @cache_ttl, *ttls ].min ]
          end
          records
        end

        def sweep(now)
          @cache.delete_if { |_key, (_records, expires_at)| expires_at <= now }
        end

        # Asks each nameserver in turn; first decodable reply wins. Raises
        # TempError once every nameserver has timed out or errored.
        def exchange(name, typeclass, dnssec: false)
          id = rand(0x10000)
          payload = build_query(id, name, typeclass, dnssec: dnssec)
          errors = []
          @nameservers.each do |server|
            reply = udp_exchange(server, payload, id)
            reply = tcp_exchange(server, payload, id) if reply&.tc == 1
            return reply if reply
          rescue IO::TimeoutError, SystemCallError, SocketError, Resolv::DNS::DecodeError => e
            errors << "#{server}: #{e.class}"
          end
          raise TempError, "DNS lookup failed for #{name} (#{errors.join(", ")})"
        end

        def build_query(id, name, typeclass, dnssec: false)
          # Explicit id: the default taps a Ractor-hostile class variable.
          message = Resolv::DNS::Message.new(id)
          message.rd = 1
          message.add_question(Resolv::DNS::Name.create(absolute(name)), typeclass)
          payload = message.encode
          dnssec ? with_edns_do(payload) : payload
        end

        # Resolv's encoder has no EDNS support, so the OPT pseudo-record
        # (RFC 6891) asking for DNSSEC is spliced in by hand: bump ARCOUNT
        # (header bytes 10-11) and append root name, TYPE 41, CLASS = our
        # UDP payload size, TTL = flags with the DO bit, empty RDATA.
        EDNS_UDP_SIZE = 1232 # the fragmentation-safe ceiling; larger answers fall back to TCP
        def with_edns_do(payload)
          arcount = payload.byteslice(10, 2).unpack1("n")
          payload.byteslice(0, 10) + [ arcount + 1 ].pack("n") + payload.byteslice(12..).to_s +
            "\x00".b + [ 41, EDNS_UDP_SIZE, 0x0000_8000, 0 ].pack("nnNn")
        end

        def absolute(name)
          name.end_with?(".") ? name : "#{name}."
        end

        def udp_exchange(server, payload, id)
          socket = UDPSocket.new(Addrinfo.ip(server).afamily)
          socket.timeout = @timeout # honored by IO and by Scheduler in workers
          socket.connect(server, @port)
          socket.send(payload, 0)
          # A few tries: a mismatched id is a stray/spoofed datagram, not
          # the reply. Bounded so a flood can't spin this fiber forever.
          4.times do
            reply = decode(socket.recv(MAX_UDP))
            return reply if reply&.id == id
          end
          nil
        ensure
          socket&.close
        end

        def tcp_exchange(server, payload, id)
          Socket.tcp(server, @port, connect_timeout: @timeout) do |socket|
            socket.timeout = @timeout
            socket.write([ payload.bytesize ].pack("n") + payload)
            length = socket.read(2)&.unpack1("n")
            raise TempError, "DNS TCP reply truncated from #{server}" if length.nil?

            reply = decode(socket.read(length).to_s)
            raise TempError, "DNS TCP reply id mismatch from #{server}" unless reply&.id == id

            reply
          end
        end

        def decode(data)
          message = Resolv::DNS::Message.decode(data)
          # Resolv's decoder drops the AD (authenticated data) header bit;
          # read it off the wire (byte 3, mask 0x20) for the DANE path.
          message.instance_variable_set(:@mail_on_rails_ad, (data.getbyte(3) & 0x20) != 0)
          message
        rescue Resolv::DNS::DecodeError
          nil
        end
      end
    end
  end
end
