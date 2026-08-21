# frozen_string_literal: true

require "socket"

module MailOnRails
  module Dnssec
    # Wire client for the validating stub resolver: sends queries with
    # CD (checking disabled - the upstream recursive must hand over data
    # it considers bogus, because judging it is our job) and the EDNS DO
    # bit, over UDP with TCP fallback on truncation.
    #
    # dnsruby's own resolver is not used: its select-thread transport
    # holds class-level state (hostile to the worker Ractors the servers
    # run in) and proved unreliable here. Only dnsruby's Message codec is
    # trusted. Injectable in tests - anything responding to
    # query(name, type) => Dnsruby::Message can stand in.
    class Transport
      class TempError < StandardError; end

      TIMEOUT = 5
      PORT = 53
      UDP_SIZE = 1232 # fragmentation-safe EDNS ceiling; larger answers go TCP

      # Tried only after every primary nameserver has failed a query.
      # Chain-of-trust walks ask for things ordinary stubs never see -
      # the root DNSKEY RRset in particular is a large answer some
      # forwarding stubs simply cannot serve - and with validation
      # in-process these carry no trust, so falling back to a public
      # recursive costs availability nothing and saves outbound mail
      # from deferring behind a half-capable local stub.
      FALLBACK_NAMESERVERS = [ "8.8.8.8", "1.1.1.1" ].freeze

      # Parsed once, like SenderAuth::Dns - resolv.conf changes
      # need a process restart, which container deploys do anyway.
      def self.system_nameservers
        servers = File.readlines("/etc/resolv.conf", chomp: true)
                      .filter_map { |line| line[/\Anameserver\s+(\S+)/, 1] }
        servers.empty? ? [ "127.0.0.1" ] : servers.first(3)
      rescue SystemCallError
        [ "127.0.0.1" ]
      end

      def initialize(nameservers: nil, timeout: TIMEOUT, port: PORT,
                     fallback_nameservers: FALLBACK_NAMESERVERS)
        @nameservers = nameservers || self.class.system_nameservers
        @fallbacks = (Array(fallback_nameservers) - @nameservers).freeze
        @timeout = timeout
        @port = port
      end

      # One question out, one decoded reply back (id-checked; truncated
      # replies retried over TCP). Fallback nameservers are consulted
      # only once every primary has failed; TempError raises when all of
      # them have.
      def query(name, type)
        request = build_query(name, type)
        payload = request.encode
        errors = []
        (@nameservers + @fallbacks).each do |server|
          reply = udp_exchange(server, payload, request.header.id)
          reply = tcp_exchange(server, payload, request.header.id) if reply&.header&.tc
          return reply if reply
        rescue IO::TimeoutError, SystemCallError, SocketError, Dnsruby::DecodeError => e
          errors << "#{server}: #{e.class}"
        end
        raise TempError, "DNS lookup failed for #{name} #{type} (#{errors.join(", ")})"
      end

      private

      def build_query(name, type)
        msg = Dnsruby::Message.new(name, type)
        msg.header.rd = true
        msg.header.cd = true
        opt = Dnsruby::RR::OPT.new(UDP_SIZE)
        opt.dnssec_ok = true
        msg.add_additional(opt)
        msg
      end

      def udp_exchange(server, payload, id)
        socket = UDPSocket.new(Addrinfo.ip(server).afamily)
        socket.timeout = @timeout
        socket.connect(server, @port)
        socket.send(payload, 0)
        # A few tries: a mismatched id is a stray/spoofed datagram, not
        # the reply. Bounded so a flood can't spin this thread forever.
        4.times do
          reply = decode(socket.recv(UDP_SIZE * 4))
          return reply if reply&.header&.id == id
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
          raise TempError, "DNS TCP reply id mismatch from #{server}" unless reply&.header&.id == id

          reply
        end
      end

      def decode(data)
        Dnsruby::Message.decode(data)
      rescue Dnsruby::DecodeError
        nil
      end
    end
  end
end
