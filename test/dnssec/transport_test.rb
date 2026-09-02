# frozen_string_literal: true

require "test_helper"
require "socket"

# The resolver's wire client: CD+DO on every query, and fallback
# nameservers picking up only after every primary fails.
class TransportTest < Minitest::Test
  # One-shot loopback DNS responder; hands back the decoded queries it saw.
  class Responder
    attr_reader :port, :seen

    def initialize(ip: "127.0.0.1", port: 0, rcode: Dnsruby::RCode.NOERROR)
      @socket = UDPSocket.new
      @socket.bind(ip, port)
      @port = @socket.addr[1]
      @rcode = rcode
      @seen = []
      @thread = Thread.new { serve }
    end

    def serve
      loop do
        data, addr = @socket.recvfrom(4096)
        query = Dnsruby::Message.decode(data)
        @seen << query
        reply = Dnsruby::Message.new
        reply.header.id = query.header.id
        reply.header.qr = true
        reply.header.rcode = @rcode
        query.question.each { |q| reply.add_question(q.qname, q.qtype) }
        @socket.send(reply.encode, 0, addr[3], addr[1])
      end
    rescue IOError
      nil
    end

    def close
      @socket.close
      @thread.kill
    end
  end

  def teardown
    @responder&.close
    @fallback&.close
  end

  test "queries go out with CD and the EDNS DO bit" do
    @responder = Responder.new
    transport = MailOnRails::Dnssec::Transport.new(
      nameservers: [ "127.0.0.1" ], port: @responder.port, fallback_nameservers: [], timeout: 3
    )

    reply = transport.query("example.test.", "TLSA")
    assert_equal Dnsruby::RCode.NOERROR, reply.rcode

    query = @responder.seen.first
    assert query.header.cd, "CD must be set - upstream validation would filter the data we judge ourselves"
    opt = query.additional.find { |rr| rr.type == Dnsruby::Types.OPT }
    refute_nil opt, "the query must carry an EDNS OPT record"
    assert opt.dnssec_ok, "the DO bit asks for RRSIGs and NSEC records"
  end

  test "fallback nameservers answer when every primary fails" do
    @responder = Responder.new
    # 127.0.0.2 has nothing bound on the responder's port: connected UDP
    # on loopback fails fast with ECONNREFUSED.
    transport = MailOnRails::Dnssec::Transport.new(
      nameservers: [ "127.0.0.2" ], port: @responder.port,
      fallback_nameservers: [ "127.0.0.1" ], timeout: 3
    )

    reply = transport.query("example.test.", "A")
    assert_equal Dnsruby::RCode.NOERROR, reply.rcode
    assert_equal 1, @responder.seen.size, "the fallback server should have been asked exactly once"
  end

  test "a SERVFAIL from a primary falls through to the fallbacks" do
    # docker's embedded DNS answers SERVFAIL for some DNSSEC queries the
    # public resolvers handle fine; a definitive-looking rcode must count
    # as a failed server, not as the answer.
    @responder = Responder.new(rcode: Dnsruby::RCode.SERVFAIL)
    @fallback = Responder.new(ip: "127.0.0.2", port: @responder.port)
    transport = MailOnRails::Dnssec::Transport.new(
      nameservers: [ "127.0.0.1" ], port: @responder.port,
      fallback_nameservers: [ "127.0.0.2" ], timeout: 3
    )

    reply = transport.query("example.test.", "TLSA")
    assert_equal Dnsruby::RCode.NOERROR, reply.rcode
    assert_equal 1, @responder.seen.size, "the SERVFAILing primary should have been asked"
    assert_equal 1, @fallback.seen.size, "the fallback should have answered after the SERVFAIL"
  end

  test "every server answering SERVFAIL raises TempError naming the rcode" do
    @responder = Responder.new(rcode: Dnsruby::RCode.SERVFAIL)
    transport = MailOnRails::Dnssec::Transport.new(
      nameservers: [ "127.0.0.1" ], port: @responder.port, fallback_nameservers: [], timeout: 3
    )

    error = assert_raises(MailOnRails::Dnssec::Transport::TempError) do
      transport.query("example.test.", "TLSA")
    end
    assert_match(/SERVFAIL/, error.message)
  end

  test "NXDOMAIN is an answer, not a server failure" do
    @responder = Responder.new(rcode: Dnsruby::RCode.NXDOMAIN)
    @fallback = Responder.new(ip: "127.0.0.2", port: @responder.port)
    transport = MailOnRails::Dnssec::Transport.new(
      nameservers: [ "127.0.0.1" ], port: @responder.port,
      fallback_nameservers: [ "127.0.0.2" ], timeout: 3
    )

    reply = transport.query("example.test.", "TLSA")
    assert_equal Dnsruby::RCode.NXDOMAIN, reply.rcode
    assert_equal 0, @fallback.seen.size, "a negative answer must not trigger the fallbacks"
  end

  test "with fallbacks disabled a dead primary raises TempError" do
    transport = MailOnRails::Dnssec::Transport.new(
      nameservers: [ "127.0.0.2" ], port: 9, fallback_nameservers: [], timeout: 1
    )

    assert_raises(MailOnRails::Dnssec::Transport::TempError) do
      transport.query("example.test.", "A")
    end
  end
end
