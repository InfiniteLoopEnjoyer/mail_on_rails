# frozen_string_literal: true

require "test_helper"
require "socket"

# The resolver's wire client: CD+DO on every query, and fallback
# nameservers picking up only after every primary fails.
class TransportTest < Minitest::Test
  # One-shot loopback DNS responder; hands back the decoded queries it saw.
  class Responder
    attr_reader :port, :seen

    # With a block, the block scripts the datagrams sent back for each
    # query: (decoded query, the honest reply) -> array of byte strings.
    def initialize(ip: "127.0.0.1", port: 0, rcode: Dnsruby::RCode.NOERROR, &script)
      @socket = UDPSocket.new
      @socket.bind(ip, port)
      @port = @socket.addr[1]
      @rcode = rcode
      @script = script
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
        datagrams = @script ? @script.call(query, reply) : [ reply.encode ]
        datagrams.each { |bytes| @socket.send(bytes, 0, addr[3], addr[1]) }
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

  # ----- reply matching and undecodable replies -------------------------

  def transport_to(responder, fallback: nil, timeout: 3)
    MailOnRails::Dnssec::Transport.new(
      nameservers: [ "127.0.0.1" ], port: responder.port,
      fallback_nameservers: fallback ? [ "127.0.0.2" ] : [], timeout: timeout
    )
  end

  def elapsed
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  end

  # A response carrying +id+ for a question of the forger's choosing.
  def forged_reply(id, qname, qtype, address)
    msg = Dnsruby::Message.new(qname, qtype)
    msg.header.id = id
    msg.header.qr = true
    msg.add_answer(Dnsruby::RR.create("#{qname} 300 IN A #{address}"))
    msg.encode
  end

  test "a datagram with the right id but another question is not the reply" do
    @responder = Responder.new do |query, reply|
      reply.add_answer(Dnsruby::RR.create("example.test. 300 IN A 192.0.2.1"))
      [ forged_reply(query.header.id, "other.test.", "A", "203.0.113.66"),
        forged_reply(query.header.id, "example.test.", "AAAA", "203.0.113.67"),
        reply.encode ]
    end

    reply = transport_to(@responder).query("example.test.", "A")
    assert_equal [ "192.0.2.1" ], reply.answer.map { |rr| rr.address.to_s }
  end

  test "a datagram without the QR bit is not the reply" do
    @responder = Responder.new do |query, reply|
      reply.add_answer(Dnsruby::RR.create("example.test. 300 IN A 192.0.2.1"))
      echo = forged_reply(query.header.id, "example.test.", "A", "203.0.113.66")
      echo.setbyte(2, echo.getbyte(2) & 0x7f) # the same message as a query
      [ echo, reply.encode ]
    end

    reply = transport_to(@responder).query("example.test.", "A")
    assert_equal [ "192.0.2.1" ], reply.answer.map { |rr| rr.address.to_s }
  end

  test "a reply the question is missing from is never accepted" do
    @responder = Responder.new do |query, _reply|
      bare = Dnsruby::Message.new
      bare.header.id = query.header.id
      bare.header.qr = true
      [ bare.encode ]
    end

    assert_raises(MailOnRails::Dnssec::Transport::TempError) do
      transport_to(@responder, timeout: 1).query("example.test.", "A")
    end
  end

  test "an undecodable reply fails that server at once and the next one is asked" do
    # An NSEC3 whose hash length runs past its RDATA - dnsruby raises
    # NoMethodError on it. The header is ours, so this is the server's
    # answer; sitting out the timeout would only stall the queue run.
    @responder = Responder.new do |query, _reply|
      owner = Dnsruby::MessageEncoder.new { |encoder| encoder.put_name(query.question[0].qname, true) }.to_s
      rdata = [ 1, 0, 0, 0, 20 ].pack("CCnCC") + "abc"
      [ [ query.header.id, 0x8180, 1, 0, 1, 0 ].pack("n6") + owner + [ 52, 1 ].pack("nn") +
        owner + [ 50, 1, 300, rdata.bytesize ].pack("nnNn") + rdata ]
    end
    @fallback = Responder.new(ip: "127.0.0.2", port: @responder.port)

    reply = nil
    seconds = elapsed { reply = transport_to(@responder, fallback: true, timeout: 3).query("example.test.", "TLSA") }
    assert_equal Dnsruby::RCode.NOERROR, reply.rcode
    assert_equal 1, @fallback.seen.size
    assert_operator seconds, :<, 2, "the 3s timeout must not have been waited out"
  end

  test "undecodable replies from every server raise TempError, nothing else" do
    @responder = Responder.new { |query, _reply| [ [ query.header.id, 0x8180, 0, 9, 0, 0 ].pack("n6") ] }

    error = assert_raises(MailOnRails::Dnssec::Transport::TempError) do
      transport_to(@responder).query("example.test.", "TLSA")
    end
    assert_match(/DecodeError/, error.message)
  end

  test "a TLSA record with a malformed digest arrives as published" do
    rdata = [ 3, 1, 1 ].pack("CCC") + "\xde\xad\xbe\xef".b
    @responder = Responder.new do |query, _reply|
      owner = Dnsruby::MessageEncoder.new { |encoder| encoder.put_name(query.question[0].qname, true) }.to_s
      [ [ query.header.id, 0x8180, 1, 1, 0, 0 ].pack("n6") + owner + [ 52, 1 ].pack("nn") +
        owner + [ 52, 1, 300, rdata.bytesize ].pack("nnNn") + rdata ]
    end

    reply = transport_to(@responder).query("_25._tcp.mx.example.test.", "TLSA")
    record = reply.answer[0]
    assert_equal [ 3, 1, 1, "\xde\xad\xbe\xef".b ], [ record.usage, record.selector, record.matching_type, record.databin ]
  end

  test "a truncated reply is re-asked over TCP without being decoded" do
    require "fake_dns"
    dns = FakeDns.new do |query, _reply, via|
      name, = query.question.first
      msg = Dnsruby::Message.new(name.to_s, "TLSA")
      msg.header.id = query.id
      msg.header.qr = true
      if via == :udp
        # TC set over counts the datagram does not honor: undecodable,
        # and beside the point.
        msg.encode.tap { |bytes| bytes.setbyte(2, bytes.getbyte(2) | 0x02); bytes[6, 2] = [ 40 ].pack("n") }
      else
        msg.add_answer(Dnsruby::RR.create("#{name}. 300 IN TLSA 3 1 1 #{"ab" * 32}"))
        msg.encode
      end
    end
    transport = MailOnRails::Dnssec::Transport.new(nameservers: [ "127.0.0.1" ], port: dns.port,
                                                   fallback_nameservers: [], timeout: 3)

    reply = transport.query("_25._tcp.mx.example.test.", "TLSA")
    assert_equal 1, reply.answer.length
  ensure
    dns&.close
  end
end
