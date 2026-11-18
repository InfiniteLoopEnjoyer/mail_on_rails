# frozen_string_literal: true

require "test_helper"

# What Transport reads off a reply itself: the header checks that come
# before any decoding, and the decode that turns everything dnsruby
# raises into "undecodable" - except a malformed TLSA record, which has
# to arrive as published (RFC 7671 section 4.1 judges it; the RRSIG
# covers it).
class WireTest < Minitest::Test
  Wire = MailOnRails::Dnssec::Wire

  TLSA_NAME = "_25._tcp.mx.example.test."
  GOOD = [ 3, 1, 1 ].pack("CCC") + ("\xab".b * 32)
  SHORT_DIGEST = [ 3, 1, 1 ].pack("CCC") + "\xde\xad\xbe\xef".b

  def name_bytes(name)
    Dnsruby::MessageEncoder.new { |encoder| encoder.put_name(Dnsruby::Name.create(name), true) }.to_s
  end

  # A response to (qname, qtype) with one answer record per RDATA given.
  def wire(qname, qtype, *rdatas, id: 0x1234, flags: 0x8180)
    owner = name_bytes(qname)
    records = rdatas.map { |rdata| owner + [ qtype, 1, 300, rdata.bytesize ].pack("nnNn") + rdata }
    [ id, flags, 1, rdatas.size, 0, 0 ].pack("n6") + owner + [ qtype, 1 ].pack("nn") + records.join
  end

  def rdata_of(record)
    Dnsruby::MessageEncoder.new { |encoder| record.encode_rdata(encoder, true) }.to_s.b
  end

  test "the header alone says whether a datagram is a response to this query" do
    reply = wire("a.example.test.", 1, id: 0x1234)
    assert Wire.response_to?(reply, 0x1234)
    assert_not Wire.response_to?(reply, 0x1235), "another id"
    assert_not Wire.response_to?(wire("a.example.test.", 1, flags: 0x0100), 0x1234), "QR clear: a query, not a response"
    assert_not Wire.response_to?("\x12\x34\x81".b, 0x1234), "shorter than a header"

    assert Wire.truncated?(wire("a.example.test.", 1, flags: 0x8380))
    assert_not Wire.truncated?(reply)
  end

  test "what dnsruby cannot decode is nil, whatever it raised" do
    assert_nil Wire.decode("".b)
    assert_nil Wire.decode("\x12\x34\x81\x80\x00\x01".b)

    # An NSEC3 whose hash length runs past its RDATA: NoMethodError
    # inside dnsruby, not DecodeError.
    clipped = wire("a.example.test.", 50, [ 1, 0, 0, 0, 20 ].pack("CCnCC") + "abc")
    assert_raises(NoMethodError) { Dnsruby::Message.decode(clipped) }
    assert_nil Wire.decode(clipped)
  end

  test "an ordinary message decodes as dnsruby decodes it" do
    msg = Wire.decode(wire(TLSA_NAME, 52, GOOD))
    record = msg.answer[0]
    assert_instance_of Dnsruby::RR::IN::TLSA, record
    assert_equal GOOD, rdata_of(record)
  end

  test "a TLSA record with a malformed digest is decoded as published" do
    data = wire(TLSA_NAME, 52, GOOD, SHORT_DIGEST)
    assert_raises(ArgumentError) { Dnsruby::Message.decode(data) }

    msg = Wire.decode(data)
    good, bad = msg.answer.to_a
    assert_equal GOOD, rdata_of(good)
    assert_kind_of Dnsruby::RR::IN::TLSA, bad
    assert_equal [ 3, 1, 1 ], [ bad.usage, bad.selector, bad.matching_type ]
    assert_equal "\xde\xad\xbe\xef".b, bad.databin
    assert_equal SHORT_DIGEST, rdata_of(bad), "the RDATA an RRSIG covers must survive the detour"
    assert_equal TLSA_NAME.chomp("."), bad.name.to_s
    assert_equal 300, bad.ttl

    # The resolver handles records in RRsets, and RRSet copies each one.
    rrset = msg.answer.rrset(Dnsruby::Name.create(TLSA_NAME), Dnsruby::Types.TLSA)
    assert_equal [ GOOD, SHORT_DIGEST ].sort, rrset.rrs.map { |rr| rdata_of(rr) }.sort
  end

  test "full-data TLSA records that do not parse are kept too" do
    garbage = [ 3, 0, 0 ].pack("CCC") + "not a certificate"
    msg = Wire.decode(wire(TLSA_NAME, 52, garbage))
    assert_equal garbage, rdata_of(msg.answer[0])
    assert_equal 0, msg.answer[0].matching_type
  end

  test "such a record survives name compression and re-encoding" do
    msg = Wire.decode(wire(TLSA_NAME, 52, GOOD, SHORT_DIGEST))
    again = Wire.decode(msg.encode) # dnsruby's encoder compresses the owner names
    assert_equal [ GOOD, SHORT_DIGEST ], again.answer.map { |rr| rdata_of(rr) }
  end

  test "a malformed TLSA record does not rescue a message that is broken elsewhere" do
    owner = name_bytes(TLSA_NAME)
    clipped_nsec3 = [ 1, 0, 0, 0, 20 ].pack("CCnCC") + "abc"
    data = [ 0x1234, 0x8180, 1, 1, 1, 0 ].pack("n6") + owner + [ 52, 1 ].pack("nn") +
           owner + [ 52, 1, 300, SHORT_DIGEST.bytesize ].pack("nnNn") + SHORT_DIGEST +
           owner + [ 50, 1, 300, clipped_nsec3.bytesize ].pack("nnNn") + clipped_nsec3
    assert_nil Wire.decode(data)

    assert_nil Wire.decode(wire(TLSA_NAME, 52, "\x03\x01".b)), "a TLSA too short to have its three fields"
    assert_nil Wire.decode(wire(TLSA_NAME, 52, SHORT_DIGEST).byteslice(0..-3)), "RDATA cut off by the end of the message"
  end
end
