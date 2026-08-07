# frozen_string_literal: true

require "test_helper"
require "resolv"
require "socket"
require "fake_dns"
require "mail_on_rails/smtp/sender_auth/dns"

# The DNSSEC-flagged query path behind DANE: TLSA/MX queries go out with
# an EDNS0 OPT record carrying the DO bit, and the answer's AD bit comes
# back as Answer#secure. FakeDns responders return raw bytes when they
# need to set header bits Resolv's encoder can't.
class DnsDnssecTest < Minitest::Test
  Dns = MailOnRails::Smtp::SenderAuth::Dns
  # Generic.create mints a fresh class each call and re-registers the
  # codec entry, so everything must share the one Dns created.
  TLSA = Dns::TLSA_TYPE

  TLSA_NAME = "_25._tcp.mx.example.com"

  def teardown
    @fake&.close
  end

  def dns_with(timeout: 2, &responder)
    @fake = FakeDns.new(&responder)
    Dns.new(nameservers: [ "127.0.0.1" ], timeout: timeout, port: @fake.port)
  end

  def tlsa_rdata(usage: 3, selector: 1, matching_type: 1, data: "\xab".b * 32)
    ([ usage, selector, matching_type ].pack("CCC") + data).b
  end

  def with_ad(reply)
    bytes = reply.encode
    bytes.setbyte(3, bytes.getbyte(3) | 0x20)
    bytes
  end

  test "tlsa queries advertise EDNS0 with the DO bit" do
    seen = nil
    dns = dns_with do |query, reply, _via|
      seen = query.additional.map { |_name, _ttl, record| record.class::TypeValue }
      reply
    end

    dns.tlsa(TLSA_NAME)
    assert_equal [ 41 ], seen, "the query must carry exactly one OPT pseudo-record"
  end

  test "tlsa answers parse rdata and surface the AD bit" do
    dns = dns_with do |_query, reply, _via|
      reply.add_answer(Resolv::DNS::Name.create("#{TLSA_NAME}."), 300, TLSA.new(tlsa_rdata))
      reply.add_answer(Resolv::DNS::Name.create("#{TLSA_NAME}."), 300,
                       TLSA.new(tlsa_rdata(usage: 2, selector: 0, matching_type: 2, data: "\x01".b * 64)))
      with_ad(reply)
    end

    answer = dns.tlsa(TLSA_NAME)
    assert answer.secure
    assert_equal 2, answer.records.size
    first = answer.records.first
    assert_equal [ 3, 1, 1 ], [ first.usage, first.selector, first.matching_type ]
    assert_equal "\xab".b * 32, first.data
  end

  test "an answer without the AD bit is insecure" do
    dns = dns_with do |_query, reply, _via|
      reply.add_answer(Resolv::DNS::Name.create("#{TLSA_NAME}."), 300, TLSA.new(tlsa_rdata))
      reply
    end

    answer = dns.tlsa(TLSA_NAME)
    refute answer.secure
    assert_equal 1, answer.records.size
  end

  test "truncated tlsa rdata is dropped, not crashed on" do
    dns = dns_with do |_query, reply, _via|
      reply.add_answer(Resolv::DNS::Name.create("#{TLSA_NAME}."), 300, TLSA.new("\x03\x01".b))
      with_ad(reply)
    end

    assert_empty dns.tlsa(TLSA_NAME).records
  end

  test "mx_answer returns preference pairs with the AD flag" do
    dns = dns_with do |_query, reply, _via|
      reply.add_answer(Resolv::DNS::Name.create("example.com."), 300,
                       Resolv::DNS::Resource::IN::MX.new(20, Resolv::DNS::Name.create("backup.example.com")))
      reply.add_answer(Resolv::DNS::Name.create("example.com."), 300,
                       Resolv::DNS::Resource::IN::MX.new(10, Resolv::DNS::Name.create("mx.example.com")))
      with_ad(reply)
    end

    answer = dns.mx_answer("example.com")
    assert answer.secure
    assert_equal [ [ 10, "mx.example.com" ], [ 20, "backup.example.com" ] ], answer.records
  end

  test "servfail on a dnssec query raises TempError" do
    dns = dns_with do |_query, reply, _via|
      reply.rcode = Resolv::DNS::RCode::ServFail
      reply
    end

    assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
  end

  test "nxdomain is an empty secure-flagged answer" do
    dns = dns_with do |_query, reply, _via|
      reply.rcode = Resolv::DNS::RCode::NXDomain
      with_ad(reply)
    end

    answer = dns.tlsa(TLSA_NAME)
    assert_empty answer.records
    assert answer.secure, "secure denial of existence still carries AD"
  end
end
