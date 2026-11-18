# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/sender_auth/dns"
require "mail_on_rails/dnssec"
require_relative "../dnssec/signer"
require File.expand_path("../../app/models/mail_on_rails/dane", __dir__)

# The DANE-facing pair (tlsa/mx_answer) now rides the in-process
# validating resolver (Dnssec::Resolver): Answer#secure is the resolver's
# :secure verdict, :insecure surfaces as secure: false, :bogus and
# transport failures raise TempError so deliveries defer. The resolver is
# injected; its own verification behavior is covered by test/dnssec.
class DnsDnssecTest < Minitest::Test
  Dns = MailOnRails::SenderAuth::Dns
  Result = MailOnRails::Dnssec::Resolver::Answer

  TLSA_NAME = "_25._tcp.mx.example.com"

  # Scripted stand-in for Dnssec::Resolver: maps "name|TYPE" to a
  # Resolver::Answer (or a proc, for raising), counting calls.
  class FakeResolver
    attr_reader :calls

    def initialize(answers)
      @answers = answers
      @calls = []
    end

    def resolve(name, type)
      key = "#{name}|#{type}"
      @calls << key
      answer = @answers.fetch(key)
      answer.is_a?(Proc) ? answer.call : answer
    end
  end

  def dns_with(answers, cache_ttl: 60, clock: -> { 0.0 })
    resolver = FakeResolver.new(answers)
    [ Dns.new(nameservers: [ "192.0.2.53" ], resolver: resolver, cache_ttl: cache_ttl, clock: clock), resolver ]
  end

  def tlsa_rr(usage: 3, selector: 1, matching_type: 1, data: "ab" * 32, ttl: 300)
    Dnsruby::RR.create("#{TLSA_NAME}. #{ttl} IN TLSA #{usage} #{selector} #{matching_type} #{data}")
  end

  test "secure TLSA answers parse into usage/selector/matching_type/data" do
    dns, = dns_with({
      "#{TLSA_NAME}|TLSA" => Result.new(status: :secure, records: [
        tlsa_rr,
        tlsa_rr(usage: 2, selector: 0, matching_type: 2, data: "01" * 64)
      ])
    })

    answer = dns.tlsa(TLSA_NAME)
    assert answer.secure
    assert_equal 2, answer.records.size
    first = answer.records.first
    assert_equal [ 3, 1, 1 ], [ first.usage, first.selector, first.matching_type ]
    assert_equal ("\xab".b * 32), first.data
  end

  test "an :insecure answer keeps its records but is not secure" do
    dns, = dns_with({ "#{TLSA_NAME}|TLSA" => Result.new(status: :insecure, records: [ tlsa_rr ]) })

    answer = dns.tlsa(TLSA_NAME)
    refute answer.secure
    assert_equal 1, answer.records.size
  end

  test "a secure denial is an empty secure answer - the no-DANE-published signal" do
    dns, = dns_with({ "#{TLSA_NAME}|TLSA" => Result.new(status: :secure, records: [], proof: :no_data) })

    answer = dns.tlsa(TLSA_NAME)
    assert answer.secure
    assert_empty answer.records
  end

  test ":bogus raises TempError so the delivery defers" do
    dns, = dns_with({
      "#{TLSA_NAME}|TLSA" => Result.new(status: :bogus, records: [], reason: "signature failed")
    })

    error = assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
    assert_match(/signature failed/, error.message)
  end

  test "resolver transport failures surface as TempError" do
    dns, = dns_with({
      "#{TLSA_NAME}|TLSA" => -> { raise MailOnRails::Dnssec::Transport::TempError, "upstream gone" }
    })

    assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
  end

  test "mx_answer sorts by preference and carries the verdict" do
    mx = [
      Dnsruby::RR.create("example.com. 300 IN MX 20 backup.example.com."),
      Dnsruby::RR.create("example.com. 300 IN MX 10 mail.example.com.")
    ]
    dns, = dns_with({ "example.com|MX" => Result.new(status: :secure, records: mx) })

    answer = dns.mx_answer("example.com")
    assert answer.secure
    assert_equal [ [ 10, "mail.example.com" ], [ 20, "backup.example.com" ] ], answer.records
  end

  test "validated answers cache; bogus never does" do
    calls = 0
    flapping = lambda do
      calls += 1
      raise MailOnRails::Dnssec::Transport::TempError, "flap" if calls == 1

      Result.new(status: :secure, records: [ tlsa_rr ])
    end
    dns, resolver = dns_with({ "#{TLSA_NAME}|TLSA" => flapping })

    assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
    assert dns.tlsa(TLSA_NAME).secure, "the failure must not be cached"
    dns.tlsa(TLSA_NAME)
    assert_equal 2, resolver.calls.size, "the validated answer should have cached"
  end

  test "cache expiry honors record TTLs below the cap" do
    now = [ 0.0 ]
    dns, resolver = dns_with(
      { "#{TLSA_NAME}|TLSA" => Result.new(status: :secure, records: [ tlsa_rr(ttl: 5) ]) },
      cache_ttl: 60, clock: -> { now[0] }
    )

    dns.tlsa(TLSA_NAME)
    dns.tlsa(TLSA_NAME)
    assert_equal 1, resolver.calls.size

    now[0] = 6.0
    dns.tlsa(TLSA_NAME)
    assert_equal 2, resolver.calls.size, "the 5s record TTL should bound the 60s cap"
  end

  test "anything else the resolver raises is a TempError too" do
    # Callers (the outbound deliverer) rescue TempError and nothing
    # else; a stray exception used to end the whole queue run.
    dns, = dns_with({
      "#{TLSA_NAME}|TLSA" => -> { raise ArgumentError, "data with invalid value: deadbeef" },
      "example.com|MX" => -> { raise Dnsruby::ResolvError, "Name length is 258, greater than max of 255 octets!" }
    })

    error = assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
    assert_match(/ArgumentError: data with invalid value/, error.message)
    assert_raises(Dns::TempError) { dns.mx_answer("example.com") }
  end

  test "a failed lookup of either kind is never cached" do
    calls = 0
    flaky = lambda do
      calls += 1
      raise NoMethodError, "undefined method 'length' for nil" if calls == 1

      Result.new(status: :secure, records: [ tlsa_rr ])
    end
    dns, = dns_with({ "#{TLSA_NAME}|TLSA" => flaky })

    assert_raises(Dns::TempError) { dns.tlsa(TLSA_NAME) }
    assert dns.tlsa(TLSA_NAME).secure
  end

  test "without an injected resolver a real validating resolver is built lazily" do
    dns = Dns.new(nameservers: [ "192.0.2.53" ])
    resolver = dns.send(:dnssec_resolver)
    assert_instance_of MailOnRails::Dnssec::Resolver, resolver
  end

  # ----- end to end over the real validator ------------------------------
  #
  # The scripted resolver above covers the mapping; these run the real
  # Dnssec::Resolver against a signed test hierarchy, for the two cases
  # where the consumer-side meaning is the point: a forged denial must
  # not read as "no TLSA published", and a malformed TLSA record must
  # read as an unusable record (RFC 7671 section 4.1) rather than as a
  # failed lookup.
  class SignedZones
    SIGNED_AT = Time.utc(2026, 8, 1)
    EXPIRES_AT = Time.utc(2026, 9, 1)
    NOW = Time.utc(2026, 8, 15)

    attr_reader :root, :example, :transport

    def initialize
      @root = TestZone.new(".", algorithm: TestZone::ALG_ECDSAP256)
      @example = TestZone.new("example.", algorithm: TestZone::ALG_ED25519)
      @transport = FakeTransport.new
      @transport.add DnsResponse.build(".", "DNSKEY", answer: [ @root.dnskey_rrset(signed_at: SIGNED_AT, expires_at: EXPIRES_AT) ])
      @transport.add DnsResponse.build("example.", "DNSKEY", answer: [ @example.dnskey_rrset(signed_at: SIGNED_AT, expires_at: EXPIRES_AT) ])
      @transport.add DnsResponse.build("example.", "DS", answer: [ sign(TestZone.rrset(@example.ds), @root) ])
    end

    def sign(rrset, zone = @example)
      zone.sign(rrset, signed_at: SIGNED_AT, expires_at: EXPIRES_AT)
    end

    def dns
      resolver = MailOnRails::Dnssec::Resolver.new(transport: @transport, trust_anchors: { "." => [ @root.ds ] },
                                                   now: -> { NOW })
      Dns.new(nameservers: [ "192.0.2.53" ], resolver: resolver, cache_ttl: 0)
    end
  end

  SIGNED_TLSA = "_25._tcp.mx.example"

  def good_tlsa
    Dnsruby::RR.create("#{SIGNED_TLSA}. 300 IN TLSA 3 1 1 #{"ab" * 32}")
  end

  # "3 1 1 deadbeef": a SHA-256 digest four octets long.
  def mistyped_tlsa
    MailOnRails::Dnssec::Wire::PublishedTlsa.from(Dnsruby::RR.create("#{SIGNED_TLSA}. 300 IN TLSA 3 1 255 deadbeef"), 1)
  end

  test "a mistyped TLSA record beside a good one leaves the good one usable" do
    zones = SignedZones.new
    zones.transport.add DnsResponse.build("#{SIGNED_TLSA}.", "TLSA",
                                          answer: [ zones.sign(TestZone.rrset(good_tlsa, mistyped_tlsa)) ])

    answer = zones.dns.tlsa(SIGNED_TLSA)
    assert answer.secure
    assert_equal 2, answer.records.size
    usable = MailOnRails::Dane.usable_records(answer.records)
    assert_equal [ "\xab".b * 32 ], usable.map(&:data)
  end

  test "a TLSA RRset of nothing but mistyped records is secure, present and unusable" do
    zones = SignedZones.new
    zones.transport.add DnsResponse.build("#{SIGNED_TLSA}.", "TLSA", answer: [ zones.sign(TestZone.rrset(mistyped_tlsa)) ])

    answer = zones.dns.tlsa(SIGNED_TLSA)
    assert answer.secure
    assert_equal 1, answer.records.size, "the host publishes TLSA: not the same as publishing none"
    assert_empty MailOnRails::Dane.usable_records(answer.records)
  end

  test "a mistyped TLSA record in an unsigned zone is an insecure answer, not a failed lookup" do
    zones = SignedZones.new
    unsigned = "_25._tcp.mx.unsigned.example"
    record = MailOnRails::Dnssec::Wire::PublishedTlsa.from(Dnsruby::RR.create("#{unsigned}. 300 IN TLSA 3 1 255 deadbeef"), 1)
    delegation = TestZone.rrset(Dnsruby::RR.create("unsigned.example. 300 IN NSEC example. NS RRSIG NSEC"))
    soa = TestZone.rrset(Dnsruby::RR.create("example. 300 IN SOA ns.example. h.example. 1 300 300 300 300"))
    zones.transport.add DnsResponse.build("unsigned.example.", "DS", authority: [ zones.sign(soa), zones.sign(delegation) ])
    zones.transport.add DnsResponse.build("#{unsigned}.", "TLSA", answer: [ TestZone.rrset(record) ])

    answer = zones.dns.tlsa(unsigned)
    refute answer.secure
    assert_equal 1, answer.records.size
  end

  test "usable_records sets malformed association data aside" do
    record = ->(matching_type, data) { Dns::Tlsa.new(usage: 3, selector: 1, matching_type: matching_type, data: data) }
    key = OpenSSL::PKey::EC.generate("prime256v1").public_to_der

    usable = MailOnRails::Dane.usable_records([
      record.call(1, "x" * 32), record.call(2, "x" * 64), record.call(0, key),
      record.call(1, "x" * 4), record.call(1, ""), record.call(2, "x" * 32), record.call(0, "not a key"), record.call(0, "")
    ])
    assert_equal [ [ 1, 32 ], [ 2, 64 ], [ 0, key.bytesize ] ], usable.map { |r| [ r.matching_type, r.data.bytesize ] }
  end

  test "a replayed wildcard NSEC does not read as 'this host publishes no TLSA'" do
    # Audit H6 from the consumer's side: before the fix this lookup came
    # back secure and empty, which is exactly what takes a host out of
    # DANE mode.
    zones = SignedZones.new
    genuine = zones.sign(TestZone.rrset(Dnsruby::RR.create("*.example. 300 IN NSEC mx.example. TXT RRSIG NSEC")))
    forged_sig = Dnsruby::Message.decode(DnsResponse.build("x.", "A", answer: [ genuine.sigs[0] ]).encode).answer[0]
    forged_sig.name = Dnsruby::Name.create("#{SIGNED_TLSA}.")
    soa = TestZone.rrset(Dnsruby::RR.create("example. 300 IN SOA ns.example. h.example. 1 300 300 300 300"))
    zones.transport.add DnsResponse.build(
      "#{SIGNED_TLSA}.", "TLSA",
      authority: [ zones.sign(soa), Dnsruby::RR.create("#{SIGNED_TLSA}. 300 IN NSEC mx.example. TXT RRSIG NSEC"), forged_sig ]
    )

    error = assert_raises(Dns::TempError) { zones.dns.tlsa(SIGNED_TLSA) }
    assert_match(/DNSSEC validation failed/, error.message)
  end
end
