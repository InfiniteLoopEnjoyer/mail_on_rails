# frozen_string_literal: true

require "test_helper"
require "signer"

# The validating stub forwarder end to end, against a synthetic signed
# hierarchy with real cryptography: a test root (RSA-SHA256) delegating
# to test. (ECDSA P-256) delegating to example.test. (Ed25519), so every
# chain walk crosses all three algorithm families. The upstream is a
# FakeTransport - the resolver must derive every verdict from signatures
# and proofs alone.
class ResolverTest < Minitest::Test
  SIGNED_AT = Time.utc(2026, 8, 1)
  EXPIRES_AT = Time.utc(2026, 9, 1)
  NOW = Time.utc(2026, 8, 15)

  ROOT = TestZone.new(".", algorithm: TestZone::ALG_RSASHA256)
  TEST = TestZone.new("test.", algorithm: TestZone::ALG_ECDSAP256)
  EXAMPLE = TestZone.new("example.test.", algorithm: TestZone::ALG_ED25519)

  # Factory methods, not constants: RRSet#clone is shallow (the record
  # array is shared), so signing a "copy" of a shared RRSet would leak
  # signatures across tests.
  def self.a_rrset
    TestZone.rrset(Dnsruby::RR.create("a.example.test. 300 IN A 192.0.2.1"))
  end

  def self.example_soa
    TestZone.rrset(Dnsruby::RR.create("example.test. 300 IN SOA ns.example.test. h.example.test. 1 300 300 300 300"))
  end

  def self.test_soa
    TestZone.rrset(Dnsruby::RR.create("test. 300 IN SOA ns.test. h.test. 1 300 300 300 300"))
  end

  # The example.test. NSEC3 chain (SHA-1, no salt, zero iterations - the
  # RFC 9276 recommended shape). Empty non-terminals get records too.
  EXAMPLE_NAMES = {
    "example.test."     => "SOA NS DNSKEY RRSIG",
    "a.example.test."   => "A RRSIG",
    "w.example.test."   => "",
    "*.w.example.test." => "TXT RRSIG"
  }.freeze

  def self.sign(rrset, zone, **opts)
    zone.sign(rrset, signed_at: SIGNED_AT, expires_at: EXPIRES_AT, **opts)
  end

  def self.nsec3_chain(zone, names, flags: 0)
    hashes = names.map do |name, types|
      [ Dnsruby::RR::NSEC3.calculate_hash(Dnsruby::Name.create(name), 0, "",
                                          Dnsruby::Nsec3HashAlgorithms.SHA_1), types ]
    end.sort_by(&:first)
    hashes.each_with_index.map do |(hash, types), i|
      succ = hashes[(i + 1) % hashes.length][0]
      rrset = TestZone.rrset(
        Dnsruby::RR.create("#{hash}.#{zone.name} 300 IN NSEC3 1 #{flags} 0 - #{succ} #{types}")
      )
      sign(rrset, zone)
    end
  end

  # Chain-of-trust fixtures every scenario needs.
  def self.base_transport
    transport = FakeTransport.new
    transport.add DnsResponse.build(".", "DNSKEY", answer: [ ROOT.dnskey_rrset(signed_at: SIGNED_AT, expires_at: EXPIRES_AT) ])
    transport.add DnsResponse.build("test.", "DNSKEY", answer: [ TEST.dnskey_rrset(signed_at: SIGNED_AT, expires_at: EXPIRES_AT) ])
    transport.add DnsResponse.build("example.test.", "DNSKEY", answer: [ EXAMPLE.dnskey_rrset(signed_at: SIGNED_AT, expires_at: EXPIRES_AT) ])
    transport.add DnsResponse.build("test.", "DS", answer: [ sign(TestZone.rrset(TEST.ds), ROOT) ])
    transport.add DnsResponse.build("example.test.", "DS", answer: [ sign(TestZone.rrset(EXAMPLE.ds), TEST) ])
    transport
  end

  def resolver(transport, **opts)
    MailOnRails::Dnssec::Resolver.new(
      transport: transport, trust_anchors: { "." => [ ROOT.ds ] }, now: -> { NOW }, **opts
    )
  end

  def signed(rrset, zone, **opts)
    self.class.sign(rrset, zone, **opts)
  end

  def example_chain(flags: 0)
    self.class.nsec3_chain(EXAMPLE, EXAMPLE_NAMES, flags: flags)
  end

  test "a signed answer across three algorithm families is :secure" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])

    answer = resolver(transport).resolve("a.example.test.", "A")
    assert_equal :secure, answer.status
    assert_equal [ "192.0.2.1" ], answer.records.map { |r| r.address.to_s }
  end

  test "a tampered signature is :bogus" do
    transport = self.class.base_transport
    rrset = signed(self.class.a_rrset, EXAMPLE)
    sig = rrset.sigs[0]
    sig.signature = sig.signature.dup.tap { |s| s.setbyte(0, s.getbyte(0) ^ 0xFF) }
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ rrset ])

    answer = resolver(transport).resolve("a.example.test.", "A")
    assert_equal :bogus, answer.status
    assert_match(/failed to verify/, answer.reason)
  end

  test "an expired signature is :bogus" do
    transport = self.class.base_transport
    stale = TestZone.rrset(Dnsruby::RR.create("a.example.test. 300 IN A 192.0.2.9"))
    EXAMPLE.sign(stale, signed_at: Time.utc(2026, 6, 1), expires_at: Time.utc(2026, 7, 1))
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ stale ])

    assert_equal :bogus, resolver(transport).resolve("a.example.test.", "A").status
  end

  test "NXDOMAIN with a verified NSEC3 name error is :secure" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("nope.example.test.", "A", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *example_chain ])

    answer = resolver(transport).resolve("nope.example.test.", "A")
    assert_equal :secure, answer.status
    assert_equal :name_error, answer.proof
  end

  test "NXDOMAIN under an Opt-Out chain is :insecure" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("gone.example.test.", "A", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *example_chain(flags: 1) ])

    answer = resolver(transport).resolve("gone.example.test.", "A")
    assert_equal :insecure, answer.status
    assert_equal :name_error, answer.proof
  end

  test "NXDOMAIN whose denial records are unsigned is :bogus" do
    transport = self.class.base_transport
    unsigned_chain = self.class.nsec3_chain(EXAMPLE, EXAMPLE_NAMES).map do |rrset|
      TestZone.rrset(*rrset.rrs) # sigs stripped
    end
    transport.add DnsResponse.build("nope.example.test.", "A", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *unsigned_chain ])

    assert_equal :bogus, resolver(transport).resolve("nope.example.test.", "A").status
  end

  test "a TLSA NODATA with proof is :secure - the DANE decision shape" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "TLSA",
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *example_chain ])

    answer = resolver(transport).resolve("a.example.test.", "TLSA")
    assert_equal :secure, answer.status
    assert_equal :no_data, answer.proof
    assert_empty answer.records
  end

  test "a wildcard-expanded answer verifies over its original owner" do
    transport = self.class.base_transport
    expanded = TestZone.rrset(Dnsruby::RR.create("x.w.example.test. 300 IN TXT \"wild\""))
    signed(expanded, EXAMPLE, sign_as: "*.w.example.test.", labels: 3)
    transport.add DnsResponse.build("x.w.example.test.", "TXT",
                                    answer: [ expanded ],
                                    authority: [ *example_chain ])

    answer = resolver(transport).resolve("x.w.example.test.", "TXT")
    assert_equal :secure, answer.status
    assert_equal :wildcard_answer, answer.proof
  end

  test "a wildcard expansion without a next-closer proof is :bogus" do
    transport = self.class.base_transport
    expanded = TestZone.rrset(Dnsruby::RR.create("x.w.example.test. 300 IN TXT \"wild\""))
    signed(expanded, EXAMPLE, sign_as: "*.w.example.test.", labels: 3)
    transport.add DnsResponse.build("x.w.example.test.", "TXT", answer: [ expanded ])

    answer = resolver(transport).resolve("x.w.example.test.", "TXT")
    assert_equal :bogus, answer.status
    assert_match(/wildcard/, answer.reason)
  end

  test "a CNAME chain carries the worst link's status" do
    transport = self.class.base_transport
    cname = TestZone.rrset(Dnsruby::RR.create("alias.example.test. 300 IN CNAME a.example.test."))
    transport.add DnsResponse.build("alias.example.test.", "A", answer: [ signed(cname, EXAMPLE) ])
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])

    answer = resolver(transport).resolve("alias.example.test.", "A")
    assert_equal :secure, answer.status
    assert_equal [ "192.0.2.1" ], answer.records.map { |r| r.address.to_s }
  end

  test "an unsigned answer below a proven-unsigned delegation is :insecure" do
    transport = self.class.base_transport
    # test.'s NSEC proves unsigned.test. has NS but no DS - a real
    # insecure delegation - so plain records under it are legitimate.
    delegation_nsec = signed(TestZone.rrset(
      Dnsruby::RR.create("unsigned.test. 300 IN NSEC test. NS RRSIG NSEC")
    ), TEST)
    transport.add DnsResponse.build("unsigned.test.", "DS",
                                    authority: [ signed(self.class.test_soa, TEST), delegation_nsec ])
    transport.add DnsResponse.build("www.unsigned.test.", "A",
                                    answer: [ TestZone.rrset(Dnsruby::RR.create("www.unsigned.test. 300 IN A 192.0.2.7")) ])

    answer = resolver(transport).resolve("www.unsigned.test.", "A")
    assert_equal :insecure, answer.status
    assert_equal [ "192.0.2.7" ], answer.records.map { |r| r.address.to_s }
  end

  test "an unsigned answer inside a signed zone is :bogus" do
    transport = self.class.base_transport
    # The walk to legitimize the unsigned answer finds b.example.test.
    # provably nonexistent instead.
    transport.add DnsResponse.build("b.example.test.", "DS", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *example_chain ])
    transport.add DnsResponse.build("b.example.test.", "A",
                                    answer: [ TestZone.rrset(Dnsruby::RR.create("b.example.test. 300 IN A 192.0.2.66")) ])

    assert_equal :bogus, resolver(transport).resolve("b.example.test.", "A").status
  end

  test "validated zone keys are cached across resolves" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])
    transport.add DnsResponse.build("a.example.test.", "TLSA",
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *example_chain ])

    r = resolver(transport)
    assert_equal :secure, r.resolve("a.example.test.", "A").status
    assert_equal :secure, r.resolve("a.example.test.", "TLSA").status
    root_key_fetches = transport.queries.count { |q| q == ".|DNSKEY" }
    assert_equal 1, root_key_fetches, "the root DNSKEY chain should validate once and cache"
  end

  test "the query budget trips to :bogus instead of unbounded work" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])

    answer = resolver(transport, budget: { queries: 2 }).resolve("a.example.test.", "A")
    assert_equal :bogus, answer.status
    assert_match(/budget/, answer.reason)
  end

  test "upstream SERVFAIL raises TempError rather than downgrading" do
    transport = self.class.base_transport
    servfail = DnsResponse.build("a.example.test.", "A", rcode: Dnsruby::RCode.SERVFAIL)
    transport.add servfail

    assert_raises(MailOnRails::Dnssec::Transport::TempError) do
      resolver(transport).resolve("a.example.test.", "A")
    end
  end
end
