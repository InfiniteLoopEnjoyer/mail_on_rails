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

  def self.nsec3_chain(zone, names, flags: 0, iterations: 0)
    hashes = names.map do |name, types|
      [ Dnsruby::RR::NSEC3.calculate_hash(Dnsruby::Name.create(name), iterations, "",
                                          Dnsruby::Nsec3HashAlgorithms.SHA_1), types ]
    end.sort_by(&:first)
    hashes.each_with_index.map do |(hash, types), i|
      succ = hashes[(i + 1) % hashes.length][0]
      rrset = TestZone.rrset(
        Dnsruby::RR.create("#{hash}.#{zone.name} 300 IN NSEC3 1 #{flags} #{iterations} - #{succ} #{types}")
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

  test "a denial from an over-iterated NSEC3 zone is :insecure, not :bogus (RFC 9276)" do
    transport = self.class.base_transport
    over_iterated = self.class.nsec3_chain(EXAMPLE, EXAMPLE_NAMES, iterations: 150)
    transport.add DnsResponse.build("nope.example.test.", "A", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *over_iterated ])
    transport.add DnsResponse.build("a.example.test.", "TLSA",
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *over_iterated ])
    # Before settling for insecure the validator asks the zone whether a
    # signed delegation sits between it and the name; an over-iterated
    # zone answers that the only way it can.
    transport.add DnsResponse.build("nope.example.test.", "DS", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *over_iterated ])
    transport.add DnsResponse.build("a.example.test.", "DS",
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *over_iterated ])

    nxdomain = resolver(transport).resolve("nope.example.test.", "A")
    assert_equal :insecure, nxdomain.status
    assert_match(/iterations/, nxdomain.reason)

    nodata = resolver(transport).resolve("a.example.test.", "TLSA")
    assert_equal :insecure, nodata.status, "the DANE NODATA shape must downgrade the same way"
  end

  test "an over-iterated chain that is also unsigned is still :bogus" do
    transport = self.class.base_transport
    unsigned = self.class.nsec3_chain(EXAMPLE, EXAMPLE_NAMES, iterations: 150).map { |rrset| TestZone.rrset(*rrset.rrs) }
    transport.add DnsResponse.build("nope.example.test.", "A", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *unsigned ])

    assert_equal :bogus, resolver(transport).resolve("nope.example.test.", "A").status
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

  test "a delegation signed only with an algorithm we cannot verify is :insecure" do
    transport = self.class.base_transport
    # DSA (3): RFC 8624 forbids validating it, so the DS RRset - itself
    # properly signed by test. - names no usable key, and the child is
    # outside DNSSEC rather than broken (RFC 4035 section 5.2).
    dsa_ds = TestZone.rrset(Dnsruby::RR.create("dsa.test. 300 IN DS 12345 3 2 #{"ab" * 32}"))
    transport.add DnsResponse.build("dsa.test.", "DS", answer: [ signed(dsa_ds, TEST) ])
    transport.add DnsResponse.build("www.dsa.test.", "A",
                                    answer: [ TestZone.rrset(Dnsruby::RR.create("www.dsa.test. 300 IN A 192.0.2.8")) ])

    answer = resolver(transport).resolve("www.dsa.test.", "A")
    assert_equal :insecure, answer.status
    assert_equal [ "192.0.2.8" ], answer.records.map { |r| r.address.to_s }
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

  # ----- wildcard-expanded signatures (audit H6) -----------------------

  TLSA_NAME = "_25._tcp.mx.example.test."

  def rrset(*strings)
    TestZone.rrset(strings.map { |string| Dnsruby::RR.create(string) })
  end

  def tlsa_rrset(name = TLSA_NAME)
    rrset("#{name} 300 IN TLSA 3 1 1 #{"ab" * 32}")
  end

  # An RRSIG exactly as signed, re-addressed to +owner+: what a party
  # without the key can do with a signature it has seen.
  def replayed(sig, owner: nil)
    copy = Dnsruby::Message.decode(DnsResponse.build("x.", "A", answer: [ sig ]).encode).answer[0]
    copy.name = Dnsruby::Name.create(owner) if owner
    yield copy if block_given?
    copy
  end

  # example.test. as an NSEC zone with a wildcard:
  # apex -> *.example.test. -> mx.example.test. -> apex.
  def wildcard_zone_nsecs
    {
      apex: signed(rrset("example.test. 300 IN NSEC *.example.test. NS SOA RRSIG NSEC DNSKEY"), EXAMPLE),
      wildcard: signed(rrset("*.example.test. 300 IN NSEC mx.example.test. TXT RRSIG NSEC"), EXAMPLE),
      mx: signed(rrset("mx.example.test. 300 IN NSEC example.test. A RRSIG NSEC"), EXAMPLE)
    }
  end

  test "a wildcard NSEC replayed under another owner cannot deny an existing TLSA RRset" do
    # The zone publishes TLSA at _25._tcp.mx and, separately, a wildcard.
    # Its genuine "*.example.test. NSEC" RRSIG (Labels 2) verifies, as a
    # wildcard expansion, under any owner below example.test. - so a
    # party on the path renames both to the TLSA name and offers them as
    # "this name exists and has no TLSA": DANE silently off.
    genuine = wildcard_zone_nsecs[:wildcard]
    forged_nsec = Dnsruby::RR.create("#{TLSA_NAME} 300 IN NSEC mx.example.test. TXT RRSIG NSEC")
    forged_sig = replayed(genuine.sigs[0], owner: TLSA_NAME)
    assert_equal genuine.sigs[0].signature, forged_sig.signature, "the signature itself is untouched"

    transport = self.class.base_transport
    transport.add DnsResponse.build(TLSA_NAME, "TLSA",
                                    authority: [ signed(self.class.example_soa, EXAMPLE), forged_nsec, forged_sig ])

    answer = resolver(transport).resolve(TLSA_NAME, "TLSA")
    assert_equal :bogus, answer.status
    assert_match(/unproven/, answer.reason)
  end

  test "the same zone's honest TLSA answer and honest wildcard denials still validate" do
    nsecs = wildcard_zone_nsecs
    transport = self.class.base_transport
    transport.add DnsResponse.build(TLSA_NAME, "TLSA", answer: [ signed(tlsa_rrset, EXAMPLE) ])
    # x.example.test. does not exist; the wildcard would answer for it
    # but has no TLSA. The proof leans on the NSEC at the literal
    # wildcard owner - Labels 2 on a three-label owner, and not an
    # expansion.
    transport.add DnsResponse.build("x.example.test.", "TLSA",
                                    authority: [ signed(self.class.example_soa, EXAMPLE), nsecs[:mx], nsecs[:wildcard] ])
    # ...and it does have TXT, expanded with the no-closer-match proof.
    expanded = rrset("x.example.test. 300 IN TXT \"wild\"")
    signed(expanded, EXAMPLE, sign_as: "*.example.test.", labels: 2)
    transport.add DnsResponse.build("x.example.test.", "TXT", answer: [ expanded ], authority: [ nsecs[:mx] ])
    # Asking for the wildcard owner itself is an ordinary answer.
    literal = signed(rrset("*.example.test. 300 IN TXT \"wild\""), EXAMPLE)
    transport.add DnsResponse.build("*.example.test.", "TXT", answer: [ literal ])

    r = resolver(transport)
    assert_equal :secure, r.resolve(TLSA_NAME, "TLSA").status

    no_data = r.resolve("x.example.test.", "TLSA")
    assert_equal [ :secure, :wildcard_no_data ], [ no_data.status, no_data.proof ]

    wildcard = r.resolve("x.example.test.", "TXT")
    assert_equal [ :secure, :wildcard_answer ], [ wildcard.status, wildcard.proof ]

    assert_equal [ :secure, nil ], r.resolve("*.example.test.", "TXT").then { |a| [ a.status, a.proof ] }
  end

  test "NSEC3 records signed as a wildcard expansion are not proof material" do
    transport = self.class.base_transport
    chain = self.class.nsec3_chain(EXAMPLE, EXAMPLE_NAMES).map do |set|
      TestZone.rrset(*set.rrs).tap { |bare| signed(bare, EXAMPLE, sign_as: "*.example.test.", labels: 2) }
    end
    transport.add DnsResponse.build("nope.example.test.", "A", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *chain ])

    assert_equal :bogus, resolver(transport).resolve("nope.example.test.", "A").status
  end

  test "a DS RRset signed as a wildcard expansion does not vouch for a delegation" do
    # "No usable DS algorithm" makes a zone insecure, so a wildcard DS
    # accepted under a made-up owner would legitimize unsigned data
    # anywhere beneath the wildcard's parent.
    ds = rrset("sub.example.test. 300 IN DS 12345 3 2 #{"ab" * 32}")
    signed(ds, EXAMPLE, sign_as: "*.example.test.", labels: 2)
    transport = self.class.base_transport
    transport.add DnsResponse.build("sub.example.test.", "DS", answer: [ ds ])
    transport.add DnsResponse.build("www.sub.example.test.", "A", answer: [ rrset("www.sub.example.test. 300 IN A 192.0.2.66") ])

    assert_equal :bogus, resolver(transport).resolve("www.sub.example.test.", "A").status
  end

  test "a wildcard-expanded CNAME link needs the no-closer-match proof like any answer" do
    link = rrset("alias.example.test. 300 IN CNAME a.example.test.")
    signed(link, EXAMPLE, sign_as: "*.example.test.", labels: 2)
    target = DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])

    unproven = self.class.base_transport
    unproven.add DnsResponse.build("alias.example.test.", "A", answer: [ link ])
    unproven.add target
    answer = resolver(unproven).resolve("alias.example.test.", "A")
    assert_equal :bogus, answer.status
    assert_match(/wildcard/, answer.reason)

    proven = self.class.base_transport
    cover = signed(rrset("a.example.test. 300 IN NSEC example.test. A RRSIG NSEC"), EXAMPLE)
    proven.add DnsResponse.build("alias.example.test.", "A", answer: [ link ], authority: [ cover ])
    proven.add target
    answer = resolver(proven).resolve("alias.example.test.", "A")
    assert_equal :secure, answer.status
    assert_equal [ "192.0.2.1" ], answer.records.map { |r| r.address.to_s }
  end

  # ----- over-iterated NSEC3 from an ancestor (audit L12) --------------

  def nsec3_hash(name, iterations)
    Dnsruby::RR::NSEC3.calculate_hash(Dnsruby::Name.create(name), iterations, "", Dnsruby::Nsec3HashAlgorithms.SHA_1)
  end

  # One of test.'s own NSEC3 records, from a test. that signs with 150
  # iterations - genuine, verifiable, and unusable (RFC 9276).
  def parent_over_iterated_nsec3
    signed(rrset("#{nsec3_hash("test.", 150)}.test. 300 IN NSEC3 1 0 150 - #{nsec3_hash("example.test.", 150)} " \
                 "NS SOA RRSIG DNSKEY NSEC3PARAM"), TEST)
  end

  def parent_over_iterated_denial(qname, qtype, rcode: Dnsruby::RCode.NOERROR)
    DnsResponse.build(qname, qtype, rcode: rcode, authority: [ signed(self.class.test_soa, TEST), parent_over_iterated_nsec3 ])
  end

  test "an ancestor's over-iterated NSEC3 records cannot make a signed child's names insecure" do
    transport = self.class.base_transport
    transport.add parent_over_iterated_denial(TLSA_NAME, "TLSA")
    transport.add parent_over_iterated_denial("example.test.", "MX")

    r = resolver(transport)
    [ [ TLSA_NAME, "TLSA" ], [ "example.test.", "MX" ] ].each do |qname, qtype|
      answer = r.resolve(qname, qtype)
      assert_equal :bogus, answer.status, "#{qname} #{qtype}: example.test. is a signed delegation of test."
      assert_match(/iterations/, answer.reason)
    end
  end

  test "an unsigned child of an over-iterated parent is :insecure" do
    transport = self.class.base_transport
    transport.add parent_over_iterated_denial("unsigned.test.", "DS")
    transport.add DnsResponse.build("www.unsigned.test.", "A", answer: [ rrset("www.unsigned.test. 300 IN A 192.0.2.7") ])

    answer = resolver(transport).resolve("www.unsigned.test.", "A")
    assert_equal :insecure, answer.status
    assert_equal [ "192.0.2.7" ], answer.records.map { |r| r.address.to_s }
  end

  test "an over-iterated DS denial from above a signed delegation is :bogus" do
    # sub.example.test.'s DS belongs in example.test.; test.'s records
    # cannot deny it, usable or not.
    transport = self.class.base_transport
    transport.add parent_over_iterated_denial("sub.example.test.", "DS")
    transport.add DnsResponse.build("www.sub.example.test.", "A", answer: [ rrset("www.sub.example.test. 300 IN A 192.0.2.66") ])

    assert_equal :bogus, resolver(transport).resolve("www.sub.example.test.", "A").status
  end

  test "an ancestor's wildcard cannot answer for a signed child's name behind over-iterated NSEC3 records" do
    expanded = tlsa_rrset
    signed(expanded, TEST, sign_as: "*.test.", labels: 1)
    transport = self.class.base_transport
    transport.add DnsResponse.build(TLSA_NAME, "TLSA", answer: [ expanded ], authority: [ parent_over_iterated_nsec3 ])

    assert_equal :bogus, resolver(transport).resolve(TLSA_NAME, "TLSA").status
  end

  # ----- NSEC empty non-terminals (audit L13) --------------------------

  # test. as an NSEC zone: apex -> a.b.test. (unsigned delegation) -> apex.
  # b.test. owns nothing and exists only because a.b.test. does.
  def ent_zone
    {
      apex: signed(rrset("test. 300 IN NSEC a.b.test. NS SOA RRSIG NSEC DNSKEY"), TEST),
      delegation: signed(rrset("a.b.test. 300 IN NSEC test. NS RRSIG NSEC"), TEST)
    }
  end

  test "the DS walk passes through an empty non-terminal to the delegation beneath it" do
    zone = ent_zone
    transport = self.class.base_transport
    transport.add DnsResponse.build("b.test.", "DS", authority: [ signed(self.class.test_soa, TEST), zone[:apex] ])
    transport.add DnsResponse.build("a.b.test.", "DS", authority: [ signed(self.class.test_soa, TEST), zone[:delegation] ])
    transport.add DnsResponse.build("a.b.test.", "MX", answer: [ rrset("a.b.test. 300 IN MX 10 mx.a.b.test.") ])

    answer = resolver(transport).resolve("a.b.test.", "MX")
    assert_equal :insecure, answer.status
    assert_equal [ "mx.a.b.test" ], answer.records.map { |r| r.exchange.to_s }
  end

  test "an empty non-terminal is NODATA, and NXDOMAIN for it is :bogus" do
    zone = ent_zone
    transport = self.class.base_transport
    transport.add DnsResponse.build("b.test.", "TLSA", authority: [ signed(self.class.test_soa, TEST), zone[:apex] ])
    no_data = resolver(transport).resolve("b.test.", "TLSA")
    assert_equal [ :secure, :no_data ], [ no_data.status, no_data.proof ]

    transport = self.class.base_transport
    transport.add DnsResponse.build("b.test.", "TLSA", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.test_soa, TEST), zone[:apex] ])
    assert_equal :bogus, resolver(transport).resolve("b.test.", "TLSA").status, "the name exists"
  end

  # ----- hostile input costs a verdict, not an exception (audit L14) ----

  test "a name too long for DNS is :bogus, not an exception" do
    host = ([ "a" * 63 ] * 3 + [ "b" * 55 ]).join(".") # a legal MX target; "_25._tcp." in front is not
    answer = resolver(self.class.base_transport).resolve("_25._tcp.#{host}", "TLSA")
    assert_equal :bogus, answer.status
    assert_match(/unusable name/, answer.reason)
  end

  test "an unexpected error while validating is :bogus, and transport failures stay TempError" do
    broken = Object.new
    def broken.query(*) = raise(NoMethodError, "undefined method 'length' for nil")
    answer = resolver(broken).resolve("a.example.test.", "A")
    assert_equal :bogus, answer.status
    assert_match(/NoMethodError/, answer.reason)

    assert_raises(MailOnRails::Dnssec::Transport::TempError) do
      resolver(FakeTransport.new).resolve("a.example.test.", "A")
    end
  end

  # A TLSA record dnsruby's own class refuses (a SHA-256 digest that
  # is not 32 octets), as Wire.decode hands it on.
  def malformed_tlsa(name = TLSA_NAME)
    MailOnRails::Dnssec::Wire::PublishedTlsa.from(Dnsruby::RR.create("#{name} 300 IN TLSA 3 1 255 deadbeef"), 1)
  end

  test "a signed TLSA RRset with a malformed record verifies over the RDATA as published" do
    mixed = TestZone.rrset(Dnsruby::RR.create("#{TLSA_NAME} 300 IN TLSA 3 1 1 #{"ab" * 32}"), malformed_tlsa)
    transport = self.class.base_transport
    transport.add DnsResponse.build(TLSA_NAME, "TLSA", answer: [ signed(mixed, EXAMPLE) ])

    answer = resolver(transport).resolve(TLSA_NAME, "TLSA")
    assert_equal :secure, answer.status, answer.reason
    assert_equal [ 4, 32 ], answer.records.map { |r| r.databin.bytesize }.sort

    # The malformed record is inside the signature, not beside it.
    other = TestZone.rrset(Dnsruby::RR.create("#{TLSA_NAME} 300 IN TLSA 3 1 1 #{"ab" * 32}"),
                           MailOnRails::Dnssec::Wire::PublishedTlsa.from(
                             Dnsruby::RR.create("#{TLSA_NAME} 300 IN TLSA 3 1 255 deadbeee"), 1
                           ))
    mixed.sigs.each { |sig| other.add(sig) }
    transport = self.class.base_transport
    transport.add DnsResponse.build(TLSA_NAME, "TLSA", answer: [ other ])
    assert_equal :bogus, resolver(transport).resolve(TLSA_NAME, "TLSA").status
  end

  # ----- budgets (audit L15 and the informational items) ----------------

  test "a denial built to maximize NSEC3 hashing trips the hash budget" do
    # 24 records with 24 different salts at the iteration cap, under a
    # qname with dozens of labels: every (ancestor, salt) pair is a
    # separate 101-digest hash.
    qname = "_25._tcp.#{([ "a" ] * 40).join(".")}.example.test."
    records = (0...24).map do |i|
      salt = format("%02x", i) * 64
      owner = Dnsruby::RR::NSEC3.calculate_hash(Dnsruby::Name.create("n#{i}.example.test."), 100, [ salt ].pack("H*"),
                                                Dnsruby::Nsec3HashAlgorithms.SHA_1)
      signed(rrset("#{owner}.example.test. 300 IN NSEC3 1 0 100 #{salt} #{owner} A RRSIG"), EXAMPLE)
    end
    transport = self.class.base_transport
    transport.add DnsResponse.build(qname, "TLSA", authority: [ signed(self.class.example_soa, EXAMPLE), *records ])

    answer = resolver(transport).resolve(qname, "TLSA")
    assert_equal :bogus, answer.status
    assert_match(/NSEC3 hash budget/, answer.reason)
  end

  test "an honest NSEC3 denial for a deep name stays well inside the hash budget" do
    qname = "_25._tcp.mx.mail.eu.a.example.test."
    transport = self.class.base_transport
    transport.add DnsResponse.build(qname, "TLSA", rcode: Dnsruby::RCode.NXDOMAIN,
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *example_chain ])

    answer = resolver(transport, budget: { nsec3_hashes: 8 }).resolve(qname, "TLSA")
    assert_equal [ :secure, :name_error ], [ answer.status, answer.proof ]
  end

  test "the wall-clock cap trips to :bogus" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])

    answer = resolver(transport, budget: { seconds: -1 }).resolve("a.example.test.", "A")
    assert_equal :bogus, answer.status
    assert_match(/time budget/, answer.reason)
  end

  test "junk RRSIGs ahead of the real one do not crowd it out" do
    a = signed(self.class.a_rrset, EXAMPLE)
    real = a.sigs[0]
    wrong_key = (1..6).map { |i| replayed(real) { |sig| sig.key_tag = (real.key_tag + i) & 0xffff } }
    foreign_signer = replayed(real) { |sig| sig.signers_name = "test." }
    made_up_zone = replayed(real) { |sig| sig.signers_name = "a.example.test." }
    lapsed = TestZone.rrset(*self.class.a_rrset.rrs)
    EXAMPLE.sign(lapsed, signed_at: Time.utc(2026, 6, 1), expires_at: Time.utc(2026, 7, 1))

    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A",
                                    answer: [ foreign_signer, made_up_zone, *wrong_key, *lapsed.sigs * 5, *a.rrs, real ])
    # What the made-up signer costs: one DS query, honestly answered.
    transport.add DnsResponse.build("a.example.test.", "DS",
                                    authority: [ signed(self.class.example_soa, EXAMPLE), *example_chain ])

    answer = resolver(transport).resolve("a.example.test.", "A")
    assert_equal :secure, answer.status, answer.reason
  end

  test "junk RRSIGs on a DS RRset do not break the chain of trust" do
    ds = signed(TestZone.rrset(EXAMPLE.ds), TEST)
    junk = replayed(ds.sigs[0]) { |sig| sig.signers_name = "." }
    transport = self.class.base_transport
    transport.add DnsResponse.build("example.test.", "DS", answer: [ junk, *ds.rrs, *ds.sigs ])
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])

    assert_equal :secure, resolver(transport).resolve("a.example.test.", "A").status
  end

  test "plausible forged RRSIGs are still tried only MAX_SIGS_PER_RRSET at a time" do
    a = signed(self.class.a_rrset, EXAMPLE)
    real = a.sigs[0]
    # Right signer, key tag, algorithm and window - only the signature
    # is wrong, which nothing short of verifying it can tell.
    forged = (1..MailOnRails::Dnssec::Resolver::MAX_SIGS_PER_RRSET).map do |i|
      replayed(real) { |sig| sig.signature = real.signature.dup.tap { |s| s.setbyte(0, (s.getbyte(0) + i) & 0xff) } }
    end
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ *forged, *a.rrs, real ])

    assert_equal :bogus, resolver(transport).resolve("a.example.test.", "A").status
  end

  def zone_cache(resolver)
    resolver.instance_variable_get(:@zone_cache)
  end

  test "validated keys are not cached past the expiry of the signatures behind them" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])
    r = resolver(transport, now: -> { EXPIRES_AT - 20 })

    assert_equal :secure, r.resolve("a.example.test.", "A").status
    monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    lifetimes = zone_cache(r).values.map { |entry| entry[:expires] - monotonic }
    assert_equal 3, lifetimes.size
    assert lifetimes.all? { |seconds| seconds <= 20 }, "DNSKEY TTL is 3600, but every RRSIG lapses in 20s: #{lifetimes.inspect}"
  end

  test "the zone cache sweeps expired entries and stays bounded" do
    transport = self.class.base_transport
    transport.add DnsResponse.build("a.example.test.", "A", answer: [ signed(self.class.a_rrset, EXAMPLE) ])
    r = resolver(transport)
    cache = zone_cache(r)
    max = MailOnRails::Dnssec::Resolver::ZONE_CACHE_MAX
    monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    (max - 10).times { |i| cache["expired#{i}"] = { value: { status: :insecure }, expires: monotonic - 1 } }
    10.times { |i| cache["live#{i}"] = { value: { status: :insecure }, expires: monotonic + 300 } }

    assert_equal :secure, r.resolve("a.example.test.", "A").status
    assert_equal 13, cache.size, "the 10 live entries plus the three zones just validated"

    (max + 50).times { |i| cache["flood#{i}"] = { value: { status: :insecure }, expires: monotonic + 300 } }
    r.send(:cache_put, "one-more", { status: :insecure })
    assert_operator cache.size, :<=, max
    assert cache.key?("one-more")
  end
end
