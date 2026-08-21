# frozen_string_literal: true

require "test_helper"

# The RFC 5155 section 8 proofs, exercised with the spec's own Appendix B
# response scenarios (built over the Appendix A zone). The appendix zone
# signs with Opt-Out, so its proofs come back :insecure; rebuilding the
# same chain with flags: 0 asserts the :secure variants.
class Nsec3ProofTest < Minitest::Test
  Proof = Dnsruby::Nsec3Proof

  SOA = Dnsruby::RR.create("example. 3600 IN SOA ns1.example. bugs.x.w.example. 1 3600 300 3600000 3600")

  def verify(msg)
    Proof.verify(msg)
  end

  def refute_proven(msg)
    assert_raises(Dnsruby::VerifyError) { verify(msg) }
  end

  # B.1: a.c.x.w.example does not exist. b4um... matches the closest
  # encloser (x.w.example), 0p9m... covers the next closer
  # (c.x.w.example), 35mt... covers the wildcard (*.x.w.example).
  B1_OWNERS = [
    "b4um86eghhds6nea196smvmlo4ors995",
    "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    "35mthgpgcu1qg68fab165klnsnk3dpvl"
  ].freeze

  test "B.1 name error" do
    msg = Rfc5155Zone.response("a.c.x.w.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: [ SOA, *Rfc5155Zone.chain(*B1_OWNERS) ])
    result = verify(msg)
    assert_equal :name_error, result.proof
    assert_equal :insecure, result.status, "Opt-Out spans cannot prove secure nonexistence"
    assert_equal "x.w.example", result.closest_encloser.to_s
  end

  test "B.1 name error is :secure without Opt-Out" do
    msg = Rfc5155Zone.response("a.c.x.w.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: Rfc5155Zone.chain(*B1_OWNERS, flags: 0))
    assert_equal :secure, verify(msg).status
  end

  test "name error without the wildcard cover is bogus" do
    msg = Rfc5155Zone.response("a.c.x.w.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: Rfc5155Zone.chain(*B1_OWNERS.first(2)))
    refute_proven msg
  end

  test "name error without the next-closer cover is bogus" do
    msg = Rfc5155Zone.response("a.c.x.w.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: Rfc5155Zone.chain(*B1_OWNERS.values_at(0, 2)))
    refute_proven msg
  end

  test "name error for a name that exists is bogus" do
    msg = Rfc5155Zone.response("ns1.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: Rfc5155Zone.chain)
    refute_proven msg
  end

  test "B.2 no data" do
    msg = Rfc5155Zone.response("ns1.example.", Dnsruby::Types.MX,
                               authority: [ SOA, Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("ns1.example.")) ])
    result = verify(msg)
    assert_equal :no_data, result.proof
    assert_equal :secure, result.status, "a matching record proves no-data even in an Opt-Out zone"
  end

  test "B.2.1 no data at an empty non-terminal" do
    msg = Rfc5155Zone.response("y.w.example.", Dnsruby::Types.A,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("y.w.example.")) ])
    assert_equal :no_data, verify(msg).proof
  end

  test "no data claiming a type the record contains is bogus" do
    msg = Rfc5155Zone.response("ns1.example.", Dnsruby::Types.A,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("ns1.example.")) ])
    refute_proven msg
  end

  test "B.3 referral to an Opt-Out unsigned zone is :insecure" do
    msg = Rfc5155Zone.response("mc.c.example.", Dnsruby::Types.MX,
                               authority: [
                                 Dnsruby::RR.create("c.example. 3600 IN NS ns1.c.example."),
                                 *Rfc5155Zone.chain("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                                                    "35mthgpgcu1qg68fab165klnsnk3dpvl")
                               ])
    result = verify(msg)
    assert_equal :referral, result.proof
    assert_equal :insecure, result.status
  end

  test "the same referral without Opt-Out is bogus" do
    msg = Rfc5155Zone.response("mc.c.example.", Dnsruby::Types.MX,
                               authority: [
                                 Dnsruby::RR.create("c.example. 3600 IN NS ns1.c.example."),
                                 *Rfc5155Zone.chain("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                                                    "35mthgpgcu1qg68fab165klnsnk3dpvl", flags: 0)
                               ])
    refute_proven msg
  end

  test "B.4 wildcard expansion" do
    answer = [
      Dnsruby::RR.create("a.z.w.example. 3600 IN MX 1 ai.example."),
      Dnsruby::RR.create("a.z.w.example. 3600 IN RRSIG MX 7 2 3600 20150420235959 20051021000000 40430 example. AAAA")
    ]
    msg = Rfc5155Zone.response("a.z.w.example.", Dnsruby::Types.MX, answer: answer,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("ns2.example.")) ])
    result = verify(msg)
    assert_equal :wildcard_answer, result.proof
    assert_equal :insecure, result.status
  end

  test "wildcard expansion without the next-closer cover is bogus" do
    answer = [
      Dnsruby::RR.create("a.z.w.example. 3600 IN MX 1 ai.example."),
      Dnsruby::RR.create("a.z.w.example. 3600 IN RRSIG MX 7 2 3600 20150420235959 20051021000000 40430 example. AAAA")
    ]
    msg = Rfc5155Zone.response("a.z.w.example.", Dnsruby::Types.MX, answer: answer,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("ns1.example.")) ])
    refute_proven msg
  end

  test "a positive answer that is not wildcard-expanded needs no proof" do
    answer = [
      Dnsruby::RR.create("xx.example. 3600 IN A 192.0.2.10"),
      Dnsruby::RR.create("xx.example. 3600 IN RRSIG A 7 2 3600 20150420235959 20051021000000 40430 example. AAAA")
    ]
    msg = Rfc5155Zone.response("xx.example.", Dnsruby::Types.A, answer: answer,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("example.")) ])
    assert_nil verify(msg)
  end

  # B.5: a.z.w.example has no AAAA. k8ud... matches the closest encloser
  # (w.example), q04j... covers the next closer (z.w.example), r53b...
  # matches *.w.example whose bitmap has MX but no AAAA.
  B5_OWNERS = [
    "k8udemvp1j2f7eg6jebps17vp3n8i58h",
    "q04jkcevqvmu85r014c7dkba38o0ji5r",
    "r53bq7cc2uvmubfu5ocmm6pers9tk9en"
  ].freeze

  test "B.5 wildcard no data" do
    msg = Rfc5155Zone.response("a.z.w.example.", Dnsruby::Types.AAAA,
                               authority: [ SOA, *Rfc5155Zone.chain(*B5_OWNERS) ])
    result = verify(msg)
    assert_equal :wildcard_no_data, result.proof
    assert_equal :insecure, result.status
  end

  test "B.5 wildcard no data is :secure without Opt-Out" do
    msg = Rfc5155Zone.response("a.z.w.example.", Dnsruby::Types.AAAA,
                               authority: Rfc5155Zone.chain(*B5_OWNERS, flags: 0))
    assert_equal :secure, verify(msg).status
  end

  test "wildcard no data for a type the wildcard has is bogus" do
    msg = Rfc5155Zone.response("a.z.w.example.", Dnsruby::Types.MX,
                               authority: Rfc5155Zone.chain(*B5_OWNERS))
    refute_proven msg
  end

  test "B.6 DS no data at the apex" do
    msg = Rfc5155Zone.response("example.", Dnsruby::Types.DS,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("example.")) ])
    result = verify(msg)
    assert_equal :no_data, result.proof
    assert_equal :secure, result.status
  end

  test "DS no data across an Opt-Out span is :insecure" do
    msg = Rfc5155Zone.response("c.example.", Dnsruby::Types.DS,
                               authority: Rfc5155Zone.chain("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                                                            "35mthgpgcu1qg68fab165klnsnk3dpvl"))
    result = verify(msg)
    assert_equal :no_data, result.proof
    assert_equal :insecure, result.status
  end

  test "an ancestor delegation cannot prove no-data below itself" do
    # a.example's NSEC3 has NS without SOA: the child zone answers for
    # everything but DS there, so "no MX at a.example" is not provable
    # from the parent.
    msg = Rfc5155Zone.response("a.example.", Dnsruby::Types.MX,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("a.example.")) ])
    refute_proven msg
  end

  test "an ancestor delegation still proves DS no-data" do
    unsigned = Dnsruby::RR.create(
      "#{Rfc5155Zone.hash_of("a.example.")}.example. 3600 IN NSEC3 1 0 12 #{Rfc5155Zone::SALT} " \
      "b4um86eghhds6nea196smvmlo4ors995 NS RRSIG"
    )
    msg = Rfc5155Zone.response("a.example.", Dnsruby::Types.DS, authority: [ unsigned ])
    assert_equal :no_data, verify(msg).proof
  end

  test "an ancestor delegation cannot act as a closest encloser" do
    # foo.a.example is below the a.example delegation; the parent zone's
    # chain must not "prove" its nonexistence.
    msg = Rfc5155Zone.response("foo.a.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: [ Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("a.example.")) ])
    refute_proven msg
  end

  test "responses whose NSEC3 records are all unusable are :insecure, not bogus" do
    over_iterated = Rfc5155Zone::CHAIN.keys.map { |o| Rfc5155Zone.nsec3(o, iterations: 2500) }
    msg = Rfc5155Zone.response("a.c.x.w.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN, authority: over_iterated)
    result = verify(msg)
    assert_equal :none, result.proof
    assert_equal :insecure, result.status
  end

  test "a response without NSEC3 records needs no proof here" do
    msg = Rfc5155Zone.response("ns1.example.", Dnsruby::Types.MX, authority: [ SOA ])
    assert_nil verify(msg)
  end
end
