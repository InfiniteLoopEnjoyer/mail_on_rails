# frozen_string_literal: true

require "test_helper"

# Plain-NSEC denial proofs (RFC 4035), including the minimal-response
# shapes Cloudflare-style "black lies" responders produce.
class NsecProofTest < Minitest::Test
  Proof = Dnsruby::NsecProof

  # A small example. zone: apex -> a -> c -> x.w -> *.z (canonical order:
  # example, a, c, x.w, *.z... wildcards sort as a literal "*" label).
  def nsec(owner, next_name, types)
    Dnsruby::RR.create("#{owner} 300 IN NSEC #{next_name} #{types}")
  end

  def zone_nsecs
    [
      nsec("example.", "a.example.", "SOA NS RRSIG NSEC"),
      nsec("a.example.", "c.example.", "A RRSIG NSEC"),
      nsec("c.example.", "x.w.example.", "A AAAA RRSIG NSEC"),
      nsec("x.w.example.", "example.", "TXT RRSIG NSEC") # wraps to apex
    ]
  end

  test "covers? spans gaps exclusively and wraps at the apex" do
    middle = nsec("a.example.", "c.example.", "A")
    assert Proof.covers?(middle, "b.example.")
    assert_not Proof.covers?(middle, "a.example."), "owner is matched, not covered"
    assert_not Proof.covers?(middle, "c.example."), "next name is not covered"

    last = nsec("x.w.example.", "example.", "TXT")
    assert Proof.covers?(last, "z.example."), "the last NSEC covers to the end of the zone"
    assert Proof.covers?(last, "y.w.example.")
    assert_not Proof.covers?(last, "example."), "the apex itself is never covered"
    assert_not Proof.covers?(last, "b.example."), "names before the owner are not covered by the wrap"
  end

  test "name error needs a cover for qname and for the wildcard" do
    result = Proof.name_error(Dnsruby::Name.create("b.example."), zone_nsecs)
    assert_equal :name_error, result.proof
    assert_equal :secure, result.status
    assert_equal "example", result.closest_encloser.to_s

    # Without the apex NSEC there is no proof that *.example is absent.
    assert_nil Proof.name_error(Dnsruby::Name.create("b.example."), zone_nsecs[1..])
  end

  test "no data by direct match checks qtype and CNAME bits" do
    result = Proof.no_data(Dnsruby::Name.create("a.example."), Dnsruby::Types.MX, zone_nsecs)
    assert_equal :no_data, result.proof

    assert_nil Proof.no_data(Dnsruby::Name.create("a.example."), Dnsruby::Types.A, zone_nsecs),
               "the bitmap has A, so no-data for A is a lie"

    cname_owner = [ nsec("a.example.", "c.example.", "CNAME RRSIG") ]
    assert_nil Proof.no_data(Dnsruby::Name.create("a.example."), Dnsruby::Types.MX, cname_owner),
               "a CNAME owner answers every type; no-data proves nothing"
  end

  test "black-lies minimal responses prove no data" do
    # Synthesized NSEC: owner == qname, next is the immediate successor,
    # bitmap admits only RRSIG+NSEC.
    lies = [ nsec("host.example.", "\\000.host.example.", "RRSIG NSEC") ]
    result = Proof.no_data(Dnsruby::Name.create("host.example."), Dnsruby::Types.TLSA, lies)
    assert_equal :no_data, result.proof
    assert_equal :secure, result.status
  end

  test "an ancestor delegation NSEC cannot prove no-data below itself" do
    delegation = [ nsec("sub.example.", "z.example.", "NS RRSIG NSEC") ]
    assert_nil Proof.no_data(Dnsruby::Name.create("sub.example."), Dnsruby::Types.MX, delegation)
    result = Proof.no_data(Dnsruby::Name.create("sub.example."), Dnsruby::Types.DS, delegation)
    assert_equal :no_data, result.proof, "DS is the one type the parent still owns"
  end

  test "wildcard no data proves the wildcard exists but lacks the type" do
    nsecs = [
      nsec("example.", "*.example.", "SOA NS RRSIG NSEC"),
      nsec("*.example.", "b.example.", "TXT RRSIG NSEC")
    ]
    result = Proof.no_data(Dnsruby::Name.create("a.example."), Dnsruby::Types.MX, nsecs)
    assert_equal :wildcard_no_data, result.proof

    assert_nil Proof.no_data(Dnsruby::Name.create("a.example."), Dnsruby::Types.TXT, nsecs),
               "the wildcard has TXT, so it would have been expanded"
  end

  test "wildcard answers need the next-closer name covered" do
    nsecs = [ nsec("c.example.", "x.w.example.", "A RRSIG NSEC") ]
    # qname h.example (2 labels + 1), synthesized from *.example (rrsig labels 1)
    result = Proof.wildcard_answer(Dnsruby::Name.create("h.example."), 1, nsecs)
    assert_equal :wildcard_answer, result.proof

    assert_nil Proof.wildcard_answer(Dnsruby::Name.create("a.example."), 1, nsecs),
               "a.example sorts before the covering span"
    assert_nil Proof.wildcard_answer(Dnsruby::Name.create("h.example."), 2, nsecs),
               "labels equal to the owner's is not an expansion"
  end

  test "insecure_delegation? reads the delegation bitmap" do
    nsecs = zone_nsecs
    assert_not Proof.insecure_delegation?(Dnsruby::Name.create("a.example."), nsecs)

    delegation = [ nsec("sub.example.", "z.example.", "NS RRSIG NSEC") ]
    assert Proof.insecure_delegation?(Dnsruby::Name.create("sub.example."), delegation)

    signed_delegation = [ nsec("sub.example.", "z.example.", "NS DS RRSIG NSEC") ]
    assert_not Proof.insecure_delegation?(Dnsruby::Name.create("sub.example."), signed_delegation)
  end

  test "matching and covering are case-insensitive" do
    middle = nsec("a.example.", "c.example.", "A")
    assert Proof.matches?(middle, "A.Example.")
    assert Proof.covers?(middle, "B.EXAMPLE.")
  end
end
