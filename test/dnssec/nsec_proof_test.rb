# frozen_string_literal: true

require "test_helper"

# Plain-NSEC denial proofs (RFC 4035), including the minimal-response
# shapes Cloudflare-style "black lies" responders produce.
class NsecProofTest < Minitest::Test
  Proof = MailOnRails::Dnssec::NsecProof

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

  test "a delegation NSEC denies the gap after it, but nothing beneath it" do
    # The root zone in miniature: every NSEC but the apex's sits at a
    # delegation. A TLD that does not exist is denied by two of them.
    root = [
      nsec(".", "aaa.", "NS SOA RRSIG NSEC DNSKEY"),
      nsec("nokia.", "northwesternmutual.", "NS DS RRSIG NSEC")
    ]
    result = Proof.name_error(Dnsruby::Name.create("example.nonexistent."), root)
    assert_equal :name_error, result.proof
    assert_equal :secure, result.status
    assert_empty result.closest_encloser.labels, "the closest encloser is the root itself"

    # Canonical order puts deep.nokia. inside the same NSEC's span, but
    # nokia.'s own zone is the authority there (RFC 6840 section 4.1).
    assert Proof.covers?(root[1], "deep.nokia.")
    assert_nil Proof.name_error(Dnsruby::Name.create("deep.nokia."), root)
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

  # An empty non-terminal owns no NSEC of its own; the record before it
  # in the chain shows it, by pointing at a name beneath it (RFC 4592
  # section 2.2.2). zone_nsecs has one: w.example., above x.w.example.
  test "an empty non-terminal has no data of any type" do
    ent = Dnsruby::Name.create("w.example.")
    assert Proof.empty_non_terminal?(zone_nsecs[2], ent)

    [ Dnsruby::Types.TLSA, Dnsruby::Types.MX, Dnsruby::Types.DS ].each do |qtype|
      result = Proof.no_data(ent, qtype, zone_nsecs)
      assert_equal :no_data, result.proof, "#{qtype} at an empty non-terminal"
      assert_equal :secure, result.status
    end

    assert_nil Proof.no_data(Dnsruby::Name.create("d.example."), Dnsruby::Types.MX, zone_nsecs[2..2]),
               "d.example sorts in the same gap but nothing lies beneath it: that is nonexistence, not no-data"
  end

  test "an empty non-terminal exists: no name error for it or through it" do
    assert_nil Proof.name_error(Dnsruby::Name.create("w.example."), zone_nsecs),
               "x.w.example exists, so w.example does"
    assert_not Proof.proves_absent?(zone_nsecs[2], "w.example.")

    # A sibling in the same gap really is absent.
    result = Proof.name_error(Dnsruby::Name.create("d.example."), zone_nsecs)
    assert_equal :name_error, result.proof

    # A wildcard that is itself an empty non-terminal exists as well, so
    # "no wildcard" is not proven by the gap it sits in.
    nsecs = [
      nsec("example.", "a.*.example.", "SOA NS RRSIG NSEC"),
      nsec("a.*.example.", "example.", "A RRSIG NSEC")
    ]
    assert_nil Proof.name_error(Dnsruby::Name.create("b.example."), nsecs)
  end

  test "a wildcard cannot answer for an empty non-terminal or anything beneath it" do
    nsecs = [ nsec("c.example.", "x.w.example.", "A AAAA RRSIG NSEC") ]
    # qname q.w.example, "synthesized" from *.example (rrsig labels 1):
    # the next-closer name w.example sorts inside the gap, but exists.
    assert_nil Proof.wildcard_answer(Dnsruby::Name.create("q.w.example."), 1, nsecs)
    assert_nil Proof.wildcard_answer(Dnsruby::Name.create("w.example."), 1, nsecs)
    assert_equal :wildcard_answer, Proof.wildcard_answer(Dnsruby::Name.create("d.example."), 1, nsecs).proof
  end

  test "a delegation NSEC cannot show an empty non-terminal beneath itself" do
    odd = [ nsec("sub.example.", "a.b.sub.example.", "NS RRSIG NSEC") ]
    assert_nil Proof.no_data(Dnsruby::Name.create("b.sub.example."), Dnsruby::Types.MX, odd)
  end
end
