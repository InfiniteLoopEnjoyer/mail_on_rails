# frozen_string_literal: true

require "test_helper"

# The record-level primitives: RFC 5155 section 5 hashing against the
# spec's Appendix A vectors, and the matches?/covers? comparisons the
# section 8 proofs are built from.
class Nsec3RecordTest < Minitest::Test
  Proof = MailOnRails::Dnssec::Nsec3Proof

  RAW_SALT = [ Rfc5155Zone::SALT ].pack("H*")

  test "calculate_hash reproduces every RFC 5155 Appendix A vector" do
    Rfc5155Zone::HASHES.each do |name, expected|
      actual = Dnsruby::RR::NSEC3.calculate_hash(
        Dnsruby::Name.create(name), Rfc5155Zone::ITERATIONS, RAW_SALT,
        Dnsruby::Nsec3HashAlgorithms.SHA_1
      )
      assert_equal expected, actual, "H(#{name})"
    end
  end

  test "matches? recognizes the name a record's owner hash was made from" do
    record = Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("ns1.example."))
    assert Proof.matches?(record, "ns1.example.")
    assert Proof.matches?(record, "NS1.Example."), "hashing must canonicalize case"
    assert_not Proof.matches?(record, "ns2.example.")
  end

  test "covers? spans the gap between owner and next hash" do
    # H(c.x.w.example) = 0va5... falls between 0p9m... and 2t7b... (B.1).
    record = Rfc5155Zone.nsec3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")
    assert Proof.covers?(record, "c.x.w.example.")
    assert_not Proof.covers?(record, "ns1.example."), "chain boundary hashes are matched, not covered"
    assert_not Proof.covers?(record, "example."), "the owner's own name is matched, not covered"
  end

  test "covers? wraps from the chain's last record to its first" do
    last = Rfc5155Zone.nsec3("t644ebqk9bibcna874givr6joj62mlhv")
    # Find a name whose hash falls outside [first owner, last owner] -
    # such names exist in the wrap span between t644... and 0p9m....
    wrapped = (0..999).map { |i| "wrap#{i}.example." }.find do |candidate|
      hash = Proof.hash_of(last, candidate)
      hash > Proof.hashed_owner(last) || hash < "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
    end
    assert wrapped, "expected some candidate to hash into the wrap span"
    assert Proof.covers?(last, wrapped)
    assert_not Proof.covers?(last, "example."), "0p9m... is the wrap boundary itself"
    assert_not Proof.covers?(last, "xx.example."), "the owner's own name is not covered"
  end

  test "names outside the record's zone are neither matched nor covered" do
    record = Rfc5155Zone.nsec3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")
    assert_not Proof.matches?(record, "elsewhere.test.")
    assert_not Proof.covers?(record, "elsewhere.test.")
  end

  test "iteration counts beyond the RFC 9276 cap make a record unusable" do
    assert Proof.usable?(Rfc5155Zone.nsec3(Rfc5155Zone::CHAIN.keys.first, iterations: 100))
    capped = Rfc5155Zone.nsec3(Rfc5155Zone::CHAIN.keys.first, iterations: 101)
    assert_not Proof.usable?(capped)
    assert_not Proof.matches?(capped, "example.")
    assert_not Proof.covers?(capped, "c.x.w.example.")
  end

  test "a record with flags beyond Opt-Out is ignored (RFC 5155 section 8.2)" do
    assert Proof.usable?(Rfc5155Zone.nsec3(Rfc5155Zone::CHAIN.keys.first, flags: 0))
    assert Proof.usable?(Rfc5155Zone.nsec3(Rfc5155Zone::CHAIN.keys.first, flags: 1))
    unknown = Rfc5155Zone.nsec3(Rfc5155Zone::CHAIN.keys.first, flags: 3)
    assert_not Proof.usable?(unknown)
    assert_not Proof.matches?(unknown, "example.")
    assert_not Proof.covers?(unknown, "c.x.w.example.")
  end

  test "ancestor_delegation? flags NS-without-SOA bitmaps" do
    delegation = Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("a.example.")) # NS DS RRSIG
    apex = Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("example.")) # NS and SOA
    assert Proof.ancestor_delegation?(delegation)
    assert_not Proof.ancestor_delegation?(apex)
  end

  test "a zero-length salt survives the wire round trip" do
    # Hashing must work on a saltless record decoded off the wire
    # (com's chain has no salt).
    hash = Dnsruby::RR::NSEC3.calculate_hash(
      Dnsruby::Name.create("a.example."), 0, "", Dnsruby::Nsec3HashAlgorithms.SHA_1
    )
    _next_hash, types = Rfc5155Zone::CHAIN.fetch(Rfc5155Zone.hash_of("a.example."))
    record = Dnsruby::RR.create(
      "#{hash}.example. 3600 IN NSEC3 1 0 0 - #{Rfc5155Zone.hash_of("example.")} #{types}"
    )

    message = Dnsruby::Message.new("a.example.", Dnsruby::Types.A)
    message.add_authority(record)
    decoded = Dnsruby::Message.decode(message.encode).authority.rrsets("NSEC3")[0].rrs[0]

    assert_equal "-", decoded.salt
    assert Proof.matches?(decoded, "a.example.")
  end
end
