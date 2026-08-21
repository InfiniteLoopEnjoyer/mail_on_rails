# frozen_string_literal: true

require "test_helper"

# The record-level primitives: RFC 5155 section 5 hashing against the
# spec's Appendix A vectors, and the matches?/covers? comparisons the
# section 8 proofs are built from.
class Nsec3RecordTest < Minitest::Test
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
    assert record.matches?("ns1.example.")
    assert record.matches?("NS1.Example."), "hashing must canonicalize case"
    assert_not record.matches?("ns2.example.")
  end

  test "covers? spans the gap between owner and next hash" do
    # H(c.x.w.example) = 0va5... falls between 0p9m... and 2t7b... (B.1).
    record = Rfc5155Zone.nsec3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")
    assert record.covers?("c.x.w.example.")
    assert_not record.covers?("ns1.example."), "chain boundary hashes are matched, not covered"
    assert_not record.covers?("example."), "the owner's own name is matched, not covered"
  end

  test "covers? wraps from the chain's last record to its first" do
    last = Rfc5155Zone.nsec3("t644ebqk9bibcna874givr6joj62mlhv")
    # Find a name whose hash falls outside [first owner, last owner] -
    # such names exist in the wrap span between t644... and 0p9m....
    wrapped = (0..999).map { |i| "wrap#{i}.example." }.find do |candidate|
      hash = last.proof_hash(candidate)
      hash > last.hashed_owner_label || hash < "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
    end
    assert wrapped, "expected some candidate to hash into the wrap span"
    assert last.covers?(wrapped)
    assert_not last.covers?("example."), "0p9m... is the wrap boundary itself"
    assert_not last.covers?("xx.example."), "the owner's own name is not covered"
  end

  test "names outside the record's zone are neither matched nor covered" do
    record = Rfc5155Zone.nsec3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")
    assert_not record.matches?("elsewhere.test.")
    assert_not record.covers?("elsewhere.test.")
  end

  test "iteration counts beyond the RFC 9276 cap make a record unusable" do
    assert Rfc5155Zone.nsec3(Rfc5155Zone::CHAIN.keys.first, iterations: 100).usable_for_proofs?
    capped = Rfc5155Zone.nsec3(Rfc5155Zone::CHAIN.keys.first, iterations: 101)
    assert_not capped.usable_for_proofs?
    assert_not capped.matches?("example.")
    assert_not capped.covers?("c.x.w.example.")
  end

  test "ancestor_delegation? flags NS-without-SOA bitmaps" do
    delegation = Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("a.example.")) # NS DS RRSIG
    apex = Rfc5155Zone.nsec3(Rfc5155Zone.hash_of("example.")) # NS and SOA
    assert delegation.ancestor_delegation?
    assert_not apex.ancestor_delegation?
  end

  test "a zero-length salt survives the wire round trip" do
    # decode_rdata leaves an absent salt as [] rather than ""; hashing
    # must still work on a record decoded off the wire (com's chain has
    # no salt).
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

    assert_equal "", decoded.raw_salt
    assert decoded.matches?("a.example.")
  end
end
