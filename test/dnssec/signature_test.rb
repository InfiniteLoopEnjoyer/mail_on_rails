# frozen_string_literal: true

require "test_helper"
require "signer"

# Signature.verify: one RRSIG, one RRset, one DNSKEY, one instant.
#
# The known-answer half replays the example keys and signatures the
# algorithm RFCs publish, so the canonical form and each algorithm's
# signature encoding are checked against data this codebase did not
# produce. The rest signs with TestZone (which assembles its signed data
# its own way) and probes the RFC 4035 section 5.3.1 preconditions.
class SignatureTest < Minitest::Test
  Signature = MailOnRails::Dnssec::Signature

  Vector = Struct.new(:name, :dnskey, :rrset, :rrsig, :at, keyword_init: true)

  MX = "example.com. 3600 IN MX 10 mail.example.com."
  A1 = "www.example.net. 3600 IN A 192.0.2.1"
  A91 = "www.example.net. 3600 IN A 192.0.2.91"

  VECTORS = [
    # RFC 5702 section 6.1 (a 512-bit key: the RFC's, not a recommendation).
    Vector.new(
      name: "RSASHA256", at: Time.utc(2020, 1, 1), rrset: A91,
      dnskey: "example.net. 3600 IN DNSKEY 256 3 8 AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P" \
              "kxUdp6p/DlUmObdk=",
      rrsig: "www.example.net. 3600 IN RRSIG A 8 3 3600 20300101000000 20000101000000 9033 example.net. " \
             "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg=="
    ),
    # RFC 5702 section 6.2.
    Vector.new(
      name: "RSASHA512", at: Time.utc(2020, 1, 1), rrset: A91,
      dnskey: "example.net. 3600 IN DNSKEY 256 3 10 AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD" \
              "xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL",
      rrsig: "www.example.net. 3600 IN RRSIG A 10 3 3600 20300101000000 20000101000000 3740 example.net. " \
             "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfRe" \
             "KBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw="
    ),
    # RFC 6605 section 6.1.
    Vector.new(
      name: "ECDSAP256SHA256", at: Time.utc(2010, 8, 20), rrset: A1,
      dnskey: "example.net. 3600 IN DNSKEY 257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9x" \
              "MWyQLc8NAA==",
      rrsig: "www.example.net. 3600 IN RRSIG A 13 3 3600 20100909100439 20100812100439 55648 example.net. " \
             "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="
    ),
    # RFC 6605 section 6.2.
    Vector.new(
      name: "ECDSAP384SHA384", at: Time.utc(2010, 8, 20), rrset: A1,
      dnskey: "example.net. 3600 IN DNSKEY 257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRS" \
              "EkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
      rrsig: "www.example.net. 3600 IN RRSIG A 14 3 3600 20100909102025 20100812102025 10771 example.net. " \
             "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI" \
             "0RSMROxxwGipWcJm"
    ),
    # RFC 8080 section 6.1, as corrected by verified erratum 4935 (the
    # RFC's own RRSIGs omit the algorithm and miscount the labels).
    Vector.new(
      name: "ED25519", at: Time.at(1_439_000_000), rrset: MX,
      dnskey: "example.com. 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
      rrsig: "example.com. 3600 IN RRSIG MX 15 2 3600 1440021600 1438207200 3613 example.com. " \
             "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg=="
    ),
    Vector.new(
      name: "ED25519 (second key)", at: Time.at(1_439_000_000), rrset: MX,
      dnskey: "example.com. 3600 IN DNSKEY 257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=",
      rrsig: "example.com. 3600 IN RRSIG MX 15 2 3600 1440021600 1438207200 35217 example.com. " \
             "zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg=="
    ),
    # RFC 8080 section 6.2, same erratum.
    Vector.new(
      name: "ED448", at: Time.at(1_439_000_000), rrset: MX,
      dnskey: "example.com. 3600 IN DNSKEY 257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA",
      rrsig: "example.com. 3600 IN RRSIG MX 16 2 3600 1440021600 1438207200 9713 example.com. " \
             "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0amxWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE58" \
             "1N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA"
    ),
    Vector.new(
      name: "ED448 (second key)", at: Time.at(1_439_000_000), rrset: MX,
      dnskey: "example.com. 3600 IN DNSKEY 257 3 16 kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcNLp5HlHAMy12VoISsA",
      rrsig: "example.com. 3600 IN RRSIG MX 16 2 3600 1440021600 1438207200 38353 example.com. " \
             "E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4Sp8Syg1eI+lJ57CSnZqjJP41O/9l4m0AsQ4f7qI1gVnML8vWWiyW2KXhT9kuAICUSxv5" \
             "OWbf81Rq7Yu60npabODB0QFPb/rkW3kUZmQ0YQUA"
    )
  ].freeze

  def load_vector(vector)
    [ TestZone.rrset(Dnsruby::RR.create(vector.rrset)), Dnsruby::RR.create(vector.rrsig), Dnsruby::RR.create(vector.dnskey) ]
  end

  VECTORS.each do |vector|
    test "the published #{vector.name} example verifies" do
      rrset, sig, key = load_vector(vector)
      assert Signature.verify(rrset, sig, key, now: vector.at)
    end

    test "the published #{vector.name} example fails once a signature bit flips" do
      rrset, sig, key = load_vector(vector)
      sig.signature = sig.signature.dup.tap { |s| s.setbyte(5, s.getbyte(5) ^ 0x01) }
      assert_not Signature.verify(rrset, sig, key, now: vector.at)
    end

    test "the published #{vector.name} example fails over different data" do
      _rrset, sig, key = load_vector(vector)
      other = vector.rrset.sub("192.0.2.", "198.51.100.").sub("MX 10 mail", "MX 10 evil")
      assert_not Signature.verify(TestZone.rrset(Dnsruby::RR.create(other)), sig, key, now: vector.at)
    end
  end

  # ----- everything below signs its own material ------------------------

  SIGNED_AT = Time.utc(2026, 8, 1)
  EXPIRES_AT = Time.utc(2026, 9, 1)
  NOW = Time.utc(2026, 8, 15)

  ZONE = TestZone.new("example.test.", algorithm: TestZone::ALG_ECDSAP256)
  OTHER = TestZone.new("example.test.", algorithm: TestZone::ALG_ECDSAP256)

  def rrset(*lines)
    TestZone.rrset(lines.map { |line| Dnsruby::RR.create(line) })
  end

  def sign(rrset, zone = ZONE, **opts)
    zone.sign(rrset, signed_at: SIGNED_AT, expires_at: EXPIRES_AT, **opts)
  end

  def verify(rrset, key = ZONE.dnskey, now: NOW, sig: rrset.sigs[0])
    Signature.verify(rrset, sig, key, now: now)
  end

  test "the validity window is inclusive at both ends and closed outside them" do
    set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"))
    assert verify(set, now: SIGNED_AT)
    assert verify(set, now: EXPIRES_AT)
    assert_not verify(set, now: SIGNED_AT - 1)
    assert_not verify(set, now: EXPIRES_AT + 1)
  end

  test "validity times are serial numbers and survive the 32-bit wrap" do
    sig = sign(rrset("a.example.test. 300 IN A 192.0.2.1")).sigs[0]
    wrap = 1 << 32
    sig.inception = wrap - 1000 # just before the wrap
    sig.expiration = 1000       # just after it
    assert Signature.valid_at?(sig, wrap - 10)
    assert Signature.valid_at?(sig, wrap + 10)
    assert_not Signature.valid_at?(sig, wrap - 2000)
    assert_not Signature.valid_at?(sig, wrap + 2000)
  end

  test "records verify in any order, at any remaining TTL, in any owner case" do
    lines = %w[192.0.2.3 192.0.2.1 192.0.2.2].map { |ip| "a.example.test. 300 IN A #{ip}" }
    signed = sign(rrset(*lines))

    received = rrset(*lines.reverse.map { |line| line.sub("a.example.test. 300", "A.Example.TEST. 17") })
    assert verify(received, sig: signed.sigs[0]), "canonical form ignores order, cache-aged TTLs and owner case"
  end

  test "names inside RDATA are compared in canonical (lowercase) form" do
    signed = sign(rrset("example.test. 300 IN MX 10 mail.example.test."))
    received = rrset("example.test. 300 IN MX 10 MAIL.Example.Test.")
    assert verify(received, sig: signed.sigs[0])
  end

  test "a wildcard-expanded RRset verifies over the owner the Labels field names" do
    expanded = rrset("x.w.example.test. 300 IN TXT \"wild\"")
    sign(expanded, sign_as: "*.w.example.test.", labels: 3)
    assert verify(expanded)

    # The same signature claimed for the literal owner (Labels says "not
    # a wildcard") is over different data.
    literal = expanded.sigs[0]
    literal.labels = 4
    assert_not verify(expanded, sig: literal)
  end

  test "a Labels count the owner or the signing zone cannot have is rejected" do
    set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"))
    sig = set.sigs[0]

    sig.labels = 4 # more labels than the owner has
    assert_not verify(set, sig: sig)
    sig.labels = 1 # a wildcard source above the signing zone
    assert_not verify(set, sig: sig)
  end

  test "another key with the same owner and algorithm does not verify" do
    set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"))
    assert_not verify(set, OTHER.dnskey)
  end

  test "a key that is not a zone key, or is revoked, is never used" do
    not_zone = TestZone.new("example.test.", algorithm: TestZone::ALG_ECDSAP256)
    not_zone.dnskey.zone_key = false
    set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"), not_zone)
    assert_equal not_zone.dnskey.key_tag, set.sigs[0].key_tag
    assert_not verify(set, not_zone.dnskey)

    revoked = TestZone.new("example.test.", algorithm: TestZone::ALG_ECDSAP256)
    revoked.dnskey.revoked = true
    set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"), revoked)
    assert_equal revoked.dnskey.key_tag, set.sigs[0].key_tag
    assert_not verify(set, revoked.dnskey)
  end

  test "the RRSIG must belong to the RRset it is offered for" do
    a = sign(rrset("a.example.test. 300 IN A 192.0.2.1"))
    b = rrset("b.example.test. 300 IN A 192.0.2.1")
    txt = rrset("a.example.test. 300 IN TXT \"x\"")

    assert_not verify(b, sig: a.sigs[0]), "different owner"
    assert_not verify(txt, sig: a.sigs[0]), "different type"
  end

  test "an RRset outside the signer's zone is out of bailiwick" do
    elsewhere = TestZone.new("other.test.", algorithm: TestZone::ALG_ECDSAP256)
    set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"), elsewhere)
    assert_not verify(set, elsewhere.dnskey)
  end

  test "malformed signatures and keys are failures, never exceptions" do
    set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"))
    sig = set.sigs[0]
    good = sig.signature

    sig.signature = good.byteslice(0, 63) # ECDSA r | s must be exactly 64 octets
    assert_not verify(set, sig: sig)
    sig.signature = ""
    assert_not verify(set, sig: sig)

    ed = TestZone.new("example.test.", algorithm: TestZone::ALG_ED25519)
    ed_set = sign(rrset("a.example.test. 300 IN A 192.0.2.1"), ed)
    ed_set.sigs[0].signature = ed_set.sigs[0].signature + "\x00"
    assert_not verify(ed_set, ed.dnskey)

    # A DNSKEY whose key material is not a point on the curve. It has
    # to arrive off the wire: only there is the key parsed lazily.
    wire = Dnsruby::Message.new("example.test.", "DNSKEY").tap { |m| m.add_answer(ZONE.dnskey) }.encode
    wire[wire.index(ZONE.dnskey.key.b), 64] = "\x01".b * 64
    junk = Dnsruby::Message.decode(wire).answer.rrset("example.test.", "DNSKEY").rrs[0]
    sig.signature = good
    sig.key_tag = junk.key_tag
    assert_not verify(set, junk, sig: sig)
  end

  test "DSA and unassigned algorithms are unsupported; the modern set is not" do
    [ 5, 7, 8, 10, 13, 14, 15, 16 ].each { |code| assert Signature.supported_algorithm?(code), "algorithm #{code}" }
    [ 1, 3, 6, 12, 17, 253 ].each { |code| assert_not Signature.supported_algorithm?(code), "algorithm #{code}" }
  end
end
