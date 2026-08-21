# frozen_string_literal: true

require "test_helper"

# The SingleVerifier#verify_nsecs override: NSEC3 responses reach the
# RFC 5155 proofs, NSEC responses keep dnsruby's stock logic.
class VerifyNsecsTest < Minitest::Test
  def verifier
    Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
  end

  test "a valid NSEC3 name error passes verify_nsecs" do
    msg = Rfc5155Zone.response("a.c.x.w.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: Rfc5155Zone.chain("b4um86eghhds6nea196smvmlo4ors995",
                                                            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                                                            "35mthgpgcu1qg68fab165klnsnk3dpvl"))
    assert_nil verifier.verify_nsecs(msg)
  end

  test "an unproven NSEC3 denial raises through verify_nsecs" do
    msg = Rfc5155Zone.response("a.c.x.w.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN,
                               authority: [ Rfc5155Zone.nsec3("b4um86eghhds6nea196smvmlo4ors995") ])
    assert_raises(Dnsruby::VerifyError) { verifier.verify_nsecs(msg) }
  end

  test "NOERROR NSEC3-type queries are exempt, mirroring the stock guard" do
    msg = Rfc5155Zone.response("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.", Dnsruby::Types.NSEC3,
                               authority: [ Rfc5155Zone.nsec3("2t7b4g4vsa5smi47k61mv5bv1a22bojr") ])
    assert_nil verifier.verify_nsecs(msg)
  end

  test "NSEC responses still take dnsruby's stock path" do
    # An NSEC name error for b.example: apex NSEC proves no wildcard
    # (*.example sorts before a.example), the second NSEC covers
    # b.example. The stock logic accepts this shape - and must still be
    # the code that runs when no NSEC3 records are present.
    authority = [
      Dnsruby::RR.create("example. 3600 IN SOA ns1.example. bugs.x.w.example. 1 3600 300 3600000 3600"),
      Dnsruby::RR.create("example. 3600 IN NSEC a.example. SOA NS RRSIG NSEC"),
      Dnsruby::RR.create("a.example. 3600 IN NSEC c.example. A RRSIG NSEC")
    ]
    good = Rfc5155Zone.response("b.example.", Dnsruby::Types.A,
                                rcode: Dnsruby::RCode.NXDOMAIN, authority: authority)
    assert_nil verifier.verify_nsecs(good)

    bad = Rfc5155Zone.response("d.example.", Dnsruby::Types.A,
                               rcode: Dnsruby::RCode.NXDOMAIN, authority: authority)
    assert_raises(Dnsruby::VerifyError) { verifier.verify_nsecs(bad) }
  end
end
