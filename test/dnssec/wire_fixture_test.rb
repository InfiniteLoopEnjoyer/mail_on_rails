# frozen_string_literal: true

require "test_helper"

# Real responses captured off the wire (Google Public DNS, 2026-08-17) and
# replayed through Message.decode - the synthetic suites build records
# from presentation strings, so these keep the wire-decode path honest
# (type bitmaps, hashed owner labels, and the []-salt quirk all come out
# of decode_rdata here).
class WireFixtureTest < Minitest::Test
  def fixture(name)
    Dnsruby::Message.decode(File.binread(File.expand_path("fixtures/#{name}", __dir__)))
  end

  test "a live no-opt-out NXDOMAIN verifies :secure" do
    msg = fixture("nxdomain_icann_org.bin")
    result = Dnsruby::Nsec3Proof.verify(msg)
    assert_equal :name_error, result.proof
    assert_equal :secure, result.status
    assert_equal "icann.org", result.closest_encloser.to_s
  end

  test "a live TLSA denial under com's Opt-Out chain verifies :insecure" do
    # The DANE-critical shape (RFC 7672 section 2.2): TLSA provably has no
    # signed data, but com signs with Opt-Out, so the name is outside
    # DNSSEC - never "securely absent". Also exercises a zero-length salt
    # arriving off the wire as [].
    msg = fixture("tlsa_nxdomain_com.bin")
    nsec3s = Dnsruby::Nsec3Proof.records(msg)
    assert_equal [ "" ], nsec3s.map(&:raw_salt).uniq

    result = Dnsruby::Nsec3Proof.verify(msg)
    assert_equal :name_error, result.proof
    assert_equal :insecure, result.status
    assert_equal "com", result.closest_encloser.to_s
  end

  test "tampering with a live response is caught" do
    msg = fixture("nxdomain_icann_org.bin")
    # Drop the record covering the next-closer name: the denial no longer
    # holds together even though every remaining record is authentic.
    qname = Dnsruby::Name.create(msg.question[0].qname.to_s + ".")
    nsec3s = Dnsruby::Nsec3Proof.records(msg)
    ce = Dnsruby::Nsec3Proof.closest_encloser_proof(qname, nsec3s)
    kept = nsec3s - [ ce[:covering] ]

    tampered = Rfc5155Zone.response(qname, msg.question[0].qtype,
                                    rcode: Dnsruby::RCode.NXDOMAIN, authority: kept)
    assert_raises(Dnsruby::VerifyError) { Dnsruby::Nsec3Proof.verify(tampered) }
  end
end
