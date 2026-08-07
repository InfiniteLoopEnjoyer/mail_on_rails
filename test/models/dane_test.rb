require "test_helper"
require "mail_on_rails/smtp/sender_auth/dns"

# DANE TLSA matching (RFC 7672/6698) against locally minted certificate
# chains: DANE-EE pins the leaf and ignores names/expiry, DANE-TA pins an
# anchor the leaf must chain to and name-match under.
class DaneTest < ActiveSupport::TestCase
  Tlsa = MailOnRails::Smtp::SenderAuth::Dns::Tlsa

  def make_key = OpenSSL::PKey::RSA.new(2048)

  def make_cert(cn, key:, issuer: nil, issuer_key: nil, ca: false, dns_name: nil,
                not_after: Time.now + 86_400)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1_000_000)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.add_extension(factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
    cert.add_extension(factory.create_extension("keyUsage", ca ? "keyCertSign,cRLSign" : "digitalSignature", true))
    cert.add_extension(factory.create_extension("subjectAltName", "DNS:#{dns_name}")) if dns_name
    cert.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
    cert
  end

  setup do
    @ca_key = make_key
    @ca = make_cert("Test CA", key: @ca_key, ca: true)
    @leaf_key = make_key
    @leaf = make_cert("mx.example.com", key: @leaf_key, issuer: @ca, issuer_key: @ca_key,
                      dns_name: "mx.example.com")
    @chain = [ @leaf, @ca ]
  end

  def tlsa(usage:, selector: 1, matching_type: 1, cert:)
    Tlsa.new(usage: usage, selector: selector, matching_type: matching_type,
             data: Dane.association_data(cert, selector, matching_type))
  end

  test "DANE-EE matches the leaf by SPKI SHA-256" do
    record = tlsa(usage: 3, cert: @leaf)
    assert Dane.verify!([ record ], @leaf, @chain, hostname: "mx.example.com")
  end

  test "DANE-EE matches the full certificate exactly (selector 0, type 0)" do
    record = tlsa(usage: 3, selector: 0, matching_type: 0, cert: @leaf)
    assert Dane.verify!([ record ], @leaf, @chain, hostname: "mx.example.com")
  end

  test "DANE-EE ignores hostname and expiry - the DNS association is the identity" do
    expired = make_cert("wrong-name.example.net", key: @leaf_key, issuer: @ca, issuer_key: @ca_key,
                        dns_name: "wrong-name.example.net", not_after: Time.now - 60)
    record = tlsa(usage: 3, cert: expired)
    assert Dane.verify!([ record ], expired, [ expired, @ca ], hostname: "mx.example.com")
  end

  test "a wrong pin raises VerifyError" do
    other = make_cert("other", key: make_key)
    record = tlsa(usage: 3, cert: other)
    assert_raises(Dane::VerifyError) { Dane.verify!([ record ], @leaf, @chain, hostname: "mx.example.com") }
  end

  test "DANE-TA verifies the leaf up to a pinned anchor with name check" do
    record = tlsa(usage: 2, cert: @ca)
    assert Dane.verify!([ record ], @leaf, @chain, hostname: "mx.example.com")
  end

  test "DANE-TA rejects a hostname the leaf does not carry" do
    record = tlsa(usage: 2, cert: @ca)
    assert_raises(Dane::VerifyError) { Dane.verify!([ record ], @leaf, @chain, hostname: "other.example.com") }
  end

  test "DANE-TA rejects a leaf that does not chain to the pinned anchor" do
    stranger_key = make_key
    stranger_ca = make_cert("Stranger CA", key: stranger_key, ca: true)
    record = tlsa(usage: 2, cert: stranger_ca)
    assert_raises(Dane::VerifyError) do
      Dane.verify!([ record ], @leaf, [ @leaf, @ca, stranger_ca ], hostname: "mx.example.com")
    end
  end

  test "DANE-TA works with a pinned intermediate (partial chain)" do
    intermediate_key = make_key
    intermediate = make_cert("Intermediate", key: intermediate_key, issuer: @ca, issuer_key: @ca_key, ca: true)
    leaf = make_cert("mx.example.com", key: @leaf_key, issuer: intermediate, issuer_key: intermediate_key,
                     dns_name: "mx.example.com")
    record = tlsa(usage: 2, cert: intermediate)
    assert Dane.verify!([ record ], leaf, [ leaf, intermediate ], hostname: "mx.example.com")
  end

  test "PKIX usages and unknown selectors are unusable" do
    records = [
      tlsa(usage: 0, cert: @ca), tlsa(usage: 1, cert: @leaf),
      Tlsa.new(usage: 3, selector: 7, matching_type: 1, data: "x"),
      Tlsa.new(usage: 3, selector: 1, matching_type: 9, data: "x")
    ]
    assert_empty Dane.usable_records(records)
    assert_raises(Dane::VerifyError) { Dane.verify!(records, @leaf, @chain, hostname: "mx.example.com") }
  end

  test "SHA-512 matching type" do
    record = tlsa(usage: 3, matching_type: 2, cert: @leaf)
    assert Dane.verify!([ record ], @leaf, @chain, hostname: "mx.example.com")
  end
end
