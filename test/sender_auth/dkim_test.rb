require "test_helper"
require "mail_on_rails/sender_auth"
require "dkim"
require "fake_resolver"

class DkimTest < Minitest::Test
  RSA_KEY = OpenSSL::PKey::RSA.new(2048)

  MESSAGE = "From: alice@example.com\r\n" \
            "To: bob@example.org\r\n" \
            "Subject: Hello  world\r\n" \
            "Date: Fri, 10 Jul 2026 12:00:00 +0000\r\n" \
            "\r\n" \
            "A test body.\r\n" \
            "With two lines.\r\n"

  def sign(message = MESSAGE, **options)
    Dkim.sign(message, domain: "example.com", selector: "test", private_key: RSA_KEY, **options).to_s
  end

  def resolver(key = RSA_KEY, extra_tags = "")
    p = [ key.public_to_der ].pack("m0")
    FakeResolver.new(txt: { "test._domainkey.example.com" => [ "v=DKIM1; k=rsa;#{extra_tags} p=#{p}" ] })
  end

  def verify(message, res = resolver)
    MailOnRails::SenderAuth::Dkim.new(res).verify(message)
  end

  test "verifies a signature produced by the dkim gem (relaxed/relaxed)" do
    results = verify(sign)
    assert_equal 1, results.size
    assert_equal :pass, results.first[:result], results.first.inspect
    assert_equal "example.com", results.first[:domain]
  end

  test "verifies simple/simple canonicalization" do
    signed = sign(header_canonicalization: "simple", body_canonicalization: "simple")
    assert_equal :pass, verify(signed).first[:result]
  end

  test "tampered body fails with body hash mismatch" do
    tampered = sign.sub("A test body.", "An evil body.")
    result = verify(tampered).first
    assert_equal :fail, result[:result]
    assert_equal "body hash mismatch", result[:detail]
  end

  test "tampered signed header fails" do
    tampered = sign.sub("Subject: Hello  world", "Subject: Free money")
    assert_equal :fail, verify(tampered).first[:result]
  end

  test "unsigned trailing header addition still passes" do
    # Headers not listed in h= are fair game; adding one must not break
    # verification.
    assert_equal :pass, verify(sign.sub("From:", "X-Extra: hi\r\nFrom:")).first[:result]
  end

  test "l= body truncation is permerror, not a pass over the signed prefix" do
    # RFC 6376 l= hashes only a body prefix: an attacker signs a benign
    # prefix, appends an unsigned phishing part, and the signature (and
    # aligned DMARC) still pass. The tag is refused outright, so even a
    # message whose l= covers the whole body never verifies.
    truncated = sign.sub("v=1;", "v=1; l=4;")
    result = verify(truncated).first
    assert_equal :permerror, result[:result]
    assert_match(/l=/, result[:detail])

    with_appended_part = truncated + "<html>unsigned phishing part</html>\r\n"
    assert_equal :permerror, verify(with_appended_part).first[:result]
  end

  test "missing key record is permerror" do
    result = verify(sign, FakeResolver.new(txt: {})).first
    assert_equal :permerror, result[:result]
  end

  test "revoked key (empty p=) is permerror" do
    res = FakeResolver.new(txt: { "test._domainkey.example.com" => [ "v=DKIM1; k=rsa; p=" ] })
    assert_equal :permerror, verify(sign, res).first[:result]
  end

  test "wrong key fails verification" do
    result = verify(sign, resolver(OpenSSL::PKey::RSA.new(2048))).first
    assert_equal :fail, result[:result]
  end

  test "dns failure fetching the key is temperror" do
    res = FakeResolver.new(txt: { "test._domainkey.example.com" => :temperror })
    assert_equal :temperror, verify(sign, res).first[:result]
  end

  test "message without signatures returns no results" do
    assert_empty verify(MESSAGE)
  end

  test "an RSA key under 1024 bits is permerror, not a pass (RFC 8301)" do
    short = OpenSSL::PKey::RSA.new(512)
    signed = Dkim.sign(MESSAGE, domain: "example.com", selector: "test", private_key: short).to_s
    result = verify(signed, resolver(short)).first

    assert_equal :permerror, result[:result]
    assert_match(/too short.*512/, result[:detail])
  end

  test "a 1024-bit RSA key is still accepted" do
    key = OpenSSL::PKey::RSA.new(1024)
    signed = Dkim.sign(MESSAGE, domain: "example.com", selector: "test", private_key: key).to_s

    assert_equal :pass, verify(signed, resolver(key)).first[:result]
  end

  test "a non-RSA key under k=rsa is permerror rather than a crash" do
    ec = OpenSSL::PKey::EC.generate("prime256v1")
    res = FakeResolver.new(txt: { "test._domainkey.example.com" => [ "v=DKIM1; k=rsa; p=#{[ ec.public_to_der ].pack("m0")}" ] })

    assert_equal :permerror, verify(sign, res).first[:result]
  end

  test "bare-LF input verifies exactly like CRLF input" do
    crlf = sign
    lf = crlf.gsub("\r\n", "\n")
    refute_equal crlf, lf

    assert_equal verify(crlf), verify(lf)
    assert_equal :pass, verify(lf).first[:result]
    assert_equal :fail, verify(lf.sub("A test body.", "An evil body.")).first[:result]
  end

  test "verifies an ed25519-sha256 signature (RFC 8463)" do
    key = OpenSSL::PKey.generate_key("ED25519")
    body = "A test body.\r\n"
    bh = [ OpenSSL::Digest::SHA256.digest(body) ].pack("m0")

    sig_value = "v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=ed; h=from:to:subject; bh=#{bh}; b="
    data = "from:alice@example.com\r\n" \
           "to:bob@example.org\r\n" \
           "subject:Hello world\r\n" \
           "dkim-signature:#{sig_value}"
    signature = key.sign(nil, OpenSSL::Digest::SHA256.digest(data))

    message = "DKIM-Signature: #{sig_value}#{[ signature ].pack("m0")}\r\n" \
              "From: alice@example.com\r\n" \
              "To: bob@example.org\r\n" \
              "Subject: Hello  world\r\n" \
              "\r\n" + body

    res = FakeResolver.new(txt: {
      "ed._domainkey.example.com" => [ "v=DKIM1; k=ed25519; p=#{[ key.raw_public_key ].pack("m0")}" ]
    })
    result = MailOnRails::SenderAuth::Dkim.new(res).verify(message).first
    assert_equal :pass, result[:result], result.inspect
  end
end
