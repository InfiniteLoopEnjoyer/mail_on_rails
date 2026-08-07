require "test_helper"

# The ARC sealer's output, verified by an independent re-implementation
# of RFC 6376 relaxed canonicalization (kept deliberately separate from
# the sealer's own code so a shared bug can't vouch for itself).
class ArcSealerTest < ActiveSupport::TestCase
  RAW = "From: Sender <sender@origin.test>\r\n" \
        "To: someone@example.com\r\n" \
        "Subject: hello  world\r\n" \
        "Date: Thu, 07 Aug 2026 12:00:00 +0000\r\n" \
        "Message-ID: <m1@origin.test>\r\n" \
        "\r\n" \
        "line one\r\nline two   \r\n\r\n".freeze

  AUTH = "mail.example.com; spf=pass smtp.mailfrom=origin.test; dkim=pass header.d=origin.test; dmarc=pass".freeze

  setup do
    @key = OpenSSL::PKey::RSA.new(2048)
    @sealed = ArcSealer.seal(RAW, auth_results: AUTH, domain: "example.com",
                             selector: "rail", private_key: @key)
  end

  # -- independent canonicalization helpers --

  def split_headers(raw)
    raw.partition("\r\n\r\n").first.split(/\r\n(?![ \t])/)
  end

  def find_header(headers, name)
    headers.find { |h| h.split(":", 2).first.strip.casecmp?(name) }
  end

  def relaxed_header(line)
    name, value = line.split(":", 2)
    "#{name.strip.downcase}:#{value.to_s.gsub(/\r\n[ \t]/, " ").gsub(/[ \t]+/, " ").strip}\r\n"
  end

  def relaxed_body(body)
    canonical = body.split("\r\n", -1).map { |l| l.rstrip.gsub(/[ \t]+/, " ") }
    canonical.pop while canonical.any? && canonical.last.empty?
    canonical.empty? ? "" : canonical.join("\r\n") + "\r\n"
  end

  def tags(header)
    header.split(":", 2).last.split(";").to_h do |pair|
      k, v = pair.split("=", 2)
      [ k.strip, v.to_s.gsub(/\s/, "") ]
    end
  end

  test "adds a complete instance-1 ARC set above the original headers" do
    headers = split_headers(@sealed)
    assert_equal "ARC-Seal", headers[0].split(":").first
    assert_equal "ARC-Message-Signature", headers[1].split(":").first
    assert_equal "ARC-Authentication-Results", headers[2].split(":").first
    assert_equal split_headers(RAW), headers[3..], "original headers must be untouched"
    assert @sealed.end_with?("line one\r\nline two   \r\n\r\n"), "body must be untouched"

    seal = tags(headers[0])
    assert_equal [ "1", "none", "example.com", "rail", "rsa-sha256" ],
                 seal.values_at("i", "cv", "d", "s", "a")
    assert_includes headers[2], AUTH
  end

  test "the AMS body hash and signature verify independently" do
    headers = split_headers(@sealed)
    ams = find_header(headers, "ARC-Message-Signature")
    ams_tags = tags(ams)

    body = @sealed.partition("\r\n\r\n").last
    assert_equal [ OpenSSL::Digest::SHA256.digest(relaxed_body(body)) ].pack("m0"),
                 ams_tags["bh"], "body hash must cover the relaxed body"

    signed_names = ams_tags["h"].split(":")
    assert_includes signed_names.map(&:downcase), "from"

    originals = split_headers(RAW)
    data = +""
    remaining = Hash.new { |h, n| h[n] = originals.select { |line| line.split(":", 2).first.strip.casecmp?(n) } }
    signed_names.each do |name|
      data << relaxed_header(remaining[name.downcase].pop)
    end
    data << relaxed_header(ams.sub(/(\A|;)(\s*b[ \t]*=)[^;]*/m, '\1\2')).chomp("\r\n")

    signature = ams_tags["b"].unpack1("m0")
    assert @key.public_key.verify(OpenSSL::Digest::SHA256.new, signature, data),
           "AMS signature must verify over the canonicalized headers"
  end

  test "the seal signature verifies over the ARC set" do
    headers = split_headers(@sealed)
    seal = find_header(headers, "ARC-Seal")
    data = relaxed_header(find_header(headers, "ARC-Authentication-Results")) +
           relaxed_header(find_header(headers, "ARC-Message-Signature")) +
           relaxed_header(seal.sub(/(\A|;)(\s*b[ \t]*=)[^;]*/m, '\1\2')).chomp("\r\n")

    signature = tags(seal)["b"].unpack1("m0")
    assert @key.public_key.verify(OpenSSL::Digest::SHA256.new, signature, data),
           "ARC-Seal signature must verify over AAR + AMS + unsigned seal"
  end

  test "tampering after sealing breaks the AMS signature" do
    tampered = @sealed.sub("line one", "line 0ne")
    headers = split_headers(tampered)
    ams_tags = tags(find_header(headers, "ARC-Message-Signature"))
    body = tampered.partition("\r\n\r\n").last

    assert_not_equal [ OpenSSL::Digest::SHA256.digest(relaxed_body(body)) ].pack("m0"), ams_tags["bh"]
  end

  test "a message already carrying ARC headers is left untouched" do
    chained = "ARC-Seal: i=1; cv=none; d=other.test; s=s; b=xxx\r\n" + RAW
    assert_equal chained, ArcSealer.seal(chained, auth_results: AUTH, domain: "example.com",
                                         selector: "rail", private_key: @key)
  end

  test "a body-less blob is returned unchanged" do
    assert_equal "no separator here", ArcSealer.seal("no separator here", auth_results: AUTH,
                                                     domain: "example.com", selector: "rail",
                                                     private_key: @key)
  end

  test "every occurrence of a signed header is covered" do
    doubled = "To: second@example.com\r\n" + RAW
    sealed = ArcSealer.seal(doubled, auth_results: AUTH, domain: "example.com",
                            selector: "rail", private_key: @key)
    h = tags(find_header(split_headers(sealed), "ARC-Message-Signature"))["h"]
    assert_equal 2, h.split(":").count { |n| n.casecmp?("to") }
  end
end
