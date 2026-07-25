require "test_helper"
require "dkim"

# Cross-checks our DKIM signer (the `dkim` gem, as OutboundDeliverer uses
# it: rsa-sha256, relaxed/relaxed) against Postal's hand-rolled RFC 6376
# implementation, using Postal's self-contained signing vectors
# (test/fixtures/dkim_signing/*.msg, copied from postalserver/postal,
# MIT: spec/examples/dkim_signing/). Each vector's YAML frontmatter holds
# the domain, timestamp, selector, private key, signed-header list, and
# the bh=/b= Postal produced for the raw message that follows.
#
# Canonicalization is where DKIM interop bugs hide, so that is what these
# tests pin, byte-exact:
#   - our body canonicalization must reproduce Postal's bh= digest;
#   - our header canonicalization must reproduce the exact octets Postal
#     signed - proven by verifying Postal's b= signature over OUR
#     canonicalized headers with the vector's public key;
#   - and our own emitted signature must verify the same way (round trip).
# email2.msg is the stress case: real-world quoted-printable HTML with
# hard tabs, MSO conditional comments, and long folded List-* headers.
class DkimSigningTest < ActiveSupport::TestCase
  Dir[Rails.root.join("test/fixtures/dkim_signing/*.msg")].sort.each do |path|
    frontmatter, email = File.read(path).split(/^---\n/, 2)
    vector = YAML.safe_load(frontmatter)
    name = File.basename(path, ".msg")

    test "#{name}: body canonicalization matches Postal's bh=" do
      assert_equal vector["bh"], tags(sign(vector, email))["bh"]
    end

    test "#{name}: signed-header selection and order match Postal's h=" do
      assert_equal vector["headers"], tags(sign(vector, email))["h"]
    end

    test "#{name}: Postal's b= verifies over OUR canonicalized headers" do
      signed_mail = signed_mail(vector, email)
      # Postal's DKIM-Signature header (b= empty) in relaxed-canonical
      # form - deterministic regardless of how Postal folded it.
      postal_sig = "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; " \
                   "d=#{vector["domain"]}; s=#{vector["dkim_identifier"]}; t=#{vector["time"]}; " \
                   "bh=#{vector["bh"]}; h=#{vector["headers"]}; b="
      payload = signed_mail.canonical_header + postal_sig

      key = OpenSSL::PKey::RSA.new(vector["private_key"])
      assert key.public_key.verify(OpenSSL::Digest.new("SHA256"), Base64.decode64(vector["b"]), payload),
             "our relaxed header canonicalization does not reproduce the octets Postal signed"
    end

    test "#{name}: our own signature verifies (round trip)" do
      signed_mail = signed_mail(vector, email)
      header = signed_mail.dkim_header
      signature = header["b"]
      # Reconstruct the exact octets the gem signed: its sig header with
      # an empty b=, relaxed-canonical, appended to the signed headers.
      header["b"] = ""
      payload = signed_mail.canonical_header + header.to_s("relaxed")

      key = OpenSSL::PKey::RSA.new(vector["private_key"])
      assert key.public_key.verify(OpenSSL::Digest.new("SHA256"), signature, payload),
             "our own emitted b= does not verify - header serialization drifted from what was signed"
    end
  end

  private

  def signed_mail(vector, email)
    Dkim::SignedMail.new(email,
                         domain: vector["domain"],
                         selector: vector["dkim_identifier"],
                         private_key: OpenSSL::PKey::RSA.new(vector["private_key"]),
                         time: Time.at(vector["time"].to_i),
                         signable_headers: vector["headers"].split(":"))
  end

  def sign(vector, email)
    signed_mail(vector, email).dkim_header.to_s
  end

  # Parse a (possibly folded) DKIM-Signature header into its tag values.
  def tags(header)
    header.gsub(/\r?\n[ \t]+/, "").sub(/\ADKIM-Signature:\s*/i, "")
          .split(";").map { |pair| pair.strip.split("=", 2) }
          .to_h { |k, v| [ k, v.to_s.gsub(/\s+/, "") ] }
  end
end
