require "openssl"

# Seals a message with an ARC set (RFC 8617) - the chain-of-custody a
# forwarder attaches so downstream receivers can trust the original
# authentication results even after forwarding breaks SPF (new envelope)
# or DKIM (rewritten body). One seal is three headers:
#
#   ARC-Authentication-Results (AAR) - our Authentication-Results
#     verbatim, instance-stamped;
#   ARC-Message-Signature (AMS)      - a DKIM-style signature over the
#     message as we forward it;
#   ARC-Seal (AS)                    - a signature over the ARC sets
#     themselves, with cv= vouching for the chain so far.
#
# Nothing forwards mail today, so nothing calls this yet: it is the
# groundwork for per-account filing rules with a forward action (see
# README roadmap). Scope: this seals as instance 1 (cv=none) only, and
# leaves messages that already carry ARC headers untouched - honestly
# extending an existing chain (cv=pass) needs a chain validator first.
#
# Signing follows RFC 6376 as ARC borrows it: rsa-sha256,
# relaxed/relaxed canonicalization, same key records DKIM uses
# (Domain#dkim_private_key / #dkim_selector).
class ArcSealer
  # Headers worth covering when present; each actual occurrence is
  # listed in h= and signed (bottom-up per RFC 6376 5.4.2).
  SIGNED_HEADERS = %w[From To Cc Subject Date Message-ID Reply-To In-Reply-To
                      References MIME-Version Content-Type Content-Transfer-Encoding].freeze

  def self.seal(raw, auth_results:, domain:, selector:, private_key:)
    new(domain: domain, selector: selector, private_key: private_key)
      .seal(raw, auth_results: auth_results)
  end

  def initialize(domain:, selector:, private_key:)
    @domain = domain
    @selector = selector
    @key = private_key.is_a?(OpenSSL::PKey::PKey) ? private_key : OpenSSL::PKey.read(private_key.to_s)
  end

  # Returns the sealed message, or the input unchanged when it can't be
  # sealed (no header/body separator, or an ARC chain already present).
  # +auth_results+ is our Authentication-Results content starting with
  # the authserv-id, as EmailMessage#auth_results stores it.
  def seal(raw, auth_results:)
    raw = raw.to_s.gsub(/(?<!\r)\n/, "\r\n")
    header_block, separator, body = raw.partition("\r\n\r\n")
    return raw if separator.empty?

    headers = header_block.split(/\r\n(?![ \t])/)
    return raw if headers.any? { |h| header_name(h).downcase.start_with?("arc-") }

    timestamp = Time.now.to_i
    aar = "ARC-Authentication-Results: i=1; #{auth_results.to_s.strip}"
    ams = message_signature(headers, body, timestamp)
    seal_header = arc_seal(aar, ams, timestamp)

    [ seal_header, ams, aar, *headers ].join("\r\n") + "\r\n\r\n" + body
  end

  private

  def message_signature(headers, body, timestamp)
    body_hash = [ OpenSSL::Digest::SHA256.digest(canonical_body(body)) ].pack("m0")
    names = signed_header_names(headers)
    base = "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; " \
           "d=#{@domain}; s=#{@selector}; t=#{timestamp};\r\n\tbh=#{body_hash};\r\n\t" \
           "h=#{names.join(":")};\r\n\tb="
    data = signed_data(headers, names) + canonicalize_header(base).chomp("\r\n")
    base + fold(sign(data))
  end

  # The seal covers the ARC set headers themselves - AAR, AMS, then the
  # seal being built with an empty b= and no trailing CRLF (RFC 8617
  # 5.1.2), never the body.
  def arc_seal(aar, ams, timestamp)
    base = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=#{@domain}; s=#{@selector}; t=#{timestamp}; b="
    data = canonicalize_header(aar) + canonicalize_header(ams) +
           canonicalize_header(base).chomp("\r\n")
    base + fold(sign(data))
  end

  def sign(data)
    [ @key.sign(OpenSSL::Digest::SHA256.new, data) ].pack("m0")
  end

  def fold(b64)
    b64.scan(/.{1,72}/).join("\r\n\t ")
  end

  # One h= entry per actual occurrence, so every copy is signed and a
  # later injection of a duplicate breaks the signature.
  def signed_header_names(headers)
    SIGNED_HEADERS.flat_map do |name|
      count = headers.count { |h| header_name(h).casecmp?(name) }
      [ name ] * count
    end
  end

  def signed_data(headers, names)
    candidates = {}
    cursors = {}
    names.map do |name|
      key = name.downcase
      candidates[key] ||= headers.each_index.select { |i| header_name(headers[i]).casecmp?(name) }
      cursors[key] ||= candidates[key].size
      cursors[key] -= 1
      canonicalize_header(headers[candidates[key][cursors[key]]])
    end.join
  end

  # Relaxed canonicalization, mirroring the verifier
  # (MailOnRails::Smtp::SenderAuth::Dkim) which is verification-only.

  def canonical_body(body)
    lines = body.split("\r\n", -1).map { |l| l.gsub(/[ \t]+/, " ").sub(/ \z/, "") }
    lines.pop while lines.any? && lines.last.empty?
    lines.empty? ? "" : lines.join("\r\n") + "\r\n"
  end

  def canonicalize_header(line)
    name, value = line.split(":", 2)
    value = value.to_s.gsub(/\r\n(?=[ \t])/, "").gsub(/[ \t]+/, " ").strip
    "#{name.strip.downcase}:#{value}\r\n"
  end

  def header_name(line)
    line.split(":", 2).first.to_s.strip
  end
end
