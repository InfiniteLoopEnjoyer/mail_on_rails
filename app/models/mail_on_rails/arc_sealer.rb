require "openssl"
require "mail_on_rails/smtp/sender_auth/arc"

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
# README roadmap). A message with no ARC headers is sealed as instance 1
# (cv=none). One that already carries a chain is extended as instance
# N+1 when the caller passes the chain verdict it got from the validator
# (MailOnRails::Smtp::SenderAuth::Arc) - cv=pass seals the whole chain,
# cv=fail seals only its own set (RFC 8617 5.1.2); with no verdict the
# message is returned untouched, since extending unvalidated chains
# would vouch for something never checked.
#
# Signing follows RFC 6376 as ARC borrows it: rsa-sha256,
# relaxed/relaxed canonicalization, same key records DKIM uses
# (Domain#dkim_private_key / #dkim_selector).
module MailOnRails
  class ArcSealer
    # Headers worth covering when present; each actual occurrence is
    # listed in h= and signed (bottom-up per RFC 6376 5.4.2).
    SIGNED_HEADERS = %w[From To Cc Subject Date Message-ID Reply-To In-Reply-To
                        References MIME-Version Content-Type Content-Transfer-Encoding].freeze

    # Chains longer than this are not extended - mirrors the validator's
    # cap (RFC 8617 allows 50; nothing legitimate approaches it).
    MAX_CHAIN = MailOnRails::Smtp::SenderAuth::Arc::MAX_INSTANCES

    def self.seal(raw, auth_results:, domain:, selector:, private_key:, chain: nil)
      new(domain: domain, selector: selector, private_key: private_key)
        .seal(raw, auth_results: auth_results, chain: chain)
    end

    def initialize(domain:, selector:, private_key:)
      @domain = domain
      @selector = selector
      @key = private_key.is_a?(OpenSSL::PKey::PKey) ? private_key : OpenSSL::PKey.read(private_key.to_s)
    end

    # Returns the sealed message, or the input unchanged when it can't be
    # sealed (no header/body separator; an existing chain with no +chain+
    # verdict, malformed, or over-long). +auth_results+ is our
    # Authentication-Results content starting with the authserv-id, as
    # EmailMessage#auth_results stores it; +chain+ is the validator's
    # verdict for a message that already carries ARC sets (:pass/:fail).
    def seal(raw, auth_results:, chain: nil)
      raw = raw.to_s.gsub(/(?<!\r)\n/, "\r\n")
      header_block, separator, body = raw.partition("\r\n\r\n")
      return raw if separator.empty?

      headers = header_block.split(/\r\n(?![ \t])/)
      sets = existing_sets(headers)
      if sets.nil? # malformed chain: do not vouch, do not touch
        return raw
      elsif sets.empty?
        instance = 1
        cv = "none"
        prior = []
      else
        return raw unless %i[pass fail].include?(chain)

        n = sets.keys.max
        return raw unless sets.keys.sort == (1..n).to_a && n < MAX_CHAIN

        instance = n + 1
        cv = chain.to_s
        # cv=pass seals the whole chain it validated; cv=fail seals only
        # its own set (RFC 8617 5.1.2).
        prior = chain == :pass ? (1..n).flat_map { |k| sets[k].values_at(:aar, :ams, :as).map { |i| headers[i] } } : []
      end

      timestamp = Time.now.to_i
      aar = "ARC-Authentication-Results: i=#{instance}; #{auth_results.to_s.strip}"
      ams = message_signature(headers, body, timestamp, instance)
      seal_header = arc_seal(aar, ams, timestamp, instance, cv, prior)

      [ seal_header, ams, aar, *headers ].join("\r\n") + "\r\n\r\n" + body
    end

    private

    def message_signature(headers, body, timestamp, instance)
      body_hash = [ OpenSSL::Digest::SHA256.digest(canonical_body(body)) ].pack("m0")
      names = signed_header_names(headers)
      base = "ARC-Message-Signature: i=#{instance}; a=rsa-sha256; c=relaxed/relaxed; " \
             "d=#{@domain}; s=#{@selector}; t=#{timestamp};\r\n\tbh=#{body_hash};\r\n\t" \
             "h=#{names.join(":")};\r\n\tb="
      data = signed_data(headers, names) + canonicalize_header(base).chomp("\r\n")
      base + fold(sign(data))
    end

    # The instances already on the message: {i => {aar:, ams:, as: index}},
    # {} when none, nil when malformed (duplicates, gaps, unparseable or
    # incomplete sets).
    def existing_sets(headers)
      sets = Hash.new { |h, k| h[k] = {} }
      headers.each_index do |index|
        role = { "arc-authentication-results" => :aar,
                 "arc-message-signature" => :ams,
                 "arc-seal" => :as }[header_name(headers[index]).downcase]
        next unless role

        value = headers[index].split(":", 2).last.to_s
        raw = if role == :aar
          value[/\A[\s]*i[ \t]*=[ \t]*(\d{1,3})[ \t]*;/m, 1]
        else
          value.split(";").filter_map { |pair| pair.split("=", 2).last&.strip if pair.split("=", 2).first&.strip&.casecmp?("i") }.first
        end
        instance = raw.to_s[/\A\d{1,3}\z/]&.to_i
        return nil unless instance&.positive?
        return nil if sets[instance][role]

        sets[instance][role] = index
      end
      return sets if sets.empty?

      sets.values.all? { |set| set[:aar] && set[:ams] && set[:as] } ? sets : nil
    end

    # The seal covers the ARC set headers themselves - any prior sets it
    # vouches for (increasing instance order), then this set's AAR, AMS,
    # and the seal being built with an empty b= and no trailing CRLF
    # (RFC 8617 5.1.1) - never the body.
    def arc_seal(aar, ams, timestamp, instance, cv, prior)
      base = "ARC-Seal: i=#{instance}; a=rsa-sha256; cv=#{cv}; d=#{@domain}; s=#{@selector}; t=#{timestamp}; b="
      data = prior.map { |header| canonicalize_header(header) }.join +
             canonicalize_header(aar) + canonicalize_header(ams) +
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
end
