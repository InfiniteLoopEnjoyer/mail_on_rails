# frozen_string_literal: true

require "openssl"

module MailOnRails
  module Dnssec
    # One RRSIG over one RRset under one DNSKEY, at a given instant
    # (RFC 4034 section 3.1.8.1, RFC 4035 section 5.3).
    #
    # dnsruby supplies the records, their canonical RDATA encoding and
    # the parsed public key; the check itself lives here. Its own
    # verifier is not used: SingleVerifier#verify_rrset reads the wall
    # clock, runs inside a thread-local work budget with a wall-clock
    # deadline, and records what it verified in a per-verifier trust
    # store - none of which a resolver that brings its own clock, budget
    # and chain walk can use, and all of which changed shape between
    # dnsruby 1.74 and 2.0. A pure function of (records, key, time) has
    # nothing to drift.
    #
    # verify answers true or false and never raises: a malformed key or
    # signature is simply a signature that does not verify.
    module Signature
      # Algorithm number => digest. RSASHA1 (5, 7) still verifies: RFC
      # 9905 retires it for signing, and zones that have not moved yet
      # stay inside DNSSEC here rather than dropping to insecure. DSA
      # (3, 6) is gone - RFC 8624 forbids validating it - so a zone
      # signed only with DSA is insecure, like any unknown algorithm.
      RSA_DIGESTS = { 5 => "SHA1", 7 => "SHA1", 8 => "SHA256", 10 => "SHA512" }.freeze
      # Algorithm number => [digest, octets per signature integer]
      # (RFC 6605 section 4: the signature is r | s, fixed width).
      ECDSA = { 13 => [ "SHA256", 32 ], 14 => [ "SHA384", 48 ] }.freeze
      # Algorithm number => signature octets (RFC 8080 section 4).
      EDDSA_SIGNATURE_BYTES = { 15 => 64, 16 => 114 }.freeze

      ALGORITHMS = (RSA_DIGESTS.keys + ECDSA.keys + EDDSA_SIGNATURE_BYTES.keys).freeze

      SERIAL_BITS = 1 << 32
      SERIAL_HALF = 1 << 31

      module_function

      def supported_algorithm?(code)
        ALGORITHMS.include?(code)
      end

      # +rrset+ carries the records as they arrived (a wildcard-expanded
      # answer keeps its expanded owner; the source owner is rebuilt
      # from the RRSIG's Labels field). +now+ is the verification time.
      def verify(rrset, sig, key, now:)
        return false unless applicable?(rrset, sig, key)
        return false unless valid_at?(sig, now)

        cryptographically_valid?(sig, key, sig.sig_data + canonical_rrset(rrset, sig))
      rescue OpenSSL::OpenSSLError, Dnsruby::EncodeError
        false
      end

      # The RRSIG's validity window holds at +now+. Inception and
      # expiration are 32-bit serial numbers (RFC 4034 section 3.1.5),
      # so each is read as the instant nearest +now+ - a window that
      # straddles the 2106 wrap still compares correctly.
      def valid_at?(sig, now)
        now = now.to_i
        starts = serial_near(sig.inception, now)
        ends = serial_near(sig.expiration, now)
        !starts.nil? && !ends.nil? && starts <= now && now <= ends
      end

      # Seconds of validity the RRSIG has left at +now+ (negative once
      # expired) - RFC 4035 section 5.3.3 bounds how long anything it
      # authenticated may be kept.
      def expires_in(sig, now)
        now = now.to_i
        ends = serial_near(sig.expiration, now)
        ends ? ends - now : -1
      end

      # RFC 4035 section 5.3.1: the RRSIG must belong to this RRset, the
      # key must be the zone key the RRSIG names, and the RRset must sit
      # inside that key's zone.
      def applicable?(rrset, sig, key)
        owner = rrset.name
        signer = sig.signers_name
        return false if rrset.rrs.empty?
        return false unless sig.name.canonical == owner.canonical
        return false unless sig.klass == rrset.klass && sig.type_covered == rrset.type
        return false unless key.name.canonical == signer.canonical && key.klass == sig.klass
        return false unless key.algorithm == sig.algorithm && key.key_tag == sig.key_tag
        return false unless key.zone_key? && !key.revoked? && key.protocol == 3
        return false unless at_or_below?(owner, signer)

        # Labels counts the source owner without any "*": more than the
        # owner has is nonsense, fewer than the signer has would put the
        # wildcard outside the signing zone.
        sig.labels.between?(signer.labels.length, owner.labels.length)
      end

      # The signed data after RRSIG_RDATA: every RR in canonical form
      # and canonical order (RFC 4034 sections 6.2 and 6.3), under the
      # owner the signer signed and the RRSIG's Original TTL. Duplicate
      # RDATA is signed once.
      def canonical_rrset(rrset, sig)
        prefix = Dnsruby::MessageEncoder.new do |encoder|
          encoder.put_name(signed_owner(rrset.name, sig.labels), true)
          encoder.put_pack("nnN", rrset.type.code, rrset.klass.code, sig.original_ttl)
        end.to_s
        rdatas = rrset.rrs.map do |rr|
          Dnsruby::MessageEncoder.new { |encoder| rr.encode_rdata(encoder, true) }.to_s.b
        end
        rdatas.uniq.sort.map { |rdata| prefix + [ rdata.bytesize ].pack("n") + rdata }.join
      end

      # RFC 4035 section 5.3.2: an answer expanded from a wildcard was
      # signed as "*.<the rightmost Labels labels>".
      def signed_owner(owner, labels)
        return owner unless labels < owner.labels.length

        Dnsruby::Name.new([ Dnsruby::Name::Label.new("*") ] + owner.labels.last(labels), true)
      end

      def cryptographically_valid?(sig, key, data)
        public_key = key.public_key
        return false unless public_key

        code = sig.algorithm.code
        signature = sig.signature.to_s.b
        if (digest = RSA_DIGESTS[code])
          public_key.verify(digest, signature, data) == true
        elsif (digest, width = ECDSA[code])
          return false unless signature.bytesize == 2 * width

          public_key.dsa_verify_asn1(OpenSSL::Digest.digest(digest, data), ecdsa_der(signature, width)) == true
        elsif (bytes = EDDSA_SIGNATURE_BYTES[code])
          # One-shot (RFC 8032): EdDSA takes the message, not a digest.
          signature.bytesize == bytes && public_key.verify(nil, signature, data) == true
        else
          false
        end
      end

      # OpenSSL wants the two integers as an ASN.1 sequence.
      def ecdsa_der(signature, width)
        integers = [ signature.byteslice(0, width), signature.byteslice(width, width) ].map do |octets|
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(octets, 2))
        end
        OpenSSL::ASN1::Sequence.new(integers).to_der
      end

      def at_or_below?(name, zone)
        labels = name.labels.map { |label| label.to_s.downcase }
        zone_labels = zone.labels.map { |label| label.to_s.downcase }
        labels.length >= zone_labels.length && labels.last(zone_labels.length) == zone_labels
      end

      # The absolute time nearest +reference+ that +value+ can mean, or
      # nil when it is exactly half the number space away (RFC 1982
      # leaves that comparison undefined).
      def serial_near(value, reference)
        distance = (value.to_i - reference) % SERIAL_BITS
        return nil if distance == SERIAL_HALF

        distance -= SERIAL_BITS if distance > SERIAL_HALF
        reference + distance
      end
    end
  end
end
