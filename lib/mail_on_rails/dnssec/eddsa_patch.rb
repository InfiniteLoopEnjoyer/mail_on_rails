# frozen_string_literal: true

# Ed25519/Ed448 (RFC 8080, algorithms 15/16) for dnsruby.
#
# Upstream's Algorithms mapper stops at ECDSA (14), and every record
# setter funnels unknown codes into DecodeError - so a response from an
# Ed25519-signed zone fails at Message.decode, before verification is
# even attempted. Registering the codes fixes decoding; the DNSKEY and
# SingleVerifier patches below make the signatures verify.
module Dnsruby
  Algorithms.add_pair("ED25519", 15)
  Algorithms.add_pair("ED448", 16)

  EDDSA_ALGORITHMS = [ Algorithms.ED25519, Algorithms.ED448 ].freeze

  class RR
    class DNSKEY
      # RFC 8080 section 3: the key data is the raw public key - 32
      # bytes for Ed25519, 57 for Ed448 - with none of the internal
      # structure the other algorithms carry.
      module EddsaPublicKey
        def public_key
          return @public_key if @public_key

          if EDDSA_ALGORITHMS.include?(@algorithm)
            kind = Algorithms.ED25519 == @algorithm ? "ED25519" : "ED448"
            return @public_key = OpenSSL::PKey.new_raw_public_key(kind, @key)
          end
          super
        end
      end
      prepend EddsaPublicKey
    end
  end

  class SingleVerifier
    # verify_rrset's algorithm dispatch is a closed if/elsif chain ending
    # in "Algorithm unsupported", so EdDSA has to take over the whole
    # verification when an EdDSA signature is in play. The steps mirror
    # upstream exactly - same checks, same canonical sig data - with the
    # one-shot EdDSA verify (RFC 8032: no prehashing) at the end.
    module EddsaVerifyRrset
      def verify_rrset(rrset, keys = nil)
        return super unless rrset.sigs.any? { |sig| EDDSA_ALGORITHMS.include?(sig.algorithm) }

        raise VerifyError.new("No RRSet to verify") if rrset.rrs.length == 0

        sigrecs = rrset.sigs
        sigrecs.each { |sigrec| check_rr_data(rrset, sigrec) }

        # Mirror upstream's DNSKEY bookkeeping: a DNSKEY RRset verified
        # against a DS RRset seeds the trusted key store.
        if rrset.type == Types.DNSKEY && keys && !(Array === keys) && keys.class != RRSet && keys.type == Types.DS
          rrset.rrs.each do |key|
            keys.rrs.each do |ds|
              @trusted_keys.add_key_with_expiration(key, sigrecs[0].expiration) if ds.check_key(key)
            end
          end
        end

        key_source = keys
        if keys.nil? || (keys.class != Array && keys.class != RRSet && keys.type == Types.DS)
          key_source = get_keys_to_check
        end
        keyrec, sigrec = get_matching_key(key_source, sigrecs)
        raise VerifyError.new("Signing key not found") unless keyrec
        # The matched pair may be a non-EdDSA signature in a mixed RRset.
        return super unless EDDSA_ALGORITHMS.include?(sigrec.algorithm)

        if keyrec.sep_key? && !keyrec.zone_key?
          raise VerifyError.new("DNSKEY with SEP flag set and Zone Key flag not set")
        end

        sorted = rrset.sort_canonical
        sig_data = sigrec.sig_data
        sorted.each do |rec|
          old_ttl = rec.ttl
          rec.ttl = sigrec.original_ttl
          data = MessageEncoder.new { |msg| msg.put_rr(rec, true) }.to_s
          rec.ttl = old_ttl
          sig_data += data.force_encoding(Encoding::BINARY)
        end

        verified = begin
          keyrec.public_key.verify(nil, sigrec.signature, sig_data)
        rescue OpenSSL::OpenSSLError
          false
        end
        raise VerifyError.new("Signature failed to cryptographically verify") unless verified

        true
      end
    end
    prepend EddsaVerifyRrset
  end
end
