require "openssl"

# DANE certificate verification for outbound SMTP (RFC 7672): after the
# TLS handshake with a destination MX, the presented chain must match one
# of the usable TLSA records published (DNSSEC-signed) for that host.
# The two SMTP-applicable usages differ in what "match" means:
#
#   DANE-EE(3): the leaf certificate itself is pinned. Name checks and
#     expiry do not apply (RFC 7671 section 5.1) - the DNS association
#     is the whole identity.
#   DANE-TA(2): a trust anchor in the presented chain is pinned; the leaf
#     must chain to it and name the MX host.
#
# PKIX-TA(0)/PKIX-EE(1) are unusable in SMTP (RFC 7672 section 3.1.3):
# an active attacker controls which CAs the client would consult.
module MailOnRails
  module Dane
    class VerifyError < StandardError; end

    DANE_TA = 2
    DANE_EE = 3

    module_function

    # The records this verifier can act on. When a secure TLSA RRset exists
    # but every record is unusable, RFC 7671 section 4.1 says to treat the
    # host as unreachable rather than fall back to unauthenticated TLS -
    # callers get that by checking `usable_records(...).empty?`.
    def usable_records(records)
      records.select do |r|
        (r.usage == DANE_TA || r.usage == DANE_EE) &&
          (r.selector == 0 || r.selector == 1) &&
          (0..2).cover?(r.matching_type)
      end
    end

    # +leaf+ is the peer certificate, +chain+ the full presented chain
    # (leaf included, as OpenSSL::SSL::SSLSocket#peer_cert_chain returns
    # it). Returns true or raises VerifyError.
    def verify!(records, leaf, chain, hostname:)
      ee, ta = usable_records(records).partition { |r| r.usage == DANE_EE }
      return true if ee.any? { |r| matches?(r, leaf) }
      return true if ta.any? && ta_verified?(ta, leaf, Array(chain), hostname)

      raise VerifyError, "certificate chain matches none of the #{records.size} TLSA record(s)"
    end

    def matches?(record, cert)
      expected = record.data.to_s.b
      return false if expected.empty?

      actual = association_data(cert, record.selector, record.matching_type)
      actual.bytesize == expected.bytesize && OpenSSL.secure_compare(actual, expected)
    rescue OpenSSL::OpenSSLError
      false
    end

    # RFC 6698: selector picks full certificate (0) or SubjectPublicKeyInfo
    # (1); matching type is exact (0), SHA-256 (1) or SHA-512 (2).
    def association_data(cert, selector, matching_type)
      content = selector == 1 ? cert.public_key.public_to_der : cert.to_der
      case matching_type
      when 1 then OpenSSL::Digest::SHA256.digest(content)
      when 2 then OpenSSL::Digest::SHA512.digest(content)
      else content
      end
    end

    # DANE-TA: some presented certificate is the pinned trust anchor, the
    # leaf verifies up to it (PARTIAL_CHAIN so a pinned intermediate
    # terminates the path), and - unlike DANE-EE - the certificate must
    # name the host and be in validity (RFC 7672 section 3.2.3).
    def ta_verified?(ta_records, leaf, chain, hostname)
      anchors = chain.select { |cert| ta_records.any? { |r| matches?(r, cert) } }
      return false if anchors.empty?

      store = OpenSSL::X509::Store.new
      store.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
      anchors.each { |anchor| store.add_cert(anchor) }
      return false unless store.verify(leaf, chain - [ leaf ])

      hostname.blank? || OpenSSL::SSL.verify_certificate_identity(leaf, hostname)
    rescue OpenSSL::OpenSSLError
      false
    end
  end
end
