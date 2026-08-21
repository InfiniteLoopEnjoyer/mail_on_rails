# frozen_string_literal: true

require "openssl"

module MailOnRails
  module Imap
    # SCRAM-SHA-256 primitives (RFC 5802 / RFC 7677), shared by the
    # server-side AUTHENTICATE exchange and by stores that derive
    # credentials from a plaintext password at password-set time.
    #
    # SASLprep (RFC 4013) is deliberately not applied: account emails and
    # passwords here are ASCII in practice, and net-imap's client applies
    # it only to non-ASCII input, which would then simply fail to match.
    module Scram
      DIGEST = "SHA256"
      KEY_LENGTH = 32
      # Default derivation cost (the app's EmailAccount::SCRAM_ITERATIONS
      # mirrors this): well above RFC 7677's 4096 floor, which no longer
      # slows an offline attack on a leaked stored key meaningfully. The
      # expensive PBKDF2 runs client-side, once per authentication.
      ITERATIONS = 100_000

      module_function

      # => { salt:, iterations:, stored_key:, server_key: } (raw bytes)
      def derive(password, salt: OpenSSL::Random.random_bytes(16), iterations: ITERATIONS)
        salted = OpenSSL::KDF.pbkdf2_hmac(password.to_s, salt: salt, iterations: iterations,
                                          length: KEY_LENGTH, hash: DIGEST)
        client_key = hmac(salted, "Client Key")
        {
          salt: salt,
          iterations: iterations,
          stored_key: h(client_key),
          server_key: hmac(salted, "Server Key")
        }
      end

      # Verifies a client proof against the AuthMessage (RFC 5802 §3).
      # ClientKey = proof XOR HMAC(StoredKey, AuthMessage); valid iff
      # H(ClientKey) equals StoredKey.
      def valid_proof?(stored_key, auth_message, proof)
        return false unless proof.bytesize == stored_key.bytesize

        client_key = xor(proof, hmac(stored_key, auth_message))
        OpenSSL.fixed_length_secure_compare(h(client_key), stored_key)
      end

      def server_signature(server_key, auth_message)
        hmac(server_key, auth_message)
      end

      # Deterministic decoy verifier material for an unknown (or not-yet-
      # SCRAM-derived) account, in the same base64 shape a store returns
      # for a real one. Handing this back instead of an early failure
      # makes the AUTHENTICATE exchange byte-for-byte identical for
      # existing and non-existing accounts - same server-first challenge,
      # same salt/iteration disclosure - so it can't be used as a
      # username oracle. Keyed on a per-install secret, so the salt is
      # stable per (secret, email) but reveals nothing; the proof against
      # these random keys never verifies.
      #
      # Caveat: the decoy advertises the current ITERATIONS, while a real
      # account serves the cost stored when its credential was derived -
      # an account derived under an older, lower constant is
      # distinguishable from the decoy until a password change re-derives
      # it. Bumping ITERATIONS therefore reopens a narrow existence oracle
      # for stale accounts; null their scram columns to close it early.
      def decoy_credentials(email, secret)
        {
          account_id: nil,
          email: email,
          salt_base64: [ hmac(secret, "decoy-salt:#{email}")[0, 16] ].pack("m0"),
          iterations: ITERATIONS,
          stored_key_base64: [ hmac(secret, "decoy-stored:#{email}") ].pack("m0"),
          server_key_base64: [ hmac(secret, "decoy-server:#{email}") ].pack("m0"),
          honeypot: false
        }
      end

      # -- GS2 / channel binding (RFC 5802 §7, RFC 5929, RFC 9266) ---------

      # Splits a SCRAM client-first message into its GS2 header and bare
      # message. Returns [gs2_header, bare, cb_type, cb_declined] or nil
      # when the header doesn't parse: cb_type is the "p=" channel-binding
      # type (nil for "n"/"y"), cb_declined is true for the "y" flag - the
      # client supports channel binding but believes this server does not.
      def split_gs2(message)
        m = message.match(/\A((?:[ny]|p=([\x21-\x2b\x2d-\x7e]+)),(?:a=[^,]*)?,)(.*)\z/m)
        m && [ m[1], m[3], m[2], m[1].start_with?("y") ]
      end

      # Whether a session on +socket+ can prove a channel binding: only
      # over real TLS (wire tests drive sessions over plain sockets with
      # an implicit-TLS spec, and those must keep the no-binding
      # behavior). Gates both the -PLUS advertisement and the RFC 5802 §6
      # rule that a "y" gs2 flag must fail once the server advertises it.
      def channel_binding?(socket)
        socket.is_a?(OpenSSL::SSL::SSLSocket)
      end

      # Raw channel-binding bytes for a SASL cb type, nil when the type is
      # unsupported or unprovable on this connection. tls-exporter (RFC
      # 9266) is defined over the TLS 1.3 exporter with an *empty* context
      # - a different value than a NULL context on earlier versions, so
      # 1.3 is required outright. tls-server-end-point (RFC 5929 §4.1)
      # hashes the server certificate with its signature hash, floored at
      # SHA-256.
      def channel_binding_data(socket, type)
        return nil unless channel_binding?(socket)

        case type
        when "tls-exporter"
          return nil unless socket.ssl_version == "TLSv1.3"

          socket.export_keying_material("EXPORTER-Channel-Binding", 32, "")
        when "tls-server-end-point"
          cert = socket.cert
          cert && OpenSSL::Digest.digest(cert_binding_digest(cert), cert.to_der)
        end
      rescue StandardError
        nil
      end

      def cert_binding_digest(cert)
        case cert.signature_algorithm
        when /sha384/i then "SHA384"
        when /sha512/i then "SHA512"
        else "SHA256"
        end
      end

      def hmac(key, data)
        OpenSSL::HMAC.digest(DIGEST, key, data)
      end

      def h(data)
        OpenSSL::Digest.digest(DIGEST, data)
      end

      def xor(a, b)
        a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack("C*")
      end
    end
  end
end
