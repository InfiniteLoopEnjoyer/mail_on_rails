# frozen_string_literal: true

require "openssl"
require "socket"
require "fileutils"
require_relative "../settings"

module MailOnRails
  module Netserv
    # TLS material and server-side TLS for the mail listeners - one
    # implementation shared by SMTP and IMAP (they used to carry identical
    # copies; the only real difference is which settings name the cert).
    #
    # Two layers:
    #
    # * Protocol-free class methods: `context` (PEMs -> SSLContext),
    #   `accept` (wrap an accepted socket), `generate_self_signed`, and the
    #   `ContextProvider` a server holds for its lifetime.
    # * `Tls.for(:smtp)` / `Tls.for(:imap)`: a per-protocol instance that
    #   knows its settings (`smtp_tls_cert` / `imap_tls_cert`, ...) and
    #   resolves boot-time `material`.
    #
    # In production, point SMTP_TLS_CERT / SMTP_TLS_KEY (SMTP) and
    # MAIL_ON_RAILS_TLS_CERT / MAIL_ON_RAILS_TLS_KEY (IMAP) at real PEM
    # files (e.g. from Let's Encrypt). In development, a self-signed cert is
    # generated once and cached under storage/tls so it stays stable across
    # restarts (a changing cert would re-trigger the iOS "untrusted" prompt).
    #
    # `material` runs at boot and returns plain PEM strings or file paths.
    # Each server then builds its own OpenSSL::SSL::SSLContext from them (via
    # ContextProvider); a single context instance is safely shared by that
    # server's connection threads.
    class Tls
      # Configuration error in explicitly-provided TLS material. Fatal at
      # boot: a mail host that silently degrades to plaintext-only looks
      # healthy while refusing STARTTLS/SMTPS (and, since AUTH requires an
      # encrypted channel, all submission) or dropping the IMAPS listener
      # (and, since LOGINDISABLED holds until the channel is encrypted,
      # every login).
      class Error < StandardError; end

      # Settings names per protocol. `env` is the user-facing pair quoted in
      # error messages.
      PROTOCOLS = {
        smtp: { cert: :smtp_tls_cert, key: :smtp_tls_key, hosts: :smtp_tls_hosts,
                env: "SMTP_TLS_CERT/SMTP_TLS_KEY" },
        imap: { cert: :imap_tls_cert, key: :imap_tls_key, hosts: :imap_tls_hosts,
                env: "MAIL_ON_RAILS_TLS_CERT/MAIL_ON_RAILS_TLS_KEY" }
      }.freeze

      class << self
        # The per-protocol resolver (cached; stateless apart from its names).
        def for(protocol)
          (@instances ||= {})[protocol.to_sym] ||= new(protocol)
        end

        # Builds an SSLContext from PEM strings.
        def context(material)
          ctx = OpenSSL::SSL::SSLContext.new
          # The cert PEM may hold a whole chain (Let's Encrypt fullchain.pem =
          # leaf + intermediate); clients need the extras served too. PKey.read
          # autodetects the key type - LE issues EC keys, our self-signed is RSA.
          chain = OpenSSL::X509::Certificate.load(material[:cert])
          ctx.add_certificate(chain.first, OpenSSL::PKey.read(material[:key]), chain.drop(1))
          ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
          # TLS 1.2 AEAD-only (no CBC, silences LUCKY13); TLS 1.3 suites are
          # AEAD by construction and unaffected by this list.
          ctx.ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20"
          # We never verify client certs; clients verify us (or accept self-signed).
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          # No mid-session renegotiation (TLS 1.2; 1.3 dropped it): a mail
          # session has no use for it, and honoring client-initiated
          # renegotiation is a CPU-amplification lever.
          ctx.options |= OpenSSL::SSL::OP_NO_RENEGOTIATION
          ctx.session_id_context = "mail_on_rails"
          ctx
        end

        # Wraps an accepted plaintext socket in server-side TLS.
        def accept(raw_socket, ctx)
          ssl = OpenSSL::SSL::SSLSocket.new(raw_socket, ctx)
          ssl.sync_close = true
          ssl.accept
          ssl
        end

        # Fresh self-signed leaf cert + RSA key as PEM strings, for the
        # development path and the test suites.
        def generate_self_signed(hostnames = default_hostnames)
          key = OpenSSL::PKey::RSA.new(2048)
          cert = OpenSSL::X509::Certificate.new
          cert.version = 2
          cert.serial = 1
          cert.not_before = Time.now - 3600
          cert.not_after = Time.now + (10 * 365 * 24 * 3600)

          name = OpenSSL::X509::Name.parse("/CN=#{hostnames.first}")
          cert.subject = name
          cert.issuer = name
          cert.public_key = key.public_key

          ef = OpenSSL::X509::ExtensionFactory.new
          ef.subject_certificate = cert
          ef.issuer_certificate = cert
          san = hostnames.map { |h| "DNS:#{h}" }.join(",")
          cert.add_extension(ef.create_extension("subjectAltName", san, false))
          # A leaf cert, never a CA: a client that trusts this cert must not
          # inherit a signing authority from it.
          cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))
          cert.add_extension(ef.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
          cert.add_extension(ef.create_extension("extendedKeyUsage", "serverAuth", false))
          cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
          cert.sign(key, OpenSSL::Digest.new("SHA256"))

          { cert: cert.to_pem, key: key.to_pem }
        end

        def default_hostnames
          [ "localhost", Socket.gethostname ].reject(&:empty?).uniq
        end
      end

      attr_reader :protocol

      def initialize(protocol)
        @protocol = protocol.to_sym
        @names = PROTOCOLS.fetch(@protocol) { raise ArgumentError, "unknown TLS protocol #{protocol.inspect}" }
      end

      # Returns TLS material (a Hash of plain strings) or nil if TLS can't be
      # provisioned. When the protocol's cert/key settings are set, returns
      # { cert_path:, key_path: } so each server re-reads the files when the
      # cert is renewed (see ContextProvider) - and raises Error when they
      # are missing or unusable: explicitly configured TLS must never
      # degrade to plaintext. Without them, generates/loads a self-signed
      # cert under +dir+ and returns its PEMs inline as { cert:, key: }, or
      # nil if that fails (forgiving by design - it is the development
      # path). +dir+ and +logger+ are injected by the caller so this class
      # stays free of Rails.
      def material(dir: nil, logger: nil)
        cert_path = Settings.static(@names[:cert])
        key_path = Settings.static(@names[:key])
        return explicit_material(cert_path, key_path) if cert_path || key_path

        begin
          load_or_generate_self_signed(dir, logger)
        rescue StandardError => e
          logger&.error "[mail_on_rails] TLS material unavailable: #{e.class}: #{e.message}"
          nil
        end
      end

      # Explicit cert/key configuration: any problem is a fatal Error.
      def explicit_material(cert_path, key_path)
        unless cert_path && key_path
          raise Error, "#{@names[:env].sub('/', ' and ')} must be set together"
        end

        begin
          self.class.context(cert: File.read(cert_path), key: File.read(key_path)) # verify at boot, not first connection
        rescue StandardError => e
          raise Error, "TLS material #{cert_path} / #{key_path} unusable: #{e.class}: #{e.message}"
        end
        { cert_path: cert_path, key_path: key_path }
      end

      def load_or_generate_self_signed(dir, logger)
        raise ArgumentError, "#{@names[:env]} unset and no self-signed dir given" unless dir

        cert_file = File.join(dir, "selfsigned.crt")
        key_file = File.join(dir, "selfsigned.key")

        if File.exist?(cert_file) && File.exist?(key_file)
          return { cert: File.read(cert_file), key: File.read(key_file) }
        end

        pems = self.class.generate_self_signed(hostnames)
        FileUtils.mkdir_p(dir)
        File.write(key_file, pems[:key])
        File.chmod(0o600, key_file)
        File.write(cert_file, pems[:cert])
        logger&.info "[mail_on_rails] generated self-signed TLS cert at #{cert_file}"
        pems
      end

      # SANs for the self-signed cert: the configured hosts plus this machine.
      def hostnames
        hosts = Settings.static(@names[:hosts]).dup
        hosts << Socket.gethostname
        hosts.reject(&:empty?).uniq
      end

      # Thread-safe SSLContext source, one per server. For path-based material
      # (real certs), the files' mtimes are checked on each call and the
      # context is rebuilt after certbot renews them - no process restart
      # needed. PEM material (self-signed) is static.
      class ContextProvider
        def initialize(material)
          @cert_path = material[:cert_path]
          @key_path = material[:key_path]
          @mutex = Mutex.new
          @ctx = Tls.context(read_material(material))
          @mtimes = current_mtimes if @cert_path
        end

        def context
          return @ctx unless @cert_path

          @mutex.synchronize do
            mtimes = current_mtimes
            if mtimes != @mtimes
              @ctx = Tls.context(read_material(cert_path: @cert_path, key_path: @key_path))
              @mtimes = mtimes
            end
            @ctx
          end
        rescue StandardError
          @ctx # a failed reload (e.g. mid-renewal) keeps serving the old cert
        end

        private

        def read_material(material)
          if material[:cert_path]
            { cert: File.read(material[:cert_path]), key: File.read(material[:key_path]) }
          else
            material
          end
        end

        # File.stat follows symlinks, so a renewal that only repoints
        # live/*.pem into archive/ still changes these.
        def current_mtimes
          [ File.stat(@cert_path).mtime, File.stat(@key_path).mtime ]
        end
      end
    end
  end
end
