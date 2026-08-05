# frozen_string_literal: true

require "socket"
require "logger"
require_relative "config"
require_relative "../smtp_server"
require_relative "tls"

module MailOnRails
  module Smtp
    # Env-driven runtime for the SMTP server: builds the listener specs and
    # TLS material, then runs the server on a thread inside the host
    # process (the Rails app's Puma, via the :mail_on_rails plugin). The
    # caller injects the store - in the app that's the ActiveRecord-backed
    # MailOnRails::Store::SmtpBackend.
    module Daemon
      # What start returns: the running server plus its thread, with the
      # lifecycle calls the host process needs (readiness before reporting
      # healthy, graceful shutdown from the Puma hooks).
      Handle = Struct.new(:server, :thread, keyword_init: true) do
        def ready? = server.ready?
        def wait_ready(timeout = 15) = server.wait_ready(timeout)
        def shutdown(drain: 5) = server.shutdown(drain: drain)
      end

      module_function

      # Boot preflight: validates the same configuration start would use
      # and logs a one-line summary. Returns true when bootable; fatal
      # problems log an error and return false, suspicious-but-runnable
      # settings log warnings.
      def check_config(logger: default_logger)
        host = ENV.fetch("SMTP_HOST", "0.0.0.0")
        specs = listeners(host)
        tls = TLS.material(dir: ENV.fetch("SMTP_TLS_DIR", "storage/tls"), logger: logger)
        config_warnings(logger)
        tls_summary = tls ? (tls[:cert_path] ? "from #{tls[:cert_path]}" : "self-signed") : "UNAVAILABLE (plaintext only)"
        logger.info "[mail_on_rails] config OK: ports #{specs.map { |s| s[:port] }.join("/")} on #{host}, " \
                    "hostname #{specs.first[:hostname]}, TLS #{tls_summary}"
        true
      rescue TLS::Error, Config::Error => e
        logger.error "[mail_on_rails] config error: #{e.message}"
        false
      end

      # Settings that are legal but almost certainly not what the operator
      # meant - each has caused (or would cause) a quiet runtime failure.
      def config_warnings(logger)
        enforce = ENV["SMTP_DMARC_ENFORCE"]
        if enforce && enforce != "1" && enforce.match?(/\A(true|yes|on|enabled)\z/i)
          logger.warn "[mail_on_rails] SMTP_DMARC_ENFORCE=#{enforce} does NOT enable " \
                      "enforcement - only \"1\" does"
        end
        sender_auth = ENV["SMTP_SENDER_AUTH"]
        if sender_auth == "0"
          logger.warn "[mail_on_rails] SMTP_SENDER_AUTH=0 - inbound mail is accepted " \
                      "without SPF/DKIM/DMARC verification"
        elsif sender_auth && sender_auth.match?(/\A(false|no|off|disabled)\z/i)
          logger.warn "[mail_on_rails] SMTP_SENDER_AUTH=#{sender_auth} does NOT disable " \
                      "verification - only \"0\" does"
        end
      end

      # Starts the server on a named thread and returns a Handle. A server
      # that dies logs the error and its thread ends; the embedding web
      # process carries on serving web requests.
      def start(store:, logger: default_logger, host: nil, tls_dir: nil)
        host ||= ENV.fetch("SMTP_HOST", "0.0.0.0")
        specs = listeners(host)
        tls = tls_material(logger, tls_dir || ENV.fetch("SMTP_TLS_DIR", "storage/tls"))

        logger.info "[mail_on_rails] SMTP #{specs.map { |s| s[:port] }.join("/")} on #{host}"
        server = SmtpServer.new(store, specs, tls)
        thread = Thread.new do
          Thread.current.name = "mail_on_rails_smtp"
          server.run
        rescue StandardError => e
          logger.error "[mail_on_rails] mail_on_rails_smtp died: #{e.class}: #{e.message}"
        end
        Handle.new(server: server, thread: thread)
      end

      def listeners(host)
        # Announced in the SMTP banner/EHLO (RFC 5321 wants our FQDN; spam
        # filters compare it to the PTR).
        hostname = ENV.fetch("SMTP_HELO_HOST") { Socket.gethostname }
        specs = [
          { host: host, port: env_port("SMTP_PORT", 1025), tls: :starttls, role: :mx, hostname: hostname },
          { host: host, port: env_port("SMTP_SUBMISSION_PORT", 1587), tls: :starttls, role: :submission, hostname: hostname },
          { host: host, port: env_port("SMTPS_PORT", 1465), tls: :implicit, role: :submission, hostname: hostname }
        ]
        ports = specs.map { |s| s[:port] }
        unless ports.uniq.size == ports.size
          raise Config::Error, "listener ports must be distinct, got #{ports.join(", ")}"
        end

        specs
      end

      # Hash of plain strings (PEMs or file paths); nil if unavailable.
      def tls_material(logger, dir)
        material = TLS.material(dir: dir, logger: logger)
        logger.warn "[mail_on_rails] TLS unavailable - plaintext only" if material.nil?
        material
      end

      def env_port(name, default)
        Config.port(name, default)
      end

      def default_logger
        Logger.new($stdout, progname: "mail_on_rails_smtp")
      end
    end
  end
end
