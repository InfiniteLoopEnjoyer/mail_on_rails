# frozen_string_literal: true

require "thor"

module MailOnRails
  # Standalone entry point (bin/mail_server boots the host Rails app, then
  # hands ARGV here). The servers themselves run exactly as under the Puma
  # plugin; only the process lifecycle differs.
  class Cli < Thor
    def self.exit_on_failure? = true

    default_command :start

    desc :start, "Start the mail servers and run until TERM/INT"
    option :protocols, type: :array, default: nil,
           banner: "imap smtp", desc: "Subset of protocols to serve"
    def start
      protocols = (options[:protocols] || MailOnRails.protocols).map(&:to_sym)

      # Self-pipe: trap context may not take locks or touch the database,
      # so the handler only writes a byte and the main thread does the real
      # shutdown outside trap context.
      reader, writer = IO.pipe
      %w[TERM INT].each do |signal|
        trap(signal) { writer.write_nonblock(".", exception: false) }
      end

      MailOnRails.start_servers(protocols: protocols)
      MailOnRails.wait_ready!
      MailOnRails.logger.info("[mail_on_rails] serving #{protocols.join(", ")} (pid #{Process.pid})")

      reader.read(1)
      MailOnRails.logger.info("[mail_on_rails] draining (#{MailOnRails.shutdown_drain}s)")
      MailOnRails.stop_servers
    end

    desc :check, "Validate settings/listener/TLS configuration without binding"
    def check
      protocols = MailOnRails.protocols.map(&:to_sym)
      MailOnRails::Runtime.require_explicit_tls!(protocols) if defined?(Rails) && Rails.env.production?

      require "mail_on_rails/settings/check"
      settings_check = MailOnRails::Settings::Check.new
      ok = settings_check.report

      require "mail_on_rails/imap/daemon" if protocols.include?(:imap)
      require "mail_on_rails/smtp/daemon" if protocols.include?(:smtp)
      ok &= MailOnRails::Imap::Daemon.check_config if protocols.include?(:imap)
      ok &= MailOnRails::Smtp::Daemon.check_config if protocols.include?(:smtp)
      abort "mail_on_rails configuration has errors" unless ok

      puts "mail_on_rails configuration OK (#{protocols.join(", ")})"
    rescue MailOnRails::Netserv::Config::Error, RuntimeError => e
      abort "mail_on_rails configuration error: #{e.message}"
    end
  end
end
