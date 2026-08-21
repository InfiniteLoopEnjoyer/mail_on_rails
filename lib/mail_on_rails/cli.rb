# frozen_string_literal: true

require "thor"

module MailOnRails
  # Standalone entry point (bin/mail_server boots the host Rails app, then
  # hands ARGV here). The servers themselves run exactly as under the Puma
  # plugin; only the process lifecycle differs.
  #
  # Protocol choice: `--protocols smtp` / `--protocols imap smtp`, else the
  # host's explicit `config.mail_on_rails.protocols`, else every installed
  # protocol - running the mail binary means "serve mail". (The Puma
  # plugin's MAIL_ON_RAILS_SERVERS default-off-in-production rule is about
  # the *web* process and does not apply here.)
  class Cli < Thor
    def self.exit_on_failure? = true

    default_command :start

    desc :start, "Start the mail servers and run until TERM/INT"
    option :protocols, type: :array, default: nil,
           banner: "imap smtp", desc: "Subset of protocols to serve"
    def start
      protocols = resolve_protocols(options[:protocols])

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
    rescue ArgumentError => e
      abort "mail_on_rails: #{e.message}"
    end

    desc :check, "Validate settings/listener/TLS configuration without binding"
    option :protocols, type: :array, default: nil,
           banner: "imap smtp", desc: "Subset of protocols to check"
    def check
      protocols = resolve_protocols(options[:protocols])
      protocols.each { |protocol| MailOnRails::Runtime.adapter(protocol).preflight! } if MailOnRails::Runtime.production?

      require "mail_on_rails/settings/check"
      settings_check = MailOnRails::Settings::Check.new
      ok = settings_check.report

      protocols.each do |protocol|
        ok &= MailOnRails::Runtime.adapter(protocol).check_config(logger: MailOnRails.logger)
      end
      abort "mail_on_rails configuration has errors" unless ok

      puts "mail_on_rails configuration OK (#{protocols.join(", ")})"
    rescue MailOnRails::Netserv::Config::Error, RuntimeError, ArgumentError => e
      abort "mail_on_rails configuration error: #{e.message}"
    end

    private

    def resolve_protocols(requested)
      protocols = if requested && !requested.empty?
        MailOnRails::Runtime.normalize_protocols(requested)
      elsif !MailOnRails.protocols.nil?
        MailOnRails::Runtime.normalize_protocols(MailOnRails.protocols)
      else
        MailOnRails::Runtime.registered_protocols
      end
      return protocols unless protocols.empty?

      raise ArgumentError, "no mail protocols to serve: add the mail_on_rails_smtp and/or " \
                           "mail_on_rails_imap gem to the Gemfile, or pass --protocols"
    end
  end
end
