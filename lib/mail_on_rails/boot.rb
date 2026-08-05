# frozen_string_literal: true

module MailOnRails
  # Glue between the app and the in-process mail servers (vendored under
  # lib/mail_on_rails/imap and lib/mail_on_rails/smtp). Builds each
  # protocol's ActiveRecord-backed store and starts the server on a
  # background thread via its Daemon module.
  #
  # Only caller: the :mail_on_rails Puma plugin (development, or
  # MAIL_ON_RAILS_SERVERS=true - set on the production web role), which runs
  # both servers inside the web process.
  module Boot
    module_function

    # Starts one thread per requested protocol server and returns the
    # threads. A server that dies logs the error and its thread ends; the
    # Puma process carries on serving web requests.
    def start_servers(protocols: [ :imap, :smtp ])
      threads = []

      if protocols.include?(:imap)
        require "mail_on_rails/imap/daemon"
        require "mail_on_rails/store/with_source"
        store = MailOnRails::Store::WithSource.new(MailOnRails::Store::ImapBackend.new, "imap")
        threads << MailOnRails::Imap::Daemon.start(store: store, logger: Rails.logger, tls_dir: tls_dir)
      end

      if protocols.include?(:smtp)
        require "mail_on_rails/smtp/daemon"
        require "mail_on_rails/store/smtp_backend"
        threads << MailOnRails::Smtp::Daemon.start(store: MailOnRails::Store::SmtpBackend.new,
                                                   logger: Rails.logger, tls_dir: tls_dir)
      end

      threads
    end

    # The servers read/generate their self-signed dev certs here.
    def tls_dir
      Rails.root.join("storage", "tls").to_s
    end
  end
end
