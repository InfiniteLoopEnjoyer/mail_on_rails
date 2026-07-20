# frozen_string_literal: true

module MailOnRails
  # Development-mode glue over the extracted daemon gems (the sibling
  # mail_on_rails_smtp / mail_on_rails_imap repos, path dependencies in the
  # development/test groups). Builds each gem's HTTP-backed store with this
  # app's credentials and logger, then starts the servers on background
  # threads via the gems' Daemon modules - the same runtime their
  # bin/server entrypoints run in production, minus the env-var secrets.
  #
  # Only caller: the :mail_on_rails Puma plugin (development, or
  # MAIL_ON_RAILS_SERVERS=true), which runs both protocols inside the web
  # process. In the Kamal deploy the daemons run from their own repos and
  # images instead.
  module Boot
    module_function

    # Starts one thread per requested protocol server and returns the
    # threads. A server that dies logs the error and its thread ends; the
    # dev Puma process carries on serving web requests.
    def start_servers(protocols: [ :smtp, :imap ])
      threads = []

      if protocols.include?(:smtp)
        require "mail_on_rails/smtp/daemon"
        store = MailOnRails::Smtp::Store::Http.new(
          api: MailOnRails::Smtp::InternalApi.new(password: internal_api_password),
          ingress: MailOnRails::Smtp::IngressClient.new(password: ingress_password, logger: Rails.logger),
          logger: Rails.logger
        )
        threads << MailOnRails::Smtp::Daemon.start(store: store, logger: Rails.logger, tls_dir: tls_dir)
      end

      if protocols.include?(:imap)
        require "mail_on_rails/imap/daemon"
        store = MailOnRails::Imap::Store::Http.new(
          api: MailOnRails::Imap::InternalApi.new(password: internal_api_password),
          logger: Rails.logger
        )
        threads << MailOnRails::Imap::Daemon.start(store: store, logger: Rails.logger, tls_dir: tls_dir)
      end

      threads
    end

    def internal_api_password
      Rails.application.credentials.dig(:mail_on_rails, :internal_api_password)
    end

    # Same resolution as ActionMailbox::BaseController#password.
    def ingress_password
      Rails.application.credentials.dig(:action_mailbox, :ingress_password) || ENV["RAILS_INBOUND_EMAIL_PASSWORD"]
    end

    # Both gems read/generate the same self-signed cert here in development
    # (same dir), so running all-in-one just reuses the cached file.
    def tls_dir
      Rails.root.join("storage", "tls").to_s
    end
  end
end
