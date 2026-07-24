# frozen_string_literal: true

module MailOnRails
  # Development-mode glue over the extracted IMAP daemon gem (the sibling
  # mail_on_rails_imap repo, a path dependency in the development/test
  # groups). Builds the gem's HTTP-backed store with this app's credentials
  # and logger, then starts the server on a background thread via the gem's
  # Daemon module - the same runtime its bin/server entrypoint runs in
  # production, minus the env-var secrets.
  #
  # Only caller: the :mail_on_rails Puma plugin (development, or
  # MAIL_ON_RAILS_SERVERS=true), which runs IMAP inside the web process. In
  # the Kamal deploy the IMAP daemon runs from its own repo and image
  # instead. The SMTP edge is the external mail_on_rails_exim service (an
  # Exim MTA that POSTs to this app's HTTP endpoints), never in-process, so
  # there is no :smtp branch here.
  module Boot
    module_function

    # Starts one thread per requested protocol server and returns the
    # threads. A server that dies logs the error and its thread ends; the
    # dev Puma process carries on serving web requests.
    def start_servers(protocols: [ :imap ])
      threads = []

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

    # The IMAP gem reads/generates its self-signed dev cert here.
    def tls_dir
      Rails.root.join("storage", "tls").to_s
    end
  end
end
