# frozen_string_literal: true

require "logger"
require_relative "../imap_server"
require_relative "tls"

module MailOnRails
  module Imap
    # Env-driven runtime for the IMAP server: builds the listener specs and
    # TLS material, then runs the server on a thread inside the host process
    # (the Rails app's Puma, via the :mail_on_rails plugin). The caller
    # injects the store - in the app that's the ActiveRecord-backed
    # MailOnRails::Store::ImapBackend.
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

      # Starts the server on a named thread and returns a Handle. A server
      # that dies logs the error and its thread ends; the embedding web
      # process carries on serving web requests.
      def start(store:, logger: default_logger, host: nil, tls_dir: nil)
        host ||= ENV.fetch("MAIL_ON_RAILS_HOST", "0.0.0.0")
        specs = listeners(host)
        tls = tls_material(logger, tls_dir || ENV.fetch("MAIL_ON_RAILS_TLS_DIR", "storage/tls"))

        logger.info "[mail_on_rails] IMAP #{specs.map { |s| s[:port] }.join("/")} on #{host}"
        server = ImapServer.new(store, specs, tls)
        thread = Thread.new do
          Thread.current.name = "mail_on_rails_imap"
          server.run
        rescue StandardError => e
          logger.error "[mail_on_rails] mail_on_rails_imap died: #{e.class}: #{e.message}"
        end
        Handle.new(server: server, thread: thread)
      end

      def listeners(host)
        [
          { host: host, port: env_port("MAIL_ON_RAILS_IMAP_PORT", 1143), tls: :starttls },
          { host: host, port: env_port("MAIL_ON_RAILS_IMAPS_PORT", 1993), tls: :implicit }
        ]
      end

      # Hash of plain strings (PEMs or file paths); nil if unavailable.
      def tls_material(logger, dir)
        material = TLS.material(dir: dir, logger: logger)
        logger.warn "[mail_on_rails] TLS unavailable - plaintext only" if material.nil?
        material
      end

      def env_port(name, default)
        Integer(ENV.fetch(name, default))
      end

      def default_logger
        Logger.new($stdout, progname: "mail_on_rails_imap")
      end
    end
  end
end
