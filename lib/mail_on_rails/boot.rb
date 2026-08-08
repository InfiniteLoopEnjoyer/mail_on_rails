# frozen_string_literal: true

module MailOnRails
  # Glue between the app and the in-process mail servers (vendored under
  # lib/mail_on_rails/imap and lib/mail_on_rails/smtp). Builds each
  # protocol's ActiveRecord-backed store and starts the server on a
  # background thread via its Daemon module, keeping the handles for
  # readiness checks (/up, via HealthController) and graceful shutdown
  # (the Puma plugin's stop hooks).
  #
  # Only caller: the :mail_on_rails Puma plugin (development, or
  # MAIL_ON_RAILS_SERVERS=true - set on the production web role), which runs
  # both servers inside the web process.
  module Boot
    module_function

    # Starts one server per requested protocol and returns the handles. A
    # server that dies logs the error and its thread ends; the Puma
    # process carries on serving web requests.
    def start_servers(protocols: [ :imap, :smtp ])
      require_explicit_tls!(protocols) if Rails.env.production?
      @handles = {}

      if protocols.include?(:imap)
        require "mail_on_rails/imap/daemon"
        require "mail_on_rails/store/with_source"
        store = MailOnRails::Store::WithSource.new(MailOnRails::Store::ImapBackend.new, "imap")
        @handles[:imap] = MailOnRails::Imap::Daemon.start(store: store, logger: Rails.logger, tls_dir: tls_dir)
      end

      if protocols.include?(:smtp)
        require "mail_on_rails/smtp/daemon"
        require "mail_on_rails/store/smtp_backend"
        @handles[:smtp] = MailOnRails::Smtp::Daemon.start(store: MailOnRails::Store::SmtpBackend.new,
                                                          logger: Rails.logger, tls_dir: tls_dir,
                                                          hostname: method(:smtp_hostname))
      end

      @handles
    end

    # True once every started server has all its listeners bound. False
    # before start_servers and after stop_servers - a health check must
    # not pass while the mail ports are down.
    def ready?
      handles = (@handles || {}).values
      handles.any? && handles.all?(&:ready?)
    end

    # Blocks until every server is ready; raises on timeout so a listener
    # that failed to bind fails the boot (and with it the deploy's health
    # check) instead of leaving a web-only process that looks healthy.
    def wait_ready!(timeout = 15)
      (@handles || {}).each_value do |handle|
        next if handle.wait_ready(timeout)

        raise "mail server listeners failed to bind within #{timeout}s"
      end
    end

    # Graceful shutdown for Puma's stop/restart hooks; see Server#shutdown
    # for the drain semantics.
    def stop_servers(drain: 5)
      handles = (@handles || {}).values
      @handles = nil
      handles.each { |handle| handle.shutdown(drain: drain) }
    end

    # The running server for :imap or :smtp - the live-connection pages
    # read #connections (and MAX_CONNECTIONS) off it. nil when that server
    # isn't running in this process (a boot without the Puma plugin, e.g.
    # tests or a plain `rails server` with MAIL_ON_RAILS_SERVERS unset).
    def server(protocol)
      (@handles || {})[protocol]&.server
    end

    # Drops live connections whose peer IP the caller's test matches, on
    # every running server (see Server#kick). Used when an admin bans an
    # address: the denylists only silence future connections. Returns how
    # many connections were closed.
    def kick_connections(&matcher)
      (@handles || {}).values.sum { |handle| handle.server.kick(&matcher) }
    end

    # The servers read/generate their self-signed dev certs here.
    def tls_dir
      Rails.root.join("storage", "tls").to_s
    end

    # Production must never serve mail on the self-signed development
    # fallback: clients would either refuse the cert or train users to
    # click through warnings, and both failure modes look "up" from the
    # deploy's point of view. Each protocol reads its own env pair (the
    # TLS modules fail closed on their own once these are set), so a
    # missing pair here fails the boot - and with it the deploy's health
    # check - instead of quietly generating storage/tls/selfsigned.crt.
    def require_explicit_tls!(protocols)
      missing = []
      missing << "MAIL_ON_RAILS_TLS_CERT/MAIL_ON_RAILS_TLS_KEY" if protocols.include?(:imap) &&
        !(ENV["MAIL_ON_RAILS_TLS_CERT"] || ENV["MAIL_ON_RAILS_TLS_KEY"])
      missing << "SMTP_TLS_CERT/SMTP_TLS_KEY" if protocols.include?(:smtp) &&
        !(ENV["SMTP_TLS_CERT"] || ENV["SMTP_TLS_KEY"])
      return if missing.empty?

      raise "production requires explicit TLS material for the mail servers " \
            "(self-signed fallback is development-only): set #{missing.join(" and ")}"
    end

    # The name SMTP sessions announce, resolved per connection so a
    # Settings-page change applies without a restart. Falls back to the
    # env/system name if the database is unreachable - the banner must
    # still go out.
    def smtp_hostname
      Rails.application.executor.wrap { Setting.effective_smtp_helo_hostname }
    rescue StandardError
      ENV["SMTP_HELO_HOST"].presence || Socket.gethostname
    end
  end
end
