# frozen_string_literal: true

require "mail_on_rails/version"

require "active_support"
require "active_support/core_ext/module/attribute_accessors"
require "active_record"
require "zeitwerk"

# The protocol tree (servers, netserv scaffolding, per-protocol daemons,
# memory stores, fuzz harness) is deliberately NOT Zeitwerk-managed: it is
# stdlib-only, loads with zero Rails in the process (`ruby -Ilib -r
# mail_on_rails/imap/daemon`), and the server threads hold references to
# these classes for the process lifetime, so they must never be reloaded.
# Everything else (Runtime, CLI, the AR models under app/) is autoloaded.
loader = Zeitwerk::Loader.for_gem(warn_on_extra_files: false)
loader.ignore("#{__dir__}/mail_on_rails/version.rb") # required above; defines VERSION, not Version
loader.ignore("#{__dir__}/mail_on_rails/engine.rb")  # required below, only under Rails
loader.ignore("#{__dir__}/generators")
loader.ignore("#{__dir__}/puma")
loader.ignore("#{__dir__}/mail_on_rails/testing") # test harness; requires minitest, never eager-loaded
%w[imap_server.rb smtp_server.rb imap.rb smtp.rb store.rb
   clamav_scanner.rb rspamd_analyzer.rb settings.rb dnssec.rb
   sender_auth.rb scram.rb send_quota.rb outbound_data.rb clamav_client.rb
   imap smtp netserv store fuzz settings dnssec sender_auth].each do |path|
  loader.ignore("#{__dir__}/mail_on_rails/#{path}")
end
loader.setup

# The settings schema is part of the non-reloadable tree (server threads
# read it per accept), but every Rails-side consumer needs it too - load it
# eagerly, it is stdlib-only and tiny.
require "mail_on_rails/settings"

module MailOnRails
  # Rails-glue seams, bridged from `config.mail_on_rails.*` by the engine.
  # Protocol behavior (ports, TLS material, limits, timeouts, feature
  # toggles) is configured through the MailOnRails::Settings schema, which
  # layers gem defaults, the legacy MAIL_ON_RAILS_* / SMTP_* environment
  # variables, `config.mail_on_rails.setting_overrides`, and (for
  # dynamic-safe settings) the mail_on_rails_settings table.
  mattr_accessor :logger, default: ActiveSupport::Logger.new($stdout)
  mattr_accessor :app_executor
  # Optional multi-database redirection for the gem's models; Record
  # applies it (`config.mail_on_rails.connects_to = { database: ... }`).
  mattr_accessor :connects_to
  # Which installed protocols the Puma plugin runs in this process. nil =
  # not chosen here: MAIL_ON_RAILS_SERVERS decides, else every installed
  # protocol in development and none elsewhere (Runtime.in_process_protocols).
  # An explicit [] means "UI only" even with protocol gems in the bundle.
  mattr_accessor :protocols, default: nil
  mattr_accessor :tls_dir # engine defaults this to Rails.root/storage/tls
  mattr_accessor :smtp_hostname_resolver # callable; engine wraps Setting
  mattr_accessor :shutdown_drain, default: 5

  # Callable(normalized_login) -> boolean. AuthAttempt shares one
  # brute-force analysis across IMAP/SMTP and the host's web login; the
  # host tells us which web logins actually exist.
  mattr_accessor :web_login_lookup

  # Callable(:smtp | :imap), invoked whenever a server's live-connection
  # picture changes: a session registers, a session ends, or an IP locks
  # out. Runs on the connection's own thread (never an accept thread), so
  # a host can push a dashboard update (e.g. a Turbo refresh broadcast)
  # the moment something happens instead of waiting for a poll - but it
  # MUST stay cheap or debounce internally: a connection flood calls it
  # at flood rate. Exceptions are swallowed and logged by the server.
  mattr_accessor :on_connection_activity

  # Table prefix for the gem's models. The host app can set this to "" for
  # a release to run the namespaced models against pre-extraction table
  # names, decoupling the code move from the table rename.
  mattr_writer :table_name_prefix, default: nil

  # Whether the engine appends its db/migrate to the host's migration
  # paths. An app migrating FROM pre-extraction tables turns this off
  # until its rename migration has recorded the gem's schema version -
  # otherwise db:prepare would create a second, empty set of prefixed
  # tables next to the live ones.
  mattr_accessor :use_engine_migrations, default: true

  class << self
    def table_name_prefix
      @@table_name_prefix || "mail_on_rails_"
    end

    # Initializer tier of the settings schema (see MailOnRails::Settings):
    #   config.mail_on_rails.setting_overrides = { smtp_max_conn: 200 }
    # Validated eagerly - a typo'd name or an untypeable value fails the
    # boot with the setting's name.
    def setting_overrides=(hash)
      Settings.overrides = hash
    end

    # Runtime facade - the servers' lifecycle from the Puma plugin, the CLI,
    # and the host app's health/metrics/admin surfaces. Runtime is resolved
    # at call time so requiring this file never forces the whole tree.
    def start_servers(...) = Runtime.start_servers(...)
    def stop_servers(...) = Runtime.stop_servers(...)
    def ready? = Runtime.ready?
    def wait_ready!(...) = Runtime.wait_ready!(...)
    def server(protocol) = Runtime.server(protocol)
    def kick_connections(&) = Runtime.kick_connections(&)
    def refresh_denylists = Runtime.refresh_denylists
  end

  ActiveSupport.run_load_hooks(:mail_on_rails, self)
end

# After the module body: isolate_namespace consults table_name_prefix, so
# the method above must exist before the engine loads.
require "mail_on_rails/engine" if defined?(Rails::Engine)

# Protocol entry points register themselves with Runtime (one-package
# phase: both ship in this gem; as separate gems each host requires only
# the ones it installs).
require "mail_on_rails/smtp"
require "mail_on_rails/imap"
