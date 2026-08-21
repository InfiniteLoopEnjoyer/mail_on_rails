# frozen_string_literal: true

# Harness for the DB-backed suite: the adapter-portability tests for the
# Active Record side of the gem (the consolidated migration, the models,
# the Store backends). Unlike the protocol suites this DOES boot Active
# Record - but still no Rails application - so it too runs in its own
# clean ruby process (rake test:db).
#
# The adapter under test comes from DATABASE_URL; without one the suite
# runs against a file-backed SQLite database under tmp/ (file-backed, not
# :memory:, so every pool connection sees the same database and the
# multi-threaded tests exercise real locking).
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

# An empty DATABASE_URL (a CI matrix leg without one) must read as
# "unset": Active Record refuses an empty URL the moment Base loads.
ENV.delete("DATABASE_URL") if ENV["DATABASE_URL"].to_s.strip.empty?

require "minitest/autorun"
require "fileutils"
require "active_support"
require "active_support/core_ext"
require "active_record"
require "mail"
require "mail_on_rails"
require "mail_on_rails/store"

# Minimal stand-in for the Rails-style `test "..."` declaration so suites
# read like Rails ones without pulling in ActiveSupport::TestCase.
module Minitest
  class Test
    def self.test(name, &block)
      define_method("test_#{name.gsub(/\W+/, '_')}", &block)
    end

    def assert_not(object, message = nil)
      refute object, message
    end
  end
end

# The models log through Rails.logger inside a host app; the harness
# routes that to the gem logger instead of loading Rails itself. (This is
# defined after `require "mail_on_rails"` on purpose - the gem loads its
# engine only when Rails::Engine already exists.) A minimal application
# stub carries secret_key_base for the code that derives keys from it
# (the SCRAM decoy secret, the ingress seal).
module Rails
  def self.logger = MailOnRails.logger

  APPLICATION = Object.new.tap do |app|
    def app.secret_key_base = "db-suite-test-secret-key-base"

    # UnsubscribeToken signs through the host app's keyring; a plain
    # verifier per purpose is behaviorally identical for the suite.
    def app.message_verifier(purpose)
      (@message_verifiers ||= {})[purpose.to_s] ||= ActiveSupport::MessageVerifier.new("db-suite-#{purpose}")
    end
  end

  def self.application = APPLICATION
end

Time.zone = "UTC"
MailOnRails.logger = ActiveSupport::Logger.new(File::NULL)
MailOnRails.app_executor = ActiveSupport::Executor

# EmailAccount encrypts its SCRAM verifier columns; any fixed keys do for
# a throwaway test database.
ActiveRecord::Encryption.configure(
  primary_key: "db-suite-test-primary-key",
  deterministic_key: "db-suite-test-deterministic-key",
  key_derivation_salt: "db-suite-test-salt"
)

if ENV["DATABASE_URL"].present?
  ActiveRecord::Base.establish_connection(ENV["DATABASE_URL"])
else
  path = File.expand_path("../../tmp/db_suite.sqlite3", __dir__)
  FileUtils.mkdir_p(File.dirname(path))
  FileUtils.rm_f(path)
  ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: path, timeout: 5000, pool: 10)
end

# The models normally arrive via the engine's autoload paths.
models_dir = File.expand_path("../../app/models", __dir__)
Dir["#{models_dir}/concerns/mail_on_rails/*.rb"].sort.each { |file| require file }
require "#{models_dir}/mail_on_rails/record"
Dir["#{models_dir}/mail_on_rails/*.rb"].sort.each { |file| require file }

# The consolidated extraction-time snapshot, then each incremental migration
# on top (in timestamp order) - the same sequence a host's db:migrate runs.
require File.expand_path("../../db/migrate/20260808000000_create_mail_on_rails_tables", __dir__)
require File.expand_path("../../db/migrate/20260812000000_add_honeypot_intelligence", __dir__)
require File.expand_path("../../db/migrate/20260813000000_add_tarpit_seconds_to_closed_connections", __dir__)
require File.expand_path("../../db/migrate/20260818100000_create_suppressed_recipients", __dir__)
require File.expand_path("../../db/migrate/20260818130000_add_outbound_dsn_and_requiretls", __dir__)
require File.expand_path("../../db/migrate/20260819000000_create_dmarc_aggregate_events", __dir__)
require File.expand_path("../../db/migrate/20260820000000_add_dkim_rotation_to_domains", __dir__)
require File.expand_path("../../db/migrate/20260820010000_add_unsubscribe_support", __dir__)
require File.expand_path("../../db/migrate/20260820020000_add_smtputf8_to_outbound", __dir__)
require File.expand_path("../../db/migrate/20260820030000_create_bimi", __dir__)
require File.expand_path("../../db/migrate/20260820040000_add_mailing_list_to_email_accounts", __dir__)
require File.expand_path("../../db/migrate/20260820050000_create_bounce_accounts", __dir__)
require File.expand_path("../../db/migrate/20260820060000_create_session_transcripts", __dir__)
require File.expand_path("../../db/migrate/20260820070000_create_ip_enrichments", __dir__)

module DbSuite
  # FK-safe deletion/drop order: children before their parents.
  TABLES_CHILD_FIRST = %w[
    email_messages expunged_messages mailboxes email_aliases
    vacation_replies dmarc_reports tls_rpt_reports email_accounts domains
    auth_attempts auth_throttles banned_ips closed_connections honeypot_events
    mta_sts_policies settings smtp_outbound_messages suppressed_recipients
    tls_rpt_events dmarc_aggregate_events bimi_indicators session_transcripts
    ip_enrichments
  ].map { |table| "mail_on_rails_#{table}" }.freeze

  ADAPTER = ActiveRecord::Base.connection_db_config.adapter.to_s

  def self.postgres? = ADAPTER.match?(/postg/i)
  def self.mysql?    = ADAPTER.match?(/mysql|trilogy/i)
  def self.sqlite?   = ADAPTER.match?(/sqlite/i)

  def self.reset_schema!
    connection = ActiveRecord::Base.connection
    ActiveRecord::Migration.verbose = false
    TABLES_CHILD_FIRST.each { |table| connection.drop_table(table, if_exists: true) }
    CreateMailOnRailsTables.migrate(:up)
    AddHoneypotIntelligence.migrate(:up)
    AddTarpitSecondsToClosedConnections.migrate(:up)
    CreateSuppressedRecipients.migrate(:up)
    AddOutboundDsnAndRequiretls.migrate(:up)
    CreateDmarcAggregateEvents.migrate(:up)
    AddDkimRotationToDomains.migrate(:up)
    AddUnsubscribeSupport.migrate(:up)
    AddSmtputf8ToOutbound.migrate(:up)
    CreateBimi.migrate(:up)
    AddMailingListToEmailAccounts.migrate(:up)
    CreateBounceAccounts.migrate(:up)
    CreateSessionTranscripts.migrate(:up)
    CreateIpEnrichments.migrate(:up)
  end

  class TestCase < Minitest::Test
    def setup
      connection = ActiveRecord::Base.connection
      DbSuite::TABLES_CHILD_FIRST.each do |table|
        connection.delete("DELETE FROM #{connection.quote_table_name(table)}")
      end
    end
  end
end

DbSuite.reset_schema!
