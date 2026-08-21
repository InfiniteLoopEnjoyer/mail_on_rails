# frozen_string_literal: true

# A Rails-free Active Record harness for suites that exercise the gem's
# models and store backends: the core gem's own db suite and the protocol
# gems' store suites (mail_on_rails_smtp / mail_on_rails_imap test their
# AR backends against the store contracts with this). It boots Active
# Record - but no Rails application - against DATABASE_URL or a throwaway
# SQLite file, loads the gem's models, and runs every gem migration, so
# the protocol gems never carry a copy of the schema list.
#
#   require "mail_on_rails/testing/database"
#   MailOnRails::Testing::Database.setup!(sqlite_path: "tmp/db_suite.sqlite3")
#
#   class MyTest < MailOnRails::Testing::Database::TestCase   # cleans tables per test
#   end
require "fileutils"
require "minitest"
require "active_support"
require "active_support/core_ext"
require "active_record"
require "active_job"
require "global_id"
require "mail"
require "mail_on_rails"
require "mail_on_rails/store"

module MailOnRails
  module Testing
    module Database
      # FK-safe deletion/drop order: children before their parents
      # (unprefixed; the prefix is applied at use).
      TABLES_CHILD_FIRST = %w[
        email_messages expunged_messages mailboxes email_aliases
        vacation_replies dmarc_reports tls_rpt_reports email_accounts domains
        auth_attempts auth_throttles banned_ips closed_connections honeypot_events
        mta_sts_policies settings smtp_outbound_messages suppressed_recipients
        tls_rpt_events dmarc_aggregate_events bimi_indicators session_transcripts
        ip_enrichments open_connections accept_lockouts listeners connection_kicks
      ].freeze

      # Data backfills for existing installs (system accounts/aliases per
      # hosted domain); no-ops on a fresh schema and not part of the shape
      # the suites test, so they are not run here.
      DATA_MIGRATIONS = %w[
        create_postmaster_accounts create_fbl_accounts create_mailer_daemon_aliases
        create_mail_host_aliases
      ].freeze

      module_function

      # The gem's root (this file lives at lib/mail_on_rails/testing/).
      def gem_root
        File.expand_path("../../..", __dir__)
      end

      # Everything, in order: the Rails stand-ins the models expect, the
      # connection, the models, a fresh schema.
      def setup!(sqlite_path: nil, database_url: ENV["DATABASE_URL"])
        stub_rails!
        configure!
        connect!(database_url: database_url, sqlite_path: sqlite_path)
        load_models!
        reset_schema!
      end

      # The models log through Rails.logger inside a host app, and a few
      # derive keys from the application's secret_key_base (the SCRAM decoy
      # secret, the ingress seal) or sign through its message verifiers.
      # Defined only when no real Rails application is around.
      def stub_rails!
        return if defined?(::Rails) && ::Rails.respond_to?(:application) && ::Rails.application

        Object.const_set(:Rails, Module.new) unless defined?(::Rails)
        app = Object.new
        def app.secret_key_base = "mail_on_rails-testing-secret-key-base"
        def app.message_verifier(purpose)
          (@message_verifiers ||= {})[purpose.to_s] ||= ActiveSupport::MessageVerifier.new("mail_on_rails-testing-#{purpose}")
        end
        ::Rails.define_singleton_method(:logger) { MailOnRails.logger }
        ::Rails.define_singleton_method(:application) { app }
      end

      def configure!
        Time.zone ||= "UTC"
        MailOnRails.logger = ActiveSupport::Logger.new(File::NULL)
        MailOnRails.app_executor ||= ActiveSupport::Executor
        # Models enqueue jobs (Domain -> DnsCheckRefreshJob, HoneypotEvent ->
        # enrichment, ...); the test adapter records them without a queue
        # backend, and GlobalID lets records ride as job arguments.
        ActiveJob::Base.logger = ActiveSupport::Logger.new(File::NULL)
        ActiveJob::Base.queue_adapter = :test
        GlobalID.app ||= "mail_on_rails-testing"
        ActiveRecord::Base.include(GlobalID::Identification) unless ActiveRecord::Base < GlobalID::Identification
        # EmailAccount encrypts its SCRAM verifier columns; any fixed keys
        # do for a throwaway test database.
        ActiveRecord::Encryption.configure(
          primary_key: "mail_on_rails-testing-primary-key",
          deterministic_key: "mail_on_rails-testing-deterministic-key",
          key_derivation_salt: "mail_on_rails-testing-salt"
        )
      end

      # DATABASE_URL wins (the adapter matrix); without one, a file-backed
      # SQLite database (file-backed, not :memory:, so every pool
      # connection sees the same database and multi-threaded tests
      # exercise real locking).
      def connect!(database_url: ENV["DATABASE_URL"], sqlite_path: nil)
        if database_url.to_s.strip.empty?
          path = sqlite_path || File.join(Dir.pwd, "tmp", "mail_on_rails_test.sqlite3")
          FileUtils.mkdir_p(File.dirname(path))
          FileUtils.rm_f(path)
          ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: path, timeout: 5000, pool: 10)
        else
          ActiveRecord::Base.establish_connection(database_url)
        end
      end

      # The models and jobs normally arrive via the engine's autoload paths.
      def load_models!
        models_dir = File.join(gem_root, "app", "models")
        Dir["#{models_dir}/concerns/mail_on_rails/*.rb"].sort.each { |file| require file }
        require "#{models_dir}/mail_on_rails/record"
        Dir["#{models_dir}/mail_on_rails/*.rb"].sort.each { |file| require file }
        jobs_dir = File.join(gem_root, "app", "jobs", "mail_on_rails")
        require "#{jobs_dir}/base_job"
        Dir["#{jobs_dir}/*.rb"].sort.each { |file| require file }
      end

      # Every gem migration in timestamp order, as classes (the data
      # backfills excepted).
      def migrations
        Dir[File.join(gem_root, "db", "migrate", "*.rb")].sort.filter_map do |file|
          name = File.basename(file, ".rb").sub(/\A\d+_/, "")
          next if DATA_MIGRATIONS.include?(name)

          require file
          name.camelize.constantize
        end
      end

      def tables
        TABLES_CHILD_FIRST.map { |table| "#{MailOnRails.table_name_prefix}#{table}" }
      end

      # Drops the gem's tables and migrates from scratch.
      def reset_schema!
        connection = ActiveRecord::Base.connection
        ActiveRecord::Migration.verbose = false
        tables.each { |table| connection.drop_table(table, if_exists: true) }
        migrations.each { |migration| migration.migrate(:up) }
      end

      # Empties every gem table (children first).
      def clean!
        connection = ActiveRecord::Base.connection
        tables.each { |table| connection.delete("DELETE FROM #{connection.quote_table_name(table)}") }
      end

      def adapter
        ActiveRecord::Base.connection_db_config.adapter.to_s
      end

      def postgres? = adapter.match?(/postg/i)
      def mysql?    = adapter.match?(/mysql|trilogy/i)
      def sqlite?   = adapter.match?(/sqlite/i)

      # Minitest base that empties the tables before each test.
      class TestCase < Minitest::Test
        def setup
          MailOnRails::Testing::Database.clean!
        end
      end
    end
  end
end
