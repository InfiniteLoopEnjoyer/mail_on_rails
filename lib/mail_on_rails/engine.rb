# frozen_string_literal: true

module MailOnRails
  class Engine < ::Rails::Engine
    isolate_namespace MailOnRails

    config.mail_on_rails = ActiveSupport::OrderedOptions.new

    # Any mattr on the MailOnRails module is settable as
    # `config.mail_on_rails.<name> = ...` with no further wiring.
    initializer "mail_on_rails.config" do
      config.mail_on_rails.each do |name, value|
        MailOnRails.public_send("#{name}=", value)
      end
    end

    initializer "mail_on_rails.defaults", before: :run_prepare_callbacks do |app|
      MailOnRails.app_executor ||= app.executor
      MailOnRails.logger = ::Rails.logger if MailOnRails.logger.instance_of?(ActiveSupport::Logger) &&
        config.mail_on_rails[:logger].nil?
      MailOnRails.tls_dir ||= ::Rails.root.join("storage", "tls").to_s

      # The settings schema's DB tier: dynamic-scope overrides read from
      # the settings table under the app executor. Fail-soft end to end -
      # the cache keeps its last good snapshot if the database (or the
      # table, pre-migration) is unavailable, so the servers keep running
      # on boot-time configuration.
      MailOnRails::Settings.store = lambda do
        MailOnRails.app_executor.wrap { MailOnRails::Setting.override_rows }
      end

      # The name SMTP sessions announce, resolved per connection so a
      # Settings-page change applies without a restart. Falls back to the
      # env/system name if the database is unreachable - the banner must
      # still go out.
      MailOnRails.smtp_hostname_resolver ||= lambda do
        MailOnRails.app_executor.wrap { MailOnRails::Setting.effective_smtp_helo_hostname }
      rescue StandardError
        MailOnRails::Settings.static(:smtp_helo_hostname) || Socket.gethostname
      end
    end

    # The gem's migrations run in place from the app's `db:migrate` - the
    # mail tables share the primary database (and schema_migrations) with
    # the host app, which holds foreign keys into them. No copy step.
    initializer "mail_on_rails.migrations" do |app|
      unless !MailOnRails.use_engine_migrations || app.root.to_s.match?(root.to_s)
        config.paths["db/migrate"].expanded.each do |expanded_path|
          app.config.paths["db/migrate"] << expanded_path
        end
      end
    end
  end
end
