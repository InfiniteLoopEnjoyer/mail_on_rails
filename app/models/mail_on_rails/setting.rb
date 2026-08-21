# The database tier of the settings schema (MailOnRails::Settings): one
# row per overridden key, read through typed accessors so callers never
# see the string storage. A missing row means "no override - fall through
# to the initializer/ENV/default tiers"; nothing seeds this table.
#
# Writes are validated strictly against the schema (unknown and boot-only
# keys are refused, values are typed and bounded), and every commit pushes
# a refresh into the running listeners so a change applies to the next
# connection; other processes pick it up within the cache TTL.
module MailOnRails
  class Setting < Record
    validates :key, presence: true, uniqueness: true

    after_commit { MailOnRails::Settings.refresh! }

    class << self
      # Everything the DB tier holds, as { key => raw value } - the
      # settings cache types each row and ignores unusable ones.
      def override_rows
        pluck(:key, :value).to_h
      end

      # The typed effective value, full precedence (DB, initializer, ENV,
      # default).
      def read(name)
        MailOnRails::Settings[name]
      end

      # Sets one dynamic setting's override row. Raises ArgumentError for
      # an unknown or boot-only key and ArgumentError/TypeError on an
      # untypeable or out-of-bounds value - the settings UI turns those
      # into flash alerts. Blank clears the override (back to
      # initializer/ENV/default), the longstanding behavior of the HELO
      # hostname form.
      def write(name, raw)
        definition = dynamic_definition!(name)
        return clear(name) if raw.nil? || raw.to_s.strip.empty?

        value = definition.coerce(raw)
        return clear(name) if value.nil?

        find_or_initialize_by(key: definition.name.to_s).update!(value: definition.serialize(value))
        value
      end

      # Removes a dynamic setting's override row (destroy, not delete, so
      # the after_commit refresh reaches the running listeners).
      def clear(name)
        where(key: dynamic_definition!(name).name.to_s).destroy_all
        nil
      end

      def dynamic_definition!(name)
        definition = MailOnRails::Settings.lookup(name.to_sym)
        raise ArgumentError, "unknown setting #{name}" unless definition
        unless definition.dynamic?
          raise ArgumentError, "#{name} is boot-only configuration - set it via ENV or the initializer"
        end

        definition
      end

      # -- longstanding named accessors, now thin schema delegators ------

      # How long a message sits in Trash before the daily PurgeTrashJob
      # deletes it permanently. Counted from when the message entered
      # Trash (the row's created_at - moving creates a fresh row), not
      # from when it was received.
      def trash_retention_days = read(:trash_retention_days)

      def trash_retention_days=(days)
        write(:trash_retention_days, days)
      end

      # The hostname this server announces on SMTP connections (220
      # banner, HELO/EHLO replies) and sends as its own HELO when
      # delivering outbound mail. Receiving servers compare it to our
      # public DNS, so it should be the machine's mail FQDN.

      # The DB row alone - what the settings form edits; nil means "no
      # override, fall through to the environment".
      def smtp_helo_hostname_override
        find_by(key: "smtp_helo_hostname")&.value
      end

      # The configured name (override or env/initializer), nil when
      # neither is set - the DNS publisher/checker want exactly this,
      # never a fallback guess.
      def smtp_helo_hostname
        smtp_helo_hostname_override || MailOnRails::Settings.static(:smtp_helo_hostname)
      end

      # What actually goes on the wire when nothing is configured.
      def effective_smtp_helo_hostname
        smtp_helo_hostname || Socket.gethostname
      end

      # Blank clears the override; anything else must parse as a hostname
      # (the schema's RFC 1123 validator) - raises ArgumentError on junk,
      # which SettingsController#update turns into a flash alert.
      def smtp_helo_hostname=(name)
        write(:smtp_helo_hostname, name)
      end
    end

    TRASH_RETENTION_DEFAULT_DAYS = MailOnRails::Settings.definition(:trash_retention_days).default
    HELO_HOSTNAME_PATTERN = MailOnRails::Settings::HELO_HOSTNAME_PATTERN
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_setting, MailOnRails::Setting
