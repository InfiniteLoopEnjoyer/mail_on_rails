# frozen_string_literal: true

module MailOnRails
  # Runtime adapter check for the few query paths that keep a faster
  # PostgreSQL-specific form next to the portable one (full-text search).
  # Reads the resolved db_config through the gem's abstract Record class so
  # a host-app `connects_to` redirection is honored, without checking out a
  # connection.
  module AdapterSupport
    module_function

    def postgresql? = MailOnRails::Record.connection_db_config.adapter.to_s.match?(/postg/i)
  end
end
