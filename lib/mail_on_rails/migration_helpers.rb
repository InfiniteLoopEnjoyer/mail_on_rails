# frozen_string_literal: true

module MailOnRails
  # Adapter predicates for the gem's migrations, which branch DDL where
  # PostgreSQL, MySQL, and SQLite genuinely differ (generated tsvector
  # column, partial indexes, blob/text sizing, JSON defaults).
  module MigrationHelpers
    def postgres? = connection.adapter_name.match?(/postg/i)
    def mysql?    = connection.adapter_name.match?(/mysql|trilogy/i)
    def sqlite?   = connection.adapter_name.match?(/sqlite/i)
  end
end
