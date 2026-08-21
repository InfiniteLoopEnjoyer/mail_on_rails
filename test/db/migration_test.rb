# frozen_string_literal: true

require_relative "test_helper"

# The branched DDL itself is exercised by DbSuite.reset_schema! running
# the consolidated migration against the adapter under test; these tests
# pin what each branch must have produced.
class MigrationTest < DbSuite::TestCase
  def connection = ActiveRecord::Base.connection

  def index(table, name)
    connection.indexes(table).find { |candidate| candidate.name == name }
  end

  def column(table, name)
    connection.columns(table).find { |candidate| candidate.name == name }
  end

  test "creates every prefixed table" do
    assert_equal DbSuite::TABLES_CHILD_FIRST.sort,
                 connection.data_sources.grep(/\Amail_on_rails_/).sort
  end

  test "honeypot schema: canary flag on accounts and the events table" do
    honeypot = column("mail_on_rails_email_accounts", "honeypot")
    assert honeypot, "email_accounts.honeypot column must exist"
    assert_equal :boolean, honeypot.type

    %w[protocol trigger signature ip transcript enrichment occurred_at].each do |name|
      assert column("mail_on_rails_honeypot_events", name), "honeypot_events.#{name} must exist"
    end
    assert index("mail_on_rails_honeypot_events", "index_honeypot_events_on_ip_and_occurred_at")
  end

  test "rollup unique indexes exist under their canonical names on every adapter" do
    auth = index("mail_on_rails_auth_attempts", "index_auth_attempts_on_rollup_key")
    closed = index("mail_on_rails_closed_connections", "index_closed_connections_on_rollup_key")
    assert auth&.unique, "auth_attempts rollup key must be unique"
    assert closed&.unique, "closed_connections rollup key must be unique"
  end

  if DbSuite.postgres?
    test "postgres keeps the generated tsvector column with its GIN index" do
      vector = column("mail_on_rails_email_messages", "search_vector")
      assert vector, "search_vector column must exist on postgres"
      assert_equal :tsvector, vector.type
      gin = index("mail_on_rails_email_messages", "index_email_messages_on_search_vector")
      assert_equal "gin", gin&.using.to_s
    end

    test "postgres keeps the partial indexes" do
      assert_match(/rollup/, index("mail_on_rails_auth_attempts", "index_auth_attempts_on_rollup_key").where.to_s)
      assert_match(/unscanned/, index("mail_on_rails_email_messages", "index_email_messages_on_unscanned").where.to_s)
    end
  end

  if DbSuite.mysql?
    test "mysql has no search_vector column" do
      assert_nil column("mail_on_rails_email_messages", "search_vector")
    end

    test "mysql sizes blob and text columns beyond real message sizes" do
      assert_equal "longblob", column("mail_on_rails_email_messages", "raw").sql_type
      assert_equal "longblob", column("mail_on_rails_smtp_outbound_messages", "data").sql_type
      assert_equal "mediumtext", column("mail_on_rails_email_messages", "body_text").sql_type
      assert_equal "mediumtext", column("mail_on_rails_email_messages", "to_addresses").sql_type
      assert_equal "mediumtext", column("mail_on_rails_email_messages", "references_ids").sql_type
    end

    test "mysql replaces the partial rollup indexes with generated columns" do
      generated = column("mail_on_rails_auth_attempts", "rollup_occurred_at")
      assert generated&.virtual?, "rollup_occurred_at must be a generated column"
      assert column("mail_on_rails_closed_connections", "rollup_closed_at")&.virtual?
      assert_equal [ "ip", "source", "rollup_occurred_at" ],
                   index("mail_on_rails_auth_attempts", "index_auth_attempts_on_rollup_key").columns
    end

    test "mysql mailbox names collate case-sensitively" do
      assert_equal "utf8mb4_bin", column("mail_on_rails_mailboxes", "name").collation
    end
  end

  if DbSuite.sqlite?
    test "sqlite has no search_vector column" do
      assert_nil column("mail_on_rails_email_messages", "search_vector")
    end

    test "sqlite keeps the partial rollup indexes" do
      assert_match(/rollup/, index("mail_on_rails_auth_attempts", "index_auth_attempts_on_rollup_key").where.to_s)
      assert_match(/unscanned/, index("mail_on_rails_email_messages", "index_email_messages_on_unscanned").where.to_s)
    end
  end
end
