# frozen_string_literal: true

# The gem's full schema at extraction time (2026-08), one consolidated
# migration. Existing installs that renamed their pre-extraction tables
# (see the host app's rename migration) insert this version into
# schema_migrations instead of running it.
#
# Adapter-aware (PostgreSQL / MySQL 8.0.13+ / SQLite 3.35+). PostgreSQL
# additionally gets a stored generated tsvector search column on
# mail_on_rails_email_messages; MySQL swaps the partial rollup indexes for
# generated-column unique keys and sizes blob/text columns explicitly.
# The PostgreSQL branch must keep reproducing the pre-portability DDL
# exactly - existing installs recorded this version against that schema.
class CreateMailOnRailsTables < ActiveRecord::Migration[8.1]
  include MailOnRails::MigrationHelpers

  def change
    create_table "mail_on_rails_auth_attempts" do |t|
      t.boolean "account_exists", default: false, null: false
      t.integer "attempt_count", default: 1, null: false
      t.datetime "created_at", null: false
      t.string "ip"
      t.datetime "occurred_at", null: false
      t.string "outcome", null: false
      t.boolean "rollup", default: false, null: false
      t.string "source", null: false
      t.datetime "updated_at", null: false
      t.string "username"
      t.index [ "account_exists", "occurred_at" ], name: "index_auth_attempts_on_account_exists_and_occurred_at"
      t.index [ "ip", "occurred_at" ], name: "index_auth_attempts_on_ip_and_occurred_at"
      if mysql?
        # MySQL has no partial indexes; a stored generated column that is
        # NULL for non-rollup rows gives the same "unique among rollup rows
        # only" guarantee (NULL components never collide in a unique index).
        t.virtual "rollup_occurred_at", type: :datetime, precision: 6, as: "IF(rollup, occurred_at, NULL)", stored: true
        t.index [ "ip", "source", "rollup_occurred_at" ], name: "index_auth_attempts_on_rollup_key", unique: true
      else
        t.index [ "ip", "source", "occurred_at" ], name: "index_auth_attempts_on_rollup_key", unique: true, where: "rollup"
      end
      t.index [ "occurred_at" ], name: "index_auth_attempts_on_occurred_at"
      t.index [ "username" ], name: "index_auth_attempts_on_username"
    end

    create_table "mail_on_rails_auth_throttles" do |t|
      t.datetime "blocked_until"
      t.datetime "created_at", null: false
      t.integer "failure_count", default: 0, null: false
      t.string "key", null: false
      t.string "scope", null: false
      t.datetime "updated_at", null: false
      t.datetime "window_started_at", null: false
      t.index [ "scope", "key" ], name: "index_auth_throttles_on_scope_and_key", unique: true
      t.index [ "window_started_at" ], name: "index_auth_throttles_on_window_started_at"
    end

    create_table "mail_on_rails_banned_ips" do |t|
      t.string "cidr", null: false
      t.datetime "created_at", null: false
      t.string "note"
      t.string "source", default: "manual", null: false
      t.datetime "updated_at", null: false
      t.index [ "cidr" ], name: "index_banned_ips_on_cidr", unique: true
      t.index [ "source" ], name: "index_banned_ips_on_source"
    end

    create_table "mail_on_rails_closed_connections" do |t|
      t.datetime "closed_at", null: false
      t.datetime "connected_at"
      t.integer "connection_count", default: 1, null: false
      t.datetime "created_at", null: false
      t.float "duration_seconds"
      t.string "final_state"
      t.string "helo"
      t.string "ip"
      t.integer "messages"
      t.integer "port"
      t.string "protocol", null: false
      t.string "role"
      t.boolean "rollup", default: false, null: false
      t.boolean "tls", default: false, null: false
      t.datetime "updated_at", null: false
      t.string "username"
      t.index [ "closed_at" ], name: "index_closed_connections_on_closed_at"
      t.index [ "protocol", "closed_at" ], name: "index_closed_connections_on_protocol_and_closed_at"
      t.index [ "protocol", "ip", "closed_at" ], name: "index_closed_connections_on_protocol_and_ip_and_closed_at"
      if mysql?
        t.virtual "rollup_closed_at", type: :datetime, precision: 6, as: "IF(rollup, closed_at, NULL)", stored: true
        t.index [ "protocol", "ip", "rollup_closed_at" ], name: "index_closed_connections_on_rollup_key", unique: true
      else
        t.index [ "protocol", "ip", "closed_at" ], name: "index_closed_connections_on_rollup_key", unique: true, where: "rollup"
      end
    end

    create_table "mail_on_rails_dmarc_reports" do |t|
      t.datetime "begin_at", null: false
      t.integer "count", default: 1, null: false
      t.datetime "created_at", null: false
      t.string "disposition"
      t.string "dkim"
      t.bigint "domain_id", null: false
      t.datetime "end_at", null: false
      t.string "report_id", null: false
      t.string "reporter", null: false
      t.string "source_ip", null: false
      t.string "spf"
      t.datetime "updated_at", null: false
      t.index [ "domain_id", "begin_at" ], name: "index_dmarc_reports_on_domain_id_and_begin_at"
      t.index [ "domain_id", "reporter", "report_id" ], name: "index_dmarc_reports_on_domain_id_and_reporter_and_report_id"
      t.index [ "domain_id" ], name: "index_dmarc_reports_on_domain_id"
    end

    create_table "mail_on_rails_domains" do |t|
      t.datetime "created_at", null: false
      t.text "dkim_private_key"
      t.datetime "dns_checked_at"
      postgres? ? t.jsonb("dns_checks") : t.json("dns_checks")
      t.string "name", null: false
      t.datetime "updated_at", null: false
      t.index [ "name" ], name: "index_domains_on_name", unique: true
    end

    create_table "mail_on_rails_email_accounts" do |t|
      t.datetime "created_at", null: false
      t.string "email", null: false
      t.string "name"
      t.string "password_digest", null: false
      t.bigint "quota_bytes"
      t.integer "scram_iterations"
      t.string "scram_salt"
      t.string "scram_server_key"
      t.string "scram_stored_key"
      t.datetime "updated_at", null: false
      t.bigint "used_bytes", default: 0, null: false
      t.text "vacation_body"
      t.boolean "vacation_enabled", default: false, null: false
      t.date "vacation_ends_on"
      t.date "vacation_starts_on"
      t.string "vacation_subject"
      t.index [ "email" ], name: "index_email_accounts_on_email", unique: true
    end

    create_table "mail_on_rails_email_aliases" do |t|
      t.datetime "created_at", null: false
      t.string "email", null: false
      t.bigint "email_account_id", null: false
      t.datetime "updated_at", null: false
      t.index [ "email" ], name: "index_email_aliases_on_email", unique: true
      t.index [ "email_account_id" ], name: "index_email_aliases_on_email_account_id"
    end

    create_table "mail_on_rails_email_messages" do |t|
      t.string "auth_results"
      t.string "authenticated_as"
      t.text "body_text", **(mysql? ? { limit: 16_777_215 } : {})
      t.datetime "created_at", null: false
      t.string "email_object_id"
      # MySQL TEXT columns cannot take a literal default; every write path
      # (EmailMessage.deliver_raw) supplies flags explicitly.
      t.text "flags", null: false, **(mysql? ? {} : { default: "[]" })
      t.string "from_address"
      t.string "in_reply_to"
      t.datetime "internal_date", null: false
      if mysql?
        # MySQL requires FK columns to match the referenced bigint pk
        # exactly; postgres/sqlite keep the historical integer type.
        t.bigint "mailbox_id", null: false
      else
        t.integer "mailbox_id", null: false
      end
      t.string "message_id"
      t.bigint "modseq", default: 1, null: false
      # Full RFC822 messages: MySQL's default BLOB caps at 64 KiB, so it
      # needs an explicit longblob (and mediumtext for the text columns).
      t.binary "raw", null: false, **(mysql? ? { limit: 4_294_967_295 } : {})
      t.text "references_ids", **(mysql? ? { limit: 16_777_215 } : {})
      t.string "scan_status"
      if postgres?
        t.virtual "search_vector", type: :tsvector, as: "to_tsvector('simple'::regconfig, ((((((\"left\"((COALESCE(subject, ''::character varying))::text, 10000) || ' '::text) || \"left\"((COALESCE(from_address, ''::character varying))::text, 1000)) || ' '::text) || \"left\"(COALESCE(to_addresses, ''::text), 10000)) || ' '::text) || \"left\"(COALESCE(body_text, ''::text), 200000)))", stored: true
      end
      t.integer "size", default: 0, null: false
      t.string "spam_action"
      t.float "spam_score"
      t.float "spam_threshold"
      t.string "subject"
      t.string "thread_id"
      t.text "to_addresses", **(mysql? ? { limit: 16_777_215 } : {})
      t.integer "uid", null: false
      t.datetime "updated_at", null: false
      t.string "virus_name"
      t.index [ "mailbox_id", "internal_date" ], name: "index_email_messages_on_mailbox_id_and_internal_date"
      t.index [ "mailbox_id", "message_id" ], name: "index_email_messages_on_mailbox_id_and_message_id"
      t.index [ "mailbox_id", "thread_id" ], name: "index_email_messages_on_mailbox_id_and_thread_id"
      t.index [ "mailbox_id", "uid" ], name: "index_email_messages_on_mailbox_id_and_uid", unique: true
      t.index [ "mailbox_id" ], name: "index_email_messages_on_mailbox_id"
      t.index [ "message_id" ], name: "index_email_messages_on_message_id"
      if postgres?
        t.index [ "scan_status" ], name: "index_email_messages_on_unscanned", where: "((scan_status)::text = 'unscanned'::text)"
        t.index [ "search_vector" ], name: "index_email_messages_on_search_vector", using: :gin
      elsif sqlite?
        t.index [ "scan_status" ], name: "index_email_messages_on_unscanned", where: "scan_status = 'unscanned'"
      else
        # MySQL has no partial indexes; a full index on the small
        # scan_status column serves the same rescan-queue lookup.
        t.index [ "scan_status" ], name: "index_email_messages_on_unscanned"
      end
    end

    create_table "mail_on_rails_expunged_messages" do |t|
      t.bigint "mailbox_id", null: false
      t.bigint "modseq", null: false
      t.bigint "uid", null: false
      t.index [ "mailbox_id", "modseq" ], name: "index_expunged_messages_on_mailbox_id_and_modseq"
      t.index [ "mailbox_id" ], name: "index_expunged_messages_on_mailbox_id"
    end

    create_table "mail_on_rails_mailboxes" do |t|
      t.datetime "created_at", null: false
      if mysql?
        t.bigint "email_account_id", null: false
      else
        t.integer "email_account_id", null: false
      end
      t.bigint "highest_modseq", default: 1, null: false
      # IMAP mailbox names are case-sensitive (RFC 3501); MySQL's default
      # collation is case-insensitive, which would corrupt the hierarchy
      # matching in rename_mailbox and the per-account uniqueness below.
      t.string "name", null: false, **(mysql? ? { collation: "utf8mb4_bin" } : {})
      t.bigint "tombstone_floor", default: 0, null: false
      t.integer "uid_next", default: 1, null: false
      t.integer "uid_validity", null: false
      t.datetime "updated_at", null: false
      t.index [ "email_account_id", "name" ], name: "index_mailboxes_on_email_account_id_and_name", unique: true
      t.index [ "email_account_id" ], name: "index_mailboxes_on_email_account_id"
    end

    create_table "mail_on_rails_mta_sts_policies" do |t|
      t.datetime "created_at", null: false
      t.string "domain", null: false
      t.datetime "fetched_at", null: false
      t.integer "max_age", null: false
      t.string "mode", null: false
      t.text "mx_patterns", null: false
      t.string "sts_id", null: false
      t.datetime "updated_at", null: false
      t.index [ "domain" ], name: "index_mta_sts_policies_on_domain", unique: true
    end

    create_table "mail_on_rails_settings" do |t|
      t.datetime "created_at", null: false
      t.string "key", null: false
      t.datetime "updated_at", null: false
      t.string "value"
      t.index [ "key" ], name: "index_settings_on_key", unique: true
    end

    create_table "mail_on_rails_smtp_outbound_messages" do |t|
      t.integer "attempts", default: 0, null: false
      t.datetime "created_at", null: false
      t.binary "data", null: false, **(mysql? ? { limit: 4_294_967_295 } : {})
      t.text "last_error"
      t.string "mail_from", null: false
      t.datetime "next_attempt_at", null: false
      t.string "recipient", null: false
      t.datetime "sent_at"
      t.integer "status", default: 0, null: false
      t.datetime "updated_at", null: false
      t.index [ "status", "next_attempt_at" ], name: "index_smtp_outbound_messages_on_status_and_next_attempt_at"
    end

    create_table "mail_on_rails_tls_rpt_events" do |t|
      t.datetime "created_at", null: false
      t.string "failure_detail"
      t.datetime "occurred_at", null: false
      t.string "policy_domain", null: false
      t.string "policy_type", null: false
      t.string "receiving_mx"
      t.string "result_type"
      t.datetime "updated_at", null: false
      t.index [ "occurred_at" ], name: "index_tls_rpt_events_on_occurred_at"
      t.index [ "policy_domain", "occurred_at" ], name: "index_tls_rpt_events_on_policy_domain_and_occurred_at"
    end

    create_table "mail_on_rails_tls_rpt_reports" do |t|
      t.datetime "begin_at", null: false
      t.datetime "created_at", null: false
      t.bigint "domain_id", null: false
      t.datetime "end_at", null: false
      t.integer "failure_count", default: 0, null: false
      if postgres?
        t.jsonb "failure_details", default: [], null: false
      elsif sqlite?
        t.json "failure_details", default: [], null: false
      else
        # MySQL JSON columns cannot take a literal default; the model
        # supplies the [] default instead (see TlsRptReport).
        t.json "failure_details", null: false
      end
      t.string "policy_type", null: false
      t.string "report_id", null: false
      t.string "reporter", null: false
      t.integer "success_count", default: 0, null: false
      t.datetime "updated_at", null: false
      t.index [ "domain_id", "begin_at" ], name: "index_tls_rpt_reports_on_domain_id_and_begin_at"
      t.index [ "domain_id", "reporter", "report_id" ], name: "index_tls_rpt_reports_on_domain_id_and_reporter_and_report_id"
      t.index [ "domain_id" ], name: "index_tls_rpt_reports_on_domain_id"
      t.index [ "end_at" ], name: "index_tls_rpt_reports_on_end_at"
    end

    create_table "mail_on_rails_vacation_replies" do |t|
      t.datetime "created_at", null: false
      t.bigint "email_account_id", null: false
      t.datetime "last_sent_at", null: false
      t.string "sender", null: false
      t.datetime "updated_at", null: false
      t.index [ "email_account_id", "sender" ], name: "index_vacation_replies_on_email_account_id_and_sender", unique: true
      t.index [ "email_account_id" ], name: "index_vacation_replies_on_email_account_id"
    end

    # Explicit column: - the default derivation would prepend the table
    # prefix ("mail_on_rails_domain_id"), because the prefix lives on the
    # MailOnRails module, not on ActiveRecord::Base.
    add_foreign_key "mail_on_rails_dmarc_reports", "mail_on_rails_domains", column: "domain_id"
    add_foreign_key "mail_on_rails_email_aliases", "mail_on_rails_email_accounts", column: "email_account_id"
    add_foreign_key "mail_on_rails_email_messages", "mail_on_rails_mailboxes", column: "mailbox_id"
    add_foreign_key "mail_on_rails_expunged_messages", "mail_on_rails_mailboxes", column: "mailbox_id"
    add_foreign_key "mail_on_rails_mailboxes", "mail_on_rails_email_accounts", column: "email_account_id"
    add_foreign_key "mail_on_rails_tls_rpt_reports", "mail_on_rails_domains", column: "domain_id"
    add_foreign_key "mail_on_rails_vacation_replies", "mail_on_rails_email_accounts", column: "email_account_id"
  end
end
