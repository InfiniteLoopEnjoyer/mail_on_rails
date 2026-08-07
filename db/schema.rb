# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_08_07_153000) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "action_mailbox_inbound_emails", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "message_checksum", null: false
    t.string "message_id", null: false
    t.integer "status", default: 0, null: false
    t.datetime "updated_at", null: false
    t.index ["message_id", "message_checksum"], name: "index_action_mailbox_inbound_emails_uniqueness", unique: true
  end

  create_table "active_storage_attachments", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.bigint "record_id", null: false
    t.string "record_type", null: false
    t.index ["blob_id"], name: "index_active_storage_attachments_on_blob_id"
    t.index ["record_type", "record_id", "name", "blob_id"], name: "index_active_storage_attachments_uniqueness", unique: true
  end

  create_table "active_storage_blobs", force: :cascade do |t|
    t.bigint "byte_size", null: false
    t.string "checksum"
    t.string "content_type"
    t.datetime "created_at", null: false
    t.string "filename", null: false
    t.string "key", null: false
    t.text "metadata"
    t.string "service_name", null: false
    t.index ["key"], name: "index_active_storage_blobs_on_key", unique: true
  end

  create_table "active_storage_variant_records", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.string "variation_digest", null: false
    t.index ["blob_id", "variation_digest"], name: "index_active_storage_variant_records_uniqueness", unique: true
  end

  create_table "audit_events", force: :cascade do |t|
    t.string "action", null: false
    t.datetime "created_at", null: false
    t.jsonb "details", default: {}, null: false
    t.string "ip"
    t.bigint "subject_id"
    t.string "subject_label"
    t.string "subject_type"
    t.string "user_email", null: false
    t.bigint "user_id"
    t.index ["created_at"], name: "index_audit_events_on_created_at"
    t.index ["subject_type", "subject_id"], name: "index_audit_events_on_subject_type_and_subject_id"
    t.index ["user_id"], name: "index_audit_events_on_user_id"
  end

  create_table "auth_attempts", force: :cascade do |t|
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
    t.index ["account_exists", "occurred_at"], name: "index_auth_attempts_on_account_exists_and_occurred_at"
    t.index ["ip", "occurred_at"], name: "index_auth_attempts_on_ip_and_occurred_at"
    t.index ["ip", "source", "occurred_at"], name: "index_auth_attempts_on_rollup_key", unique: true, where: "rollup"
    t.index ["occurred_at"], name: "index_auth_attempts_on_occurred_at"
    t.index ["username"], name: "index_auth_attempts_on_username"
  end

  create_table "auth_throttles", force: :cascade do |t|
    t.datetime "blocked_until"
    t.datetime "created_at", null: false
    t.integer "failure_count", default: 0, null: false
    t.string "key", null: false
    t.string "scope", null: false
    t.datetime "updated_at", null: false
    t.datetime "window_started_at", null: false
    t.index ["scope", "key"], name: "index_auth_throttles_on_scope_and_key", unique: true
    t.index ["window_started_at"], name: "index_auth_throttles_on_window_started_at"
  end

  create_table "banned_ips", force: :cascade do |t|
    t.string "cidr", null: false
    t.datetime "created_at", null: false
    t.string "note"
    t.string "source", default: "manual", null: false
    t.datetime "updated_at", null: false
    t.index ["cidr"], name: "index_banned_ips_on_cidr", unique: true
    t.index ["source"], name: "index_banned_ips_on_source"
  end

  create_table "closed_connections", force: :cascade do |t|
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
    t.index ["closed_at"], name: "index_closed_connections_on_closed_at"
    t.index ["protocol", "closed_at"], name: "index_closed_connections_on_protocol_and_closed_at"
    t.index ["protocol", "ip", "closed_at"], name: "index_closed_connections_on_protocol_and_ip_and_closed_at"
    t.index ["protocol", "ip", "closed_at"], name: "index_closed_connections_on_rollup_key", unique: true, where: "rollup"
  end

  create_table "dmarc_reports", force: :cascade do |t|
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
    t.index ["domain_id", "begin_at"], name: "index_dmarc_reports_on_domain_id_and_begin_at"
    t.index ["domain_id", "reporter", "report_id"], name: "index_dmarc_reports_on_domain_id_and_reporter_and_report_id"
    t.index ["domain_id"], name: "index_dmarc_reports_on_domain_id"
  end

  create_table "domains", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "dkim_private_key"
    t.datetime "dns_checked_at"
    t.jsonb "dns_checks"
    t.string "name", null: false
    t.datetime "updated_at", null: false
    t.index ["name"], name: "index_domains_on_name", unique: true
  end

  create_table "email_accounts", force: :cascade do |t|
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
    t.index ["email"], name: "index_email_accounts_on_email", unique: true
  end

  create_table "email_aliases", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "email", null: false
    t.bigint "email_account_id", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_email_aliases_on_email", unique: true
    t.index ["email_account_id"], name: "index_email_aliases_on_email_account_id"
  end

  create_table "email_messages", force: :cascade do |t|
    t.string "auth_results"
    t.string "authenticated_as"
    t.text "body_text"
    t.datetime "created_at", null: false
    t.string "email_object_id"
    t.text "flags", default: "[]", null: false
    t.string "from_address"
    t.string "in_reply_to"
    t.datetime "internal_date", null: false
    t.integer "mailbox_id", null: false
    t.string "message_id"
    t.bigint "modseq", default: 1, null: false
    t.binary "raw", null: false
    t.text "references_ids"
    t.string "scan_status"
    t.virtual "search_vector", type: :tsvector, as: "to_tsvector('simple'::regconfig, ((((((\"left\"((COALESCE(subject, ''::character varying))::text, 10000) || ' '::text) || \"left\"((COALESCE(from_address, ''::character varying))::text, 1000)) || ' '::text) || \"left\"(COALESCE(to_addresses, ''::text), 10000)) || ' '::text) || \"left\"(COALESCE(body_text, ''::text), 200000)))", stored: true
    t.integer "size", default: 0, null: false
    t.string "spam_action"
    t.float "spam_score"
    t.float "spam_threshold"
    t.string "subject"
    t.string "thread_id"
    t.text "to_addresses"
    t.integer "uid", null: false
    t.datetime "updated_at", null: false
    t.string "virus_name"
    t.index ["mailbox_id", "internal_date"], name: "index_email_messages_on_mailbox_id_and_internal_date"
    t.index ["mailbox_id", "message_id"], name: "index_email_messages_on_mailbox_id_and_message_id"
    t.index ["mailbox_id", "thread_id"], name: "index_email_messages_on_mailbox_id_and_thread_id"
    t.index ["mailbox_id", "uid"], name: "index_email_messages_on_mailbox_id_and_uid", unique: true
    t.index ["mailbox_id"], name: "index_email_messages_on_mailbox_id"
    t.index ["message_id"], name: "index_email_messages_on_message_id"
    t.index ["search_vector"], name: "index_email_messages_on_search_vector", using: :gin
  end

  create_table "expunged_messages", force: :cascade do |t|
    t.bigint "mailbox_id", null: false
    t.bigint "modseq", null: false
    t.bigint "uid", null: false
    t.index ["mailbox_id", "modseq"], name: "index_expunged_messages_on_mailbox_id_and_modseq"
    t.index ["mailbox_id"], name: "index_expunged_messages_on_mailbox_id"
  end

  create_table "mailboxes", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "email_account_id", null: false
    t.bigint "highest_modseq", default: 1, null: false
    t.string "name", null: false
    t.bigint "tombstone_floor", default: 0, null: false
    t.integer "uid_next", default: 1, null: false
    t.integer "uid_validity", null: false
    t.datetime "updated_at", null: false
    t.index ["email_account_id", "name"], name: "index_mailboxes_on_email_account_id_and_name", unique: true
    t.index ["email_account_id"], name: "index_mailboxes_on_email_account_id"
  end

  create_table "mta_sts_policies", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "domain", null: false
    t.datetime "fetched_at", null: false
    t.integer "max_age", null: false
    t.string "mode", null: false
    t.text "mx_patterns", null: false
    t.string "sts_id", null: false
    t.datetime "updated_at", null: false
    t.index ["domain"], name: "index_mta_sts_policies_on_domain", unique: true
  end

  create_table "sessions", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "ip_address"
    t.datetime "last_active_at", null: false
    t.datetime "updated_at", null: false
    t.string "user_agent"
    t.integer "user_id", null: false
    t.index ["last_active_at"], name: "index_sessions_on_last_active_at"
    t.index ["user_id"], name: "index_sessions_on_user_id"
  end

  create_table "settings", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "key", null: false
    t.datetime "updated_at", null: false
    t.string "value"
    t.index ["key"], name: "index_settings_on_key", unique: true
  end

  create_table "smtp_outbound_messages", force: :cascade do |t|
    t.integer "attempts", default: 0, null: false
    t.datetime "created_at", null: false
    t.binary "data", null: false
    t.text "last_error"
    t.string "mail_from", null: false
    t.datetime "next_attempt_at", null: false
    t.string "recipient", null: false
    t.datetime "sent_at"
    t.integer "status", default: 0, null: false
    t.datetime "updated_at", null: false
    t.index ["status", "next_attempt_at"], name: "index_smtp_outbound_messages_on_status_and_next_attempt_at"
  end

  create_table "tls_rpt_events", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "failure_detail"
    t.datetime "occurred_at", null: false
    t.string "policy_domain", null: false
    t.string "policy_type", null: false
    t.string "receiving_mx"
    t.string "result_type"
    t.datetime "updated_at", null: false
    t.index ["occurred_at"], name: "index_tls_rpt_events_on_occurred_at"
    t.index ["policy_domain", "occurred_at"], name: "index_tls_rpt_events_on_policy_domain_and_occurred_at"
  end

  create_table "users", force: :cascade do |t|
    t.string "accent", default: "crimson", null: false
    t.string "appearance", default: "system", null: false
    t.datetime "created_at", null: false
    t.string "email_address", null: false
    t.bigint "otp_last_used_at"
    t.string "otp_secret"
    t.string "password_digest", null: false
    t.datetime "updated_at", null: false
    t.string "webauthn_id"
    t.index ["email_address"], name: "index_users_on_email_address", unique: true
  end

  create_table "vacation_replies", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "email_account_id", null: false
    t.datetime "last_sent_at", null: false
    t.string "sender", null: false
    t.datetime "updated_at", null: false
    t.index ["email_account_id", "sender"], name: "index_vacation_replies_on_email_account_id_and_sender", unique: true
    t.index ["email_account_id"], name: "index_vacation_replies_on_email_account_id"
  end

  create_table "webauthn_credentials", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "external_id", null: false
    t.string "nickname", null: false
    t.string "public_key", null: false
    t.bigint "sign_count", default: 0, null: false
    t.datetime "updated_at", null: false
    t.bigint "user_id", null: false
    t.index ["external_id"], name: "index_webauthn_credentials_on_external_id", unique: true
    t.index ["user_id"], name: "index_webauthn_credentials_on_user_id"
  end

  add_foreign_key "active_storage_attachments", "active_storage_blobs", column: "blob_id"
  add_foreign_key "active_storage_variant_records", "active_storage_blobs", column: "blob_id"
  add_foreign_key "audit_events", "users", on_delete: :nullify
  add_foreign_key "dmarc_reports", "domains"
  add_foreign_key "email_aliases", "email_accounts"
  add_foreign_key "email_messages", "mailboxes"
  add_foreign_key "expunged_messages", "mailboxes"
  add_foreign_key "mailboxes", "email_accounts"
  add_foreign_key "sessions", "users"
  add_foreign_key "vacation_replies", "email_accounts"
  add_foreign_key "webauthn_credentials", "users"
end
