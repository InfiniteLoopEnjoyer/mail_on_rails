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

ActiveRecord::Schema[8.1].define(version: 2026_07_23_120000) do
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

  create_table "email_accounts", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "email", null: false
    t.string "name"
    t.string "password_digest", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_email_accounts_on_email", unique: true
  end

  create_table "email_messages", force: :cascade do |t|
    t.string "auth_results"
    t.string "authenticated_as"
    t.datetime "created_at", null: false
    t.text "flags", default: "[]", null: false
    t.string "from_address"
    t.datetime "internal_date", null: false
    t.integer "mailbox_id", null: false
    t.string "message_id"
    t.binary "raw", null: false
    t.string "scan_status"
    t.integer "size", default: 0, null: false
    t.string "spam_action"
    t.float "spam_score"
    t.float "spam_threshold"
    t.string "subject"
    t.text "to_addresses"
    t.integer "uid", null: false
    t.datetime "updated_at", null: false
    t.string "virus_name"
    t.index ["mailbox_id", "internal_date"], name: "index_email_messages_on_mailbox_id_and_internal_date"
    t.index ["mailbox_id", "message_id"], name: "index_email_messages_on_mailbox_id_and_message_id"
    t.index ["mailbox_id", "uid"], name: "index_email_messages_on_mailbox_id_and_uid", unique: true
    t.index ["mailbox_id"], name: "index_email_messages_on_mailbox_id"
  end

  create_table "mailboxes", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "email_account_id", null: false
    t.string "name", null: false
    t.integer "uid_next", default: 1, null: false
    t.integer "uid_validity", null: false
    t.datetime "updated_at", null: false
    t.index ["email_account_id", "name"], name: "index_mailboxes_on_email_account_id_and_name", unique: true
    t.index ["email_account_id"], name: "index_mailboxes_on_email_account_id"
  end

  create_table "sessions", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "ip_address"
    t.datetime "updated_at", null: false
    t.string "user_agent"
    t.integer "user_id", null: false
    t.index ["user_id"], name: "index_sessions_on_user_id"
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

  create_table "users", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "email_address", null: false
    t.string "password_digest", null: false
    t.datetime "updated_at", null: false
    t.index ["email_address"], name: "index_users_on_email_address", unique: true
  end

  add_foreign_key "active_storage_attachments", "active_storage_blobs", column: "blob_id"
  add_foreign_key "active_storage_variant_records", "active_storage_blobs", column: "blob_id"
  add_foreign_key "email_messages", "mailboxes"
  add_foreign_key "mailboxes", "email_accounts"
  add_foreign_key "sessions", "users"
end
