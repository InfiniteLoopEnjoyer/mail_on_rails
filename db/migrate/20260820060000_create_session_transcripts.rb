# frozen_string_literal: true

# Stored transcripts of abnormally ended mail sessions (smtp_trace_capture),
# linked from the closed-connection history so the /smtp page can open the
# capture behind a row - see MailOnRails::SessionTranscript. transcript_id is
# a plain column rather than a foreign key: transcripts are pruned on a much
# shorter clock than the history rows pointing at them, and a dangling id is
# the documented "no longer retained" state.
#
# Adapter-aware like the honeypot migration: MySQL's default TEXT caps at
# 64 KiB, below the 128 KiB transcript buffer, so it gets mediumtext.
class CreateSessionTranscripts < ActiveRecord::Migration[8.1]
  include MailOnRails::MigrationHelpers

  def change
    create_table "mail_on_rails_session_transcripts" do |t|
      t.string "close_reason"
      t.datetime "closed_at", null: false
      t.datetime "connected_at"
      t.datetime "created_at", null: false
      t.string "helo"
      t.string "ip"
      t.integer "port"
      t.string "protocol", null: false
      t.text "transcript", **(mysql? ? { limit: 16_777_215 } : {})
      t.datetime "updated_at", null: false
      t.string "username"
      t.index [ "closed_at" ], name: "index_session_transcripts_on_closed_at"
    end

    add_column "mail_on_rails_closed_connections", "transcript_id", :bigint
  end
end
