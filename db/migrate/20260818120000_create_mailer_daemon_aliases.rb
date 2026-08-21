# frozen_string_literal: true

# Backfill (2026-08): domains created before mailer-daemon support get
# their mailer-daemon@ alias into the postmaster account, the same record
# Domain's after_create hook now makes for new domains - our DSN bounces
# carry mailer-daemon@<domain> as their From:, so replies to a bounce must
# reach the operator instead of a rejection. Idempotent - reruns, fresh
# installs (no domains yet), and existing mailer-daemon arrangements are
# all no-ops (ensure_postmaster_account! skips taken addresses).
class CreateMailerDaemonAliases < ActiveRecord::Migration[8.1]
  def up
    MailOnRails::Domain.find_each(&:ensure_postmaster_account!)
  end

  def down
    # Deliberately kept: the postmaster account may hold received mail by
    # the time a rollback runs, same reasoning as report accounts on
    # domain destroy.
  end
end
