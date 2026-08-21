# frozen_string_literal: true

# Backfill (2026-08): domains created before mail-host alias support get
# postmaster@/abuse@/mailer-daemon@ aliases at their mail.<name> host,
# the same records Domain's after_create hook now makes for new domains -
# external systems sometimes address operational mail to the hostname
# they saw in HELO or PTR instead of the organizational domain, and with
# no MX on mail.<name> that mail A-falls-back straight to us, where it
# answered "relaying denied". Idempotent - reruns, fresh installs (no
# domains yet), and existing arrangements are all no-ops
# (ensure_postmaster_account! skips taken addresses).
class CreateMailHostAliases < ActiveRecord::Migration[8.1]
  def up
    MailOnRails::Domain.find_each(&:ensure_postmaster_account!)
  end

  def down
    # Deliberately kept: the postmaster account may hold received mail by
    # the time a rollback runs, same reasoning as report accounts on
    # domain destroy.
  end
end
