# frozen_string_literal: true

# Backfill (2026-08): domains created before postmaster support get their
# postmaster@ account and abuse@ alias, the same records Domain's
# after_create hook now makes for new domains. Idempotent - reruns and
# fresh installs (no domains yet) are no-ops, and existing postmaster/
# abuse addresses are left untouched.
class CreatePostmasterAccounts < ActiveRecord::Migration[8.1]
  def up
    MailOnRails::Domain.find_each(&:ensure_postmaster_account!)
  end

  def down
    # Deliberately kept: the accounts may hold received mail by the time a
    # rollback runs, same reasoning as report accounts on domain destroy.
  end
end
