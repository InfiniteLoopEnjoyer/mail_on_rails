# frozen_string_literal: true

# Backfill: domains created before VERP support get their bounce@
# account, the same record Domain's after_create hook now makes for new
# domains. Idempotent - reruns, fresh installs, and existing bounce@
# arrangements are all no-ops.
class CreateBounceAccounts < ActiveRecord::Migration[8.1]
  def up
    MailOnRails::Domain.find_each(&:ensure_bounce_account!)
  end

  def down
    # Deliberately kept: the account may hold received bounces by the
    # time a rollback runs, same reasoning as the other report accounts.
  end
end
