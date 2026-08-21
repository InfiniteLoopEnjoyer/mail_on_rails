# frozen_string_literal: true

# One-click unsubscribe support (RFC 8058): suppressions gain an optional
# sender scope - an FBL complaint row (sender NULL) still suppresses all
# outbound mail to the recipient, while an unsubscribe row suppresses
# only the sender the recipient unsubscribed from. Also backfills the
# unsubscribe@ ingestion account (the mailto: target of injected
# List-Unsubscribe headers) for domains created before this feature,
# matching Domain's after_create hook for new ones.
class AddUnsubscribeSupport < ActiveRecord::Migration[8.1]
  def up
    add_column :mail_on_rails_suppressed_recipients, :sender, :string
    remove_index :mail_on_rails_suppressed_recipients, name: "index_suppressed_recipients_on_email"
    add_index :mail_on_rails_suppressed_recipients, [ :email, :sender ], unique: true,
              name: "index_suppressed_recipients_on_email_and_sender"
    add_index :mail_on_rails_suppressed_recipients, :email, name: "index_suppressed_recipients_on_email"

    # The model is used mid-migration-run; its column cache must reflect
    # this run's earlier migrations (and later ones must reset it again).
    MailOnRails::Domain.reset_column_information
    MailOnRails::Domain.find_each(&:ensure_unsubscribe_account!)
  end

  def down
    # Sender-scoped rows have no global equivalent; keep only the global
    # ones the old unique index can hold. The account stays, same
    # reasoning as report accounts on domain destroy.
    remove_index :mail_on_rails_suppressed_recipients, name: "index_suppressed_recipients_on_email"
    remove_index :mail_on_rails_suppressed_recipients, name: "index_suppressed_recipients_on_email_and_sender"
    MailOnRails::SuppressedRecipient.where.not(sender: nil).delete_all
    remove_column :mail_on_rails_suppressed_recipients, :sender
    add_index :mail_on_rails_suppressed_recipients, :email, unique: true,
              name: "index_suppressed_recipients_on_email"
  end
end
