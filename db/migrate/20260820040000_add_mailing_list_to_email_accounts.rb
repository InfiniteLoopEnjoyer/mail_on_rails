# frozen_string_literal: true

# Marks an account as a mailing-list sender: everything it submits IS
# list mail, so OutboundDeliverer stamps a List-ID derived from the
# account address onto outbound messages that lack one - which in turn
# triggers the List-Unsubscribe/one-click injection. Unflagged accounts
# keep the existing behavior: the composing client's own List-ID header
# decides.
class AddMailingListToEmailAccounts < ActiveRecord::Migration[8.1]
  def change
    add_column :mail_on_rails_email_accounts, :mailing_list, :boolean, null: false, default: false
    # An earlier migration in the same run used the model (the unsubscribe
    # account backfill), fixing its column cache pre-mailing_list.
    MailOnRails::EmailAccount.reset_column_information
  end
end
