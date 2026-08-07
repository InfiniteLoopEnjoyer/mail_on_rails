class AddStorageQuotaToEmailAccounts < ActiveRecord::Migration[8.1]
  # quota_bytes nil = unlimited (the default). used_bytes is the running
  # sum of the account's message sizes, maintained by EmailMessage's
  # create/destroy callbacks - summing octet lengths across every raw
  # message is too slow to run on each delivery.
  def up
    add_column :email_accounts, :quota_bytes, :bigint
    add_column :email_accounts, :used_bytes, :bigint, default: 0, null: false

    say_with_time "backfilling used_bytes from stored messages" do
      EmailAccount.reset_column_information
      EmailAccount.find_each do |account|
        used = EmailMessage.joins(:mailbox).where(mailboxes: { email_account_id: account.id }).sum(:size)
        account.update_column(:used_bytes, used)
      end
    end
  end

  def down
    remove_column :email_accounts, :used_bytes
    remove_column :email_accounts, :quota_bytes
  end
end
