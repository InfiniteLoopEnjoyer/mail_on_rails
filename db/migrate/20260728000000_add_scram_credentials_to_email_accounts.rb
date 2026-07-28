class AddScramCredentialsToEmailAccounts < ActiveRecord::Migration[8.1]
  def change
    add_column :email_accounts, :scram_salt, :string
    add_column :email_accounts, :scram_iterations, :integer
    add_column :email_accounts, :scram_stored_key, :string
    add_column :email_accounts, :scram_server_key, :string
  end
end
