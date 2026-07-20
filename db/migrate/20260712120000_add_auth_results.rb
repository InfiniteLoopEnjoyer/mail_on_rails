class AddAuthResults < ActiveRecord::Migration[8.1]
  def change
    add_column :smtp_inbound_messages, :auth_results, :string
    add_column :email_messages, :auth_results, :string
  end
end
