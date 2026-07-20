class AddTrustToMessages < ActiveRecord::Migration[8.1]
  def change
    # NULL = accepted unauthenticated (inbound/MX). A value = the account that
    # authenticated when submitting, i.e. a trusted, non-spoofed sender.
    add_column :smtp_inbound_messages, :authenticated_as, :string
    add_column :email_messages, :authenticated_as, :string
  end
end
