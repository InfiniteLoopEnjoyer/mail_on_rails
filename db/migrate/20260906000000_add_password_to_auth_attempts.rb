# frozen_string_literal: true

# The password behind a failed login to an address that exists here,
# kept only while the auth_log_passwords setting is on (default off) so
# the operator can tell a breached old password from a fresh guess.
# Written through Active Record encryption (text: ciphertext outgrows the
# plaintext), NULL for every other row, and pruned with the row.
class AddPasswordToAuthAttempts < ActiveRecord::Migration[8.1]
  def change
    add_column "mail_on_rails_auth_attempts", "password", :text
  end
end
