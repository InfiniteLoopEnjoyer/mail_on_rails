class CreateEmailAccounts < ActiveRecord::Migration[8.1]
  def change
    create_table :email_accounts do |t|
      t.string :email, null: false
      t.string :name
      t.string :password_digest, null: false

      t.timestamps
    end
    add_index :email_accounts, :email, unique: true
  end
end
