class CreateEmailAliases < ActiveRecord::Migration[8.1]
  def change
    create_table :email_aliases do |t|
      t.string :email, null: false
      t.references :email_account, null: false, foreign_key: true

      t.timestamps
    end
    add_index :email_aliases, :email, unique: true
  end
end
