class CreateDomains < ActiveRecord::Migration[8.1]
  def change
    create_table :domains do |t|
      t.string :name, null: false

      t.timestamps
    end
    add_index :domains, :name, unique: true
  end
end
