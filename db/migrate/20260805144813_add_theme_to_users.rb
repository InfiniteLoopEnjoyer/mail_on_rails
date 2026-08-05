class AddThemeToUsers < ActiveRecord::Migration[8.1]
  def change
    add_column :users, :appearance, :string, null: false, default: "system"
    add_column :users, :accent, :string, null: false, default: "crimson"
  end
end
