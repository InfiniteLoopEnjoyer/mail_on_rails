class CreateDmarcReports < ActiveRecord::Migration[8.1]
  def change
    create_table :dmarc_reports do |t|
      t.references :domain, null: false, foreign_key: true
      t.string :reporter, null: false
      t.string :report_id, null: false
      t.datetime :begin_at, null: false
      t.datetime :end_at, null: false
      t.string :source_ip, null: false
      t.integer :count, null: false, default: 1
      t.string :disposition
      t.string :dkim
      t.string :spf

      t.timestamps
    end
    add_index :dmarc_reports, %i[domain_id begin_at]
    add_index :dmarc_reports, %i[domain_id reporter report_id]
  end
end
