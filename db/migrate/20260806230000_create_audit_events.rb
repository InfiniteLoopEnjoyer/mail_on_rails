class CreateAuditEvents < ActiveRecord::Migration[8.1]
  def change
    create_table :audit_events do |t|
      # Nullified rather than cascaded when the user is deleted - the
      # audit row must outlive its actor; user_email keeps the name.
      t.references :user, foreign_key: { on_delete: :nullify }, index: true, null: true
      t.string :user_email, null: false
      t.string :action, null: false
      t.string :subject_type
      t.bigint :subject_id
      t.string :subject_label
      t.jsonb :details, null: false, default: {}
      t.string :ip
      t.datetime :created_at, null: false
    end
    add_index :audit_events, :created_at
    add_index :audit_events, [ :subject_type, :subject_id ]
  end
end
