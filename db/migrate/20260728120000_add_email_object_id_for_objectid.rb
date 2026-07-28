require "digest"

# OBJECTID (RFC 8474): EMAILID is derived from the message content, so
# COPY/MOVE preserve it and identical APPENDs share it. Stored (rather
# than hashed per fetch) so metadata fetches never pay for hashing raw.
class AddEmailObjectIdForObjectid < ActiveRecord::Migration[8.0]
  class MigrationEmailMessage < ActiveRecord::Base
    self.table_name = "email_messages"
  end

  def up
    add_column :email_messages, :email_object_id, :string

    MigrationEmailMessage.reset_column_information
    MigrationEmailMessage.where(email_object_id: nil).find_each do |message|
      message.update_columns(email_object_id: "E#{Digest::SHA256.hexdigest(message.raw.to_s)[0, 24]}")
    end
  end

  def down
    remove_column :email_messages, :email_object_id
  end
end
