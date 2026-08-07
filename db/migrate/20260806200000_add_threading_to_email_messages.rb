class AddThreadingToEmailMessages < ActiveRecord::Migration[8.1]
  # RFC 5322 ancestry (In-Reply-To / References), denormalised at delivery
  # time like subject/from are, plus the opaque per-conversation thread_id
  # they resolve to (EmailMessage.thread_columns). message_id gets a bare
  # index because thread resolution looks ancestors up account-wide.
  def up
    add_column :email_messages, :in_reply_to, :string
    add_column :email_messages, :references_ids, :text
    add_column :email_messages, :thread_id, :string
    add_index :email_messages, :message_id
    add_index :email_messages, [ :mailbox_id, :thread_id ]

    say_with_time "backfilling thread ids" do
      EmailMessage.reset_column_information
      # Primary-key order approximates delivery order, so replies adopt
      # the thread their ancestors founded exactly as live delivery does.
      EmailMessage.includes(mailbox: :email_account).find_each do |message|
        mail = begin
          Mail.read_from_string(message.raw)
        rescue StandardError
          nil
        end
        message.update_columns(
          EmailMessage.thread_columns(message.mailbox.email_account, mail, message.email_object_id)
        )
      end
    end
  end

  def down
    remove_column :email_messages, :thread_id
    remove_column :email_messages, :references_ids
    remove_column :email_messages, :in_reply_to
    remove_index :email_messages, :message_id
  end
end
