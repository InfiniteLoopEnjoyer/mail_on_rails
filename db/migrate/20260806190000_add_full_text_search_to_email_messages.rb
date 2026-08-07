class AddFullTextSearchToEmailMessages < ActiveRecord::Migration[8.1]
  # body_text is the message body as plain text, denormalised at delivery
  # time like subject/from/to are (and bounded - see
  # EmailMessage::SEARCHABLE_TEXT_LIMIT, which keeps the tsvector well
  # under Postgres's 1 MiB cap). The stored tsvector over it and the
  # listing columns backs both the web search and IMAP SEARCH pushdown.
  # 'simple', not 'english': mail comes in any language, and IMAP SEARCH
  # semantics leave no room for stemming or stopword removal.
  def up
    add_column :email_messages, :body_text, :text
    add_column :email_messages, :search_vector, :virtual, type: :tsvector, stored: true, as: <<~SQL.squish
      to_tsvector('simple',
        left(coalesce(subject, ''), 10000) || ' ' ||
        left(coalesce(from_address, ''), 1000) || ' ' ||
        left(coalesce(to_addresses, ''), 10000) || ' ' ||
        left(coalesce(body_text, ''), 200000))
    SQL
    add_index :email_messages, :search_vector, using: :gin

    say_with_time "backfilling body_text from stored messages" do
      EmailMessage.reset_column_information
      EmailMessage.find_each do |message|
        message.update_column(:body_text, EmailMessage.searchable_text(message.raw))
      end
    end
  end

  def down
    remove_column :email_messages, :search_vector
    remove_column :email_messages, :body_text
  end
end
