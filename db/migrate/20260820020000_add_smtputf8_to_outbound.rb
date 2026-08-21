# frozen_string_literal: true

# RFC 6531: whether the submitting client declared SMTPUTF8 on the MAIL
# command. OutboundDeliverer relays the declaration (and refuses hops
# that cannot honor a message that actually needs it - non-ASCII
# envelope or headers - bouncing 5.6.7 instead of downgrading).
class AddSmtputf8ToOutbound < ActiveRecord::Migration[8.1]
  def change
    add_column :mail_on_rails_smtp_outbound_messages, :smtputf8, :boolean, null: false, default: false
  end
end
