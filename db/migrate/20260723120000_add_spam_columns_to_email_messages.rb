# rspamd verdict per stored inbound message: spam_score is the message's
# score, spam_threshold the score at which rspamd's action kicks in
# (required_score), spam_action rspamd's chosen action ("no action",
# "reject", ...). All nil when rspamd is disabled/unreachable or the sender
# is an authenticated local submitter (no inbound analysis runs). The UI
# renders these in the received-message analysis footer.
class AddSpamColumnsToEmailMessages < ActiveRecord::Migration[8.1]
  def change
    add_column :email_messages, :spam_score, :float
    add_column :email_messages, :spam_threshold, :float
    add_column :email_messages, :spam_action, :string
  end
end
