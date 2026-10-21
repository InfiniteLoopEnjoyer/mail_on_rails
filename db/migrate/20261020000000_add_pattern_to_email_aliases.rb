# frozen_string_literal: true

# Pattern aliases: an alias row whose local part is a regular expression
# (e.g. "shop-.*@example.com") rather than a literal address, so a whole
# family of addresses delivers into one account - see
# MailOnRails::EmailAlias. The flag is what keeps the two kinds apart in
# every lookup: exact resolution must never read a pattern row as the
# literal address it is spelled as.
class AddPatternToEmailAliases < ActiveRecord::Migration[8.1]
  def change
    add_column "mail_on_rails_email_aliases", "pattern", :boolean, null: false, default: false
  end
end
