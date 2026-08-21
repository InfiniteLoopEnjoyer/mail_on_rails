# frozen_string_literal: true

module MailOnRails
  # Abstract base for every Active Record model the gem owns. Table names
  # get the MailOnRails.table_name_prefix (isolate_namespace consults it);
  # the host app can point the whole set at another database with
  # `config.mail_on_rails.connects_to = { database: { writing: :mail } }`.
  class Record < ActiveRecord::Base
    self.abstract_class = true

    connects_to(**MailOnRails.connects_to) if MailOnRails.connects_to
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_record, MailOnRails::Record
