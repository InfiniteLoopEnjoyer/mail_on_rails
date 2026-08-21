# frozen_string_literal: true

require_relative "store/base"
require_relative "store/with_source"

module MailOnRails
  # Namespace for the Active Record storage adapters behind the mail
  # servers. A server talks to the world only through a store; the
  # contracts are specified in docs/store_contract.md and have executable
  # form in each protocol gem (MailOnRails::{Imap,Smtp}::Store::Contracts).
  #
  # This gem holds the shared plumbing: Store::Base (executor wrapping,
  # AuthThrottle policy, AuthAttempt logging, the ops-state projection) and
  # Store::WithSource (stamps auth calls with their surface). The concrete
  # backends live with their protocols - Store::ImapBackend in
  # mail_on_rails_imap, Store::SmtpBackend in mail_on_rails_smtp - and
  # inherit Store::Base.
  module Store
  end
end
