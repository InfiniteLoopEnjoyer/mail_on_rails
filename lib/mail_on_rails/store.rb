# frozen_string_literal: true

require_relative "store/base"
require_relative "store/imap_backend"
require_relative "store/smtp_backend"

module MailOnRails
  # Namespace for the app-side storage adapters behind the in-process mail
  # servers. A server talks to the world only through a store; the IMAP
  # interface is specified in docs/store_contract.md and both interfaces
  # have executable form in lib/mail_on_rails/{imap,smtp}/store/contracts.rb.
  # Store::ImapBackend is the Active Record implementation the IMAP
  # sessions use (wrapped in Store::WithSource so auth attempts carry
  # source: "imap"); Store::SmtpBackend serves the SMTP sessions
  # (recipient checks, inbound ingestion, outbound queueing, quarantine);
  # Store::Base holds the shared plumbing (executor wrapping, AuthThrottle
  # policy, AuthAttempt logging).
  module Store
  end
end
