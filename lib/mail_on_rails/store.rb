# frozen_string_literal: true

require_relative "store/base"
require_relative "store/imap_backend"

module MailOnRails
  # Namespace for the app-side storage adapters behind the protocol
  # servers. The servers talk to the world only through a store; the
  # interface is specified in docs/store_contract.md. The daemon-side
  # implementations (MailOnRails::Smtp::Store::Http /
  # MailOnRails::Imap::Store::Http) live in the extracted gems and reach
  # this app over HTTP - what remains here is the Active Record store the
  # internal API delegates to (Store::ImapBackend) and its shared plumbing
  # (Store::Base).
  module Store
  end
end
