# frozen_string_literal: true

require_relative "store/base"
require_relative "store/imap_backend"

module MailOnRails
  # Namespace for the app-side storage adapter behind the IMAP server. The
  # server talks to the world only through a store; the interface is
  # specified in docs/store_contract.md. The daemon-side implementation
  # (MailOnRails::Imap::Store::Http) lives in the extracted gem and reaches
  # this app over HTTP - what remains here is the Active Record store the
  # internal API delegates to (Store::ImapBackend) and its shared plumbing
  # (Store::Base). The SMTP edge (mail_on_rails_exim) uses no store; it POSTs
  # straight to the relay ingress and the mail_on_rails/internal API.
  module Store
  end
end
