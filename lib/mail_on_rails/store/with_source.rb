# frozen_string_literal: true

require "forwardable"
require "mail_on_rails/store"

module MailOnRails
  module Store
    # Wraps a store backend so authentication calls carry a fixed source:
    # label. The protocol sessions call authenticate/record_auth_failure
    # with only ip: (the wire code doesn't know which edge it is), while
    # Store::Base#log_attempt silently skips AuthAttempt logging when
    # source is blank - this wrapper is what keeps IMAP logins visible on
    # the auth-attempts page and inside the shared brute-force budget.
    class WithSource
      extend Forwardable

      def_delegators :@backend, :log, :scram_credentials, :record_closed_connection,
                     :list_mailboxes, :create_mailbox, :delete_mailbox, :rename_mailbox,
                     :select_mailbox, :status, :fetch, :store_flags, :expunge, :append,
                     :copy, :move, :expunged_since

      def initialize(backend, source)
        @backend = backend
        @source = source
      end

      def authenticate(email, password, ip: nil, source: nil)
        @backend.authenticate(email, password, ip: ip, source: source || @source)
      end

      def record_auth_failure(email, ip: nil, source: nil)
        @backend.record_auth_failure(email, ip: ip, source: source || @source)
      end
    end
  end
end
