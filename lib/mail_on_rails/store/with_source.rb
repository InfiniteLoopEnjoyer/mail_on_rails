# frozen_string_literal: true

require "mail_on_rails/store"

module MailOnRails
  module Store
    # Wraps a store backend so authentication calls carry a fixed source:
    # label. The protocol sessions call authenticate/record_auth_failure
    # with only ip: (the wire code doesn't know which edge it is), while
    # Store::Base#log_attempt silently skips AuthAttempt logging when
    # source is blank - this wrapper is what keeps IMAP logins visible on
    # the auth-attempts page and inside the shared brute-force budget.
    #
    # Everything else passes straight through, including the OPTIONAL
    # store methods the servers probe with respond_to? (connection
    # history, honeypot events, the ops-state projection): the wrapper
    # answers exactly what the backend answers, so wrapping never hides a
    # capability - an explicit delegator list once did exactly that, and
    # the IMAP listener silently stopped projecting its ops state.
    class WithSource
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

      def respond_to_missing?(name, include_private = false)
        @backend.respond_to?(name, include_private) || super
      end

      def method_missing(name, ...)
        if @backend.respond_to?(name)
          @backend.public_send(name, ...)
        else
          super
        end
      end
    end
  end
end
