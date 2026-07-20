# frozen_string_literal: true

module MailOnRails
  module Store
    # Shared plumbing for the Active Record-backed stores. Ops run inline on
    # the calling connection thread, wrapped in the Rails executor (which
    # checks a connection out of the pool for the op's duration and
    # cooperates with code reloading in development).
    #
    # Every result is a plain value (hashes, arrays, strings, integers) -
    # never an ActiveRecord object - so protocol code stays free of Rails
    # specifics. The full interface spec lives in docs/store_contract.md.
    class Base
      def log(level, message)
        Rails.logger.public_send(level, "[mail_on_rails] #{message}")
        nil
      end

      def authenticate(email, password)
        db do
          account = EmailAccount.authenticate_by(email: email.to_s, password: password.to_s)
          { account_id: account&.id, email: account&.email }
        end
      end

      private

      def db
        Rails.application.executor.wrap { yield }
      rescue StandardError => e
        Rails.logger.error("[mail_on_rails] store error: #{e.class}: #{e.message}")
        { error: "#{e.class}: #{e.message}", code: :internal }
      end
    end
  end
end
