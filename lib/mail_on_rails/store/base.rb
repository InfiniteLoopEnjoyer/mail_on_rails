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

      # +ip+ is the mail client's address as the edge saw it, used for
      # brute-force throttling (AuthThrottle). It is optional so an edge
      # that cannot supply one still gets per-account throttling.
      #
      # A throttled attempt returns { throttled: true, retry_after: } and
      # never reaches the bcrypt comparison - the point is to make guessing
      # both futile and cheap to refuse.
      #
      # Returning here also means a refused attempt is not counted, in
      # either scope. That is deliberate in both directions: hammering an
      # already-blocked account must not climb the source's counter (it is
      # one target, nearly always a client retrying a stale password, and
      # escalating to an ip block would take out everyone else behind that
      # address), and a blocked source must not be able to push accounts
      # toward blocks (that would make the throttle a lockout tool). The
      # scopes still trip independently across *different* targets: a
      # blocked account is no shield for an attacker working through
      # others, since each fresh address is adjudicated normally and feeds
      # the ip counter. Pinned in test/models/auth_throttle_test.rb.
      def authenticate(email, password, ip: nil)
        db do
          if (blocked = AuthThrottle.check(ip: ip, email: email))
            next throttled_result(blocked, email, ip)
          end

          account = EmailAccount.authenticate_by(email: email.to_s, password: password.to_s)
          if account
            AuthThrottle.clear_account(account.email)
          else
            AuthThrottle.record_failure(ip: ip, email: email)
          end
          { account_id: account&.id, email: account&.email }
        end
      end

      # Counts a failure the store itself did not adjudicate: SCRAM proofs
      # are verified by the daemon against verifier material, so the app
      # only learns of those failures when the daemon reports them.
      def record_auth_failure(email, ip: nil)
        db do
          AuthThrottle.record_failure(ip: ip, email: email)
          {}
        end
      end

      private

      def throttled_result(blocked, email, ip)
        Rails.logger.warn("[mail_on_rails] auth throttled by #{blocked[:scope]} " \
                          "(#{ip || "no ip"}, #{email}): #{blocked[:retry_after]}s remaining")
        { account_id: nil, email: nil, throttled: true, retry_after: blocked[:retry_after] }
      end

      def db
        Rails.application.executor.wrap { yield }
      rescue StandardError => e
        Rails.logger.error("[mail_on_rails] store error: #{e.class}: #{e.message}")
        { error: "#{e.class}: #{e.message}", code: :internal }
      end
    end
  end
end
