# frozen_string_literal: true

require "mail_on_rails/rspamd_analyzer"

module MailOnRails
  # Feeds a message a user filed into Junk (spam) or rescued out of it
  # (ham) to rspamd's Bayes classifier - see JunkFeedback, which enqueues
  # this after the move commits. A job, not an inline call: the IMAP
  # backend runs the move on the session thread inside the executor, where
  # an HTTP round-trip would pin a pool connection.
  #
  # The message is looked up by row id first; a move mints a new row, so
  # when the user has already moved it again the content-derived
  # email_object_id (RFC 8474 EMAILID) finds the current copy within the
  # account. Gone entirely (expunged) = nothing to learn from.
  class LearnSpamJob < BaseJob
    class Unavailable < StandardError; end

    queue_as :default
    retry_on Unavailable, wait: :polynomially_longer, attempts: 3

    def perform(message_id, email_object_id, account_id, klass)
      return unless RspamdAnalyzer.learning_enabled?

      message = EmailMessage.find_by(id: message_id) ||
                EmailMessage.joins(:mailbox).find_by(email_object_id: email_object_id,
                                                     mailbox: { email_account_id: account_id })
      return unless message

      case RspamdAnalyzer.learn(message.raw, klass)
      when :ok, :already_learned
        MailOnRails.logger.info "[mail_on_rails] rspamd learned #{klass} from message #{message.id}"
      when :unavailable
        raise Unavailable, "rspamd controller #{RspamdAnalyzer.controller_addr} unavailable"
      else
        MailOnRails.logger.warn "[mail_on_rails] rspamd refused to learn #{klass} from message #{message.id} " \
                                "(check smtp_rspamd_controller_addr / smtp_rspamd_password)"
      end
    end
  end
end
