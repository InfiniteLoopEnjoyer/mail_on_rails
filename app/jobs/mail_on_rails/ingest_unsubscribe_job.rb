require "cgi"

# Processes mail delivered to a domain's unsubscribe@ account - the
# mailto: fallback of the List-Unsubscribe headers OutboundDeliverer
# injects (older clients use it; RFC 8058 one-click POSTs go to
# UnsubscribesController instead). The signed UnsubscribeToken in the
# subject is the entire authorization: only someone who received the
# message has it, so no sender-verification gate is needed - forged mail
# without a valid token is inert (logged, nothing suppressed). Runs after
# delivery, so a malformed request never delays or bounces mail.
module MailOnRails
  class IngestUnsubscribeJob < BaseJob
    queue_as :default

    discard_on ActiveJob::DeserializationError

    def perform(email_message)
      data = token_data(email_message.subject.to_s)
      unless data
        Rails.logger.info "[mail_on_rails] unsubscribe mail #{email_message.id} from " \
                          "#{email_message.from_address.inspect} carried no valid token - ignored"
        return
      end

      record = SuppressedRecipient.record_unsubscribe!(data[:recipient], sender: data[:sender],
                                                       reporter: "mailto")
      Rails.logger.info "[mail_on_rails] unsubscribe (mailto) recorded: <#{record.email}> from <#{record.sender}>"
    end

    private

    # The injected mailto: carries "subject=unsubscribe%3A<token>"; what
    # lands in the Subject depends on how faithfully the client decoded
    # the URL, so both the raw and percent-decoded forms are tried.
    def token_data(subject)
      candidate = subject[/unsubscribe:(\S+)/, 1]
      return nil unless candidate

      UnsubscribeToken.verify(candidate) || UnsubscribeToken.verify(CGI.unescape(candidate))
    end
  end
end
