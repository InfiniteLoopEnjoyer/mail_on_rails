# Runs on a recurring schedule (config/recurring.yml) and drains the
# outbound queue. Each row is claimed (pending -> delivering) before the
# network attempt so an overlapping run can't double-send; permanently
# failed deliveries bounce back to the sender's local INBOX.
class DeliverSmtpOutboundJob < ApplicationJob
  queue_as :default

  BATCH = 50

  def perform
    SmtpOutboundMessage.stuck.update_all(status: :pending)

    SmtpOutboundMessage.due.limit(BATCH).each do |message|
      next unless claim(message)

      deliver(message)
    end
  end

  private

  def claim(message)
    SmtpOutboundMessage.where(id: message.id, status: :pending)
                       .update_all(status: :delivering, updated_at: Time.current) == 1
  end

  def deliver(message)
    OutboundDeliverer.deliver(message)
    message.record_success!
    Rails.logger.info "[mail_on_rails] outbound #{message.id} delivered to <#{message.recipient}>"
  rescue OutboundDeliverer::PermanentError => e
    Rails.logger.warn "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> permanently failed: #{e.message}"
    bounce(message, e.message) if message.record_failure!(e.message, permanent: true) == :failed
  rescue OutboundDeliverer::TransientError => e
    if message.record_failure!(e.message, permanent: false) == :failed
      Rails.logger.warn "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> giving up after #{message.attempts} attempts: #{e.message}"
      bounce(message, e.message)
    else
      Rails.logger.info "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> deferred, will retry: #{e.message}"
    end
  rescue StandardError => e
    message.record_failure!("#{e.class}: #{e.message}", permanent: false)
    raise
  end

  # A minimal DSN delivered straight into the local sender's INBOX. The
  # envelope sender is empty per RFC 5321 (bounces must not bounce).
  def bounce(message, error)
    account = EmailAccount.find_by(email: message.mail_from.to_s.downcase)
    return unless account

    original_headers = message.data.to_s.b.partition(/\r?\n\r?\n/).first.byteslice(0, 8_192)
    notice = Mail.new do
      from    "Mail Delivery System <mailer-daemon@#{ENV.fetch("MAIL_ON_RAILS_HELO_HOST", "localhost")}>"
      to      message.mail_from
      subject "Undelivered Mail Returned to Sender"
      date    Time.current
      body    <<~BODY
        Your message to <#{message.recipient}> could not be delivered
        after #{message.attempts} attempt(s).

        Reason:
          #{error}

        ------ Original message headers ------
        #{original_headers}
      BODY
    end
    EmailMessage.deliver_raw(account.inbox, notice.to_s)
  rescue StandardError => e
    Rails.logger.error "[mail_on_rails] bounce generation failed for outbound #{message.id}: #{e.class}: #{e.message}"
  end
end
