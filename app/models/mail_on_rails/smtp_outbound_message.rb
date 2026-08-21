# One queued outbound delivery per remote recipient, created by the SMTP
# server (via the DB broker) when an authenticated submission addresses a
# non-local recipient. DeliverSmtpOutboundJob drains the queue.
module MailOnRails
  class SmtpOutboundMessage < Record
    # Minutes until the next retry, indexed by how many attempts have failed.
    # ~22 hours of retries before the message is bounced.
    BACKOFF_MINUTES = [ 1, 5, 15, 30, 60, 180, 360, 720 ].freeze
    MAX_ATTEMPTS = BACKOFF_MINUTES.size

    # `delivering` claims a row so overlapping job runs can't double-send.
    enum :status, { pending: 0, sent: 1, failed: 2, delivering: 3 }

    scope :due, -> { pending.where(next_attempt_at: ..Time.current).order(:id) }
    # A job that died mid-delivery leaves rows delivering forever; reclaim them.
    scope :stuck, -> { delivering.where(updated_at: ...15.minutes.ago) }

    def domain
      recipient.split("@").last.to_s.downcase
    end

    # -- sender DSN requests (RFC 3461), recorded at submission time ------

    def notify_set
      dsn_notify.to_s.upcase.split(",").map(&:strip)
    end

    # An absent NOTIFY defaults to failure-only notification (RFC 3461
    # 4.1); NEVER suppresses everything.
    def wants_failure_dsn? = dsn_notify.blank? || notify_set.include?("FAILURE")
    def wants_success_dsn? = notify_set.include?("SUCCESS")
    # Delay DSNs without a NOTIFY are at the MTA's discretion; we send one.
    def wants_delay_dsn?   = dsn_notify.blank? || notify_set.include?("DELAY")

    # When retries will exhaust, for the delayed DSN's Will-Retry-Until.
    def retry_deadline
      (created_at || Time.current) + BACKOFF_MINUTES.sum.minutes
    end

    def record_success!
      update!(status: :sent, sent_at: Time.current, last_error: nil)
    end

    # Transient errors back off and retry; permanent errors (or exhausted
    # retries) mark the row failed. Returns :failed or :deferred so the
    # caller knows whether to generate a bounce.
    def record_failure!(error, permanent:)
      if permanent || attempts + 1 >= MAX_ATTEMPTS
        update!(status: :failed, attempts: attempts + 1, last_error: error)
        :failed
      else
        update!(
          status: :pending,
          attempts: attempts + 1,
          last_error: error,
          next_attempt_at: BACKOFF_MINUTES[attempts].minutes.from_now
        )
        :deferred
      end
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_smtp_outbound_message, MailOnRails::SmtpOutboundMessage
