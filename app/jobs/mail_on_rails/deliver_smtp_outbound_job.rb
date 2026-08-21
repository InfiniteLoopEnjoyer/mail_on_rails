require "mail_on_rails/clamav_scanner"

# Runs on a recurring schedule (config/recurring.yml) and drains the
# outbound queue. Each row is claimed (pending -> delivering) before the
# network attempt so an overlapping run can't double-send.
#
# Notifications honor the sender's RFC 3461 requests, recorded on the row
# at submission time (all default-safe when absent): permanent failure
# returns an RFC 3464 failure DSN unless NOTIFY excluded FAILURE; a
# message queued past smtp_delay_warning_seconds gets one delayed DSN;
# NOTIFY=SUCCESS gets a delivered/relayed DSN unless the next hop took
# the DSN request over. Every DSN is delivered locally to the author
# (INBOX, or Quarantine on a virus hit) - senders are always local
# accounts, so none of this can backscatter.
module MailOnRails
  class DeliverSmtpOutboundJob < BaseJob
    queue_as :default

    BATCH = 50

    # Per-destination pacing (smtp_outbound_domain_batch): large ISPs
    # rate-limit by source IP, so a burst to one domain is spread across
    # runs - at most N attempts per destination domain per run, and a
    # transient failure parks the domain's remaining messages until the
    # next run instead of hammering a server that just said "slow down".
    # Skipped rows are never claimed, so they cost nothing and stay due.
    def perform
      SmtpOutboundMessage.stuck.update_all(status: :pending)

      domain_batch = MailOnRails::Settings[:smtp_outbound_domain_batch].to_i
      attempted = Hash.new(0)
      deferred_domains = Set.new

      SmtpOutboundMessage.due.limit(BATCH).each do |message|
        domain = message.domain
        if domain_batch.positive? && (deferred_domains.include?(domain) || attempted[domain] >= domain_batch)
          next
        end
        next unless claim(message)

        attempted[domain] += 1
        deferred_domains << domain if deliver(message) == :deferred
      end
    end

    private

    def claim(message)
      claimed = SmtpOutboundMessage.where(id: message.id, status: :pending)
                                   .update_all(status: :delivering, updated_at: Time.current) == 1
      # update_all bypasses the instance, which still thinks it's :pending -
      # and dirty tracking then treats the deferral path's
      # update!(status: :pending) as a no-change no-op (it matches the value
      # loaded from the DB), leaving the row :delivering until the stuck
      # reclaim instead of honoring next_attempt_at. Reload so the instance
      # sees what the claim wrote; assigning the attribute is not enough.
      message.reload if claimed
      claimed
    end

    # Returns :delivered, :failed, or :deferred (a transient failure that
    # will retry) - perform uses :deferred to park the destination domain
    # for the rest of the run.
    def deliver(message)
      # Suppression: the recipient reported our mail as spam through a
      # feedback loop (global - see IngestFblReportJob) or unsubscribed
      # from this sender's list mail (sender-scoped - RFC 8058 one-click
      # or the mailto: fallback). Failed permanently without a network
      # attempt - the bounce tells the local sender why; an operator
      # lifts a suppression by deleting the SuppressedRecipient row.
      if SuppressedRecipient.suppressed?(message.recipient, sender: message.mail_from)
        error = "delivery suppressed: <#{message.recipient}> unsubscribed from this sender's mail or " \
                "reported it as spam (feedback-loop complaint); contact the server operator to lift the suppression"
        Rails.logger.warn "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> suppressed (FBL complaint)"
        bounce(message, error) if message.record_failure!(error, permanent: true) == :failed
        return :failed
      end

      outcome = OutboundDeliverer.deliver(message)
      message.record_success!
      Rails.logger.info "[mail_on_rails] outbound #{message.id} delivered to <#{message.recipient}>"
      # :propagated_dsn means the next hop advertised DSN and now owns the
      # request; reporting "relayed" as well would double-notify.
      if message.wants_success_dsn? && outcome != :propagated_dsn
        deliver_dsn(message) { DeliveryStatusNotification.success(message: message) }
      end
      :delivered
    rescue OutboundDeliverer::PermanentError => e
      Rails.logger.warn "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> permanently failed: #{e.message}"
      bounce(message, e.message) if message.record_failure!(e.message, permanent: true) == :failed
      :failed
    rescue OutboundDeliverer::TransientError => e
      if message.record_failure!(e.message, permanent: false) == :failed
        Rails.logger.warn "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> giving up after #{message.attempts} attempts: #{e.message}"
        bounce(message, e.message)
        :failed
      else
        Rails.logger.info "[mail_on_rails] outbound #{message.id} to <#{message.recipient}> deferred, will retry: #{e.message}"
        delay_warning(message, e.message)
        :deferred
      end
    rescue StandardError => e
      message.record_failure!("#{e.class}: #{e.message}", permanent: false)
      raise
    end

    # An RFC 3464 failure DSN into the local sender's INBOX, unless the
    # sender's NOTIFY excluded FAILURE (or said NEVER).
    def bounce(message, error)
      return unless message.wants_failure_dsn?

      deliver_dsn(message) { DeliveryStatusNotification.failure(message: message, error: error) }
    end

    # One delayed-delivery DSN per message, once it has been queued past
    # the smtp_delay_warning_seconds threshold (0 disables).
    def delay_warning(message, error)
      threshold = MailOnRails::Settings[:smtp_delay_warning_seconds].to_i
      return if threshold.zero? || message.delay_notified_at.present? || !message.wants_delay_dsn?
      return if message.created_at.nil? || Time.current - message.created_at < threshold

      deliver_dsn(message) { DeliveryStatusNotification.delayed(message: message, error: error) }
      message.update!(delay_notified_at: Time.current)
    end

    # DSNs are local mail to the author (never outbound, never bounceable);
    # generation failure must not take the queue run down.
    #
    # The notice never rode the wire, so no edge or mailroom looked at it -
    # it is stamped and scanned here instead. authenticated_as records the
    # mailer-daemon From as the verified local sender (the server built the
    # message itself; rspamd sender-auth is skipped exactly as it is for any
    # authenticated submitter - there are no connection facts to judge). The
    # clamav scan is real, though: a failure DSN can embed the full original
    # message (RET=FULL), and signatures move - a late verdict can catch what
    # submission-time scanning missed. Infected goes to Quarantine like any
    # inbound hit; a scanner outage fails open as "unscanned" (matching the
    # other authenticated writes) for RescanUnscannedMessagesJob to catch up.
    def deliver_dsn(message)
      # The envelope sender may be an alias of the authoring account
      # (send-as-alias); either way the DSN belongs in that account.
      address = message.mail_from.to_s.downcase
      account = EmailAccount.find_by(email: address) || EmailAlias.find_by(email: address)&.email_account
      return unless account

      notice = yield
      raw = notice.to_s
      verdict = scan_verdict(raw)
      if verdict && verdict[:status] == "infected"
        EmailMessage.deliver_raw(account.quarantine_mailbox, raw, authenticated_as: notice.from&.first,
                                 scan_status: verdict[:status], virus_name: verdict[:virus])
        Rails.logger.warn "[mail_on_rails] quarantined infected DSN for #{account.email} (#{verdict[:virus]})"
      else
        EmailMessage.deliver_raw(account.inbox, raw, authenticated_as: notice.from&.first,
                                 scan_status: verdict&.dig(:status))
      end
    rescue StandardError => e
      Rails.logger.error "[mail_on_rails] DSN generation failed for outbound #{message.id}: #{e.class}: #{e.message}"
    end

    def scan_verdict(raw)
      return unless MailOnRails::ClamavScanner.enabled?

      result = MailOnRails::ClamavScanner.scan(raw)
      { status: result.infected? ? "infected" : (result.clean? ? "clean" : "unscanned"),
        virus: result.virus }
    end
  end
end
