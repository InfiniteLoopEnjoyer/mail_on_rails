require "mail_on_rails/clamav_scanner"

# Catch-up scanner for authenticated writes that happened while clamd was
# down (recurring, see config/recurring.yml). IMAP APPEND, web import and
# the composer's local copies all fail open by design - refusing every
# authenticated write during a scanner outage punishes the owner, not an
# attacker - and store the message as scan_status "unscanned", which locks
# its attachment downloads. Without this sweep that state was terminal
# unless a human clicked "Scan now" on each message; here every unscanned
# row gets a real verdict once clamav is back.
#
# Verdicts are recorded in place, deliberately not re-filed: unscanned
# rows are either quarantine review copies (already where they belong) or
# the owner's own Sent/Drafts/APPEND writes, which must not be yanked out
# of their mailbox. Mirrors the manual rescan in EmailMessagesController.
module MailOnRails
  class RescanUnscannedMessagesJob < BaseJob
    queue_as :default

    BATCH = 200

    def perform
      return unless MailOnRails::ClamavScanner.enabled?

      EmailMessage.where(scan_status: "unscanned").order(:id).limit(BATCH).each do |message|
        result = MailOnRails::ClamavScanner.scan(message.raw.to_s)
        # Still (or again) down: leave the rest pending for the next run
        # rather than hammering a dead scanner BATCH times.
        break if result.unavailable?

        message.update!(scan_status: result.infected? ? "infected" : "clean",
                        virus_name: result.virus)
        if result.infected?
          Rails.logger.warn "[mail_on_rails] late scan found virus in message #{message.id} (#{result.virus})"
        end
      end
    end
  end
end
