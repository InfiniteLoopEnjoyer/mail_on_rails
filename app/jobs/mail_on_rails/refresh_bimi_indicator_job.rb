# Evaluates one sender domain's BIMI indicator (see BimiIndicator). The
# mailroom enqueues this when it files a DMARC-passing message from a
# domain whose indicator is missing or a day old - at delivery, never
# when a message is viewed. The freshness re-check absorbs the duplicate
# enqueues racing deliveries produce.
module MailOnRails
  class RefreshBimiIndicatorJob < BaseJob
    queue_as :default

    def perform(domain)
      return unless MailOnRails::Settings[:bimi]

      row = BimiIndicator.find_by(domain: domain.to_s.strip.downcase)
      return if row&.checked_at && row.checked_at > BimiIndicator::REFRESH_INTERVAL.ago

      row = BimiIndicator.refresh!(domain)
      Rails.logger.info "[mail_on_rails] BIMI indicator for #{row.domain}: #{row.status}" \
                        "#{" (#{row.error})" if row.error.present?}"
    end
  end
end
