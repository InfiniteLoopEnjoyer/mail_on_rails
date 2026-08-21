# Evaluates one sender domain's BIMI indicator (see BimiIndicator) off
# the request path - the webmail enqueues this lazily the first time it
# wants a domain's logo and daily thereafter. The freshness re-check
# absorbs the duplicate enqueues racing readers produce.
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
