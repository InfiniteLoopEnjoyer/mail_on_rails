# frozen_string_literal: true

module MailOnRails
  # Resolves ASN/country/rDNS for a honeypot event's source IP and writes it
  # back. Runs off the connection thread (enqueued by HoneypotEvent's
  # after_create_commit), so the blocking DNS in CymruLookup never sits on the
  # live protocol path. One lookup per address, not per event: the
  # IpEnrichment cache is consulted first (a scanner's hundredth hit costs no
  # DNS) and filled afterwards. Best-effort: a missing event or a dead
  # resolver just leaves the enrichment nil.
  class HoneypotEnrichmentJob < BaseJob
    queue_as :default
    retry_on StandardError, wait: :polynomially_longer, attempts: 3

    def perform(event_id)
      event = HoneypotEvent.find_by(id: event_id)
      return unless event&.ip.present?

      enrichment = IpEnrichment.cached(event.ip)
      unless enrichment
        enrichment = CymruLookup.lookup(event.ip)
        IpEnrichment.remember(event.ip, enrichment) if enrichment.present?
      end
      event.update_columns(enrichment: enrichment, updated_at: Time.current)
    end
  end
end
