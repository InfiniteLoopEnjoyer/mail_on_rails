# frozen_string_literal: true

module MailOnRails
  # Fills one IpEnrichment cache row via CymruLookup - the same DNS-only
  # attribution the honeypot enrichment uses, off the request path.
  # Best-effort: a vanished row or a dead resolver leaves the cache blank
  # (looked_up_at still advances, so a broken resolver is retried on the
  # TTL clock, not on every page view).
  class IpEnrichmentJob < BaseJob
    queue_as :default
    retry_on StandardError, wait: :polynomially_longer, attempts: 3

    def perform(ip)
      row = IpEnrichment.find_by(ip: ip)
      return unless row

      row.update_columns(enrichment: CymruLookup.lookup(ip),
                         looked_up_at: Time.current, updated_at: Time.current)
    end
  end
end
