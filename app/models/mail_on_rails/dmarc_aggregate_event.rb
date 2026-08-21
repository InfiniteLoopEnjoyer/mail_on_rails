# One inbound message's DMARC evaluation, recorded by the SMTP session
# (via SmtpBackend#dmarc_event) for every message whose From domain
# publishes a DMARC record, and rolled up into the daily RFC 7489
# aggregate reports (SendDmarcReportsJob) for domains that ask for them
# via rua=. disposition is what this receiver actually applied after
# local-policy overrides (ARC trusted sealer, enforcement disabled);
# override_reason says why it differs from the published policy.
module MailOnRails
  class DmarcAggregateEvent < Record
    RETENTION = 7.days

    DISPOSITIONS = %w[none quarantine reject].freeze

    # Recording is telemetry riding on the acceptance path - it must
    # never take a message down with it.
    def self.record!(policy_domain:, disposition:, from_domain: nil, source_ip: nil, envelope_from: nil,
                     override_reason: nil, dkim_aligned: false, spf_aligned: false,
                     spf_result: nil, spf_domain: nil, dkim_results: nil,
                     policy_p: nil, policy_sp: nil, policy_adkim: nil, policy_aspf: nil, policy_pct: nil)
      create!(policy_domain: policy_domain.to_s.downcase, from_domain: from_domain.to_s.downcase.presence,
              source_ip: source_ip, envelope_from: envelope_from.to_s.scrub.truncate(255).presence,
              disposition: DISPOSITIONS.include?(disposition.to_s) ? disposition.to_s : "none",
              override_reason: override_reason&.to_s&.scrub&.truncate(200),
              dkim_aligned: dkim_aligned, spf_aligned: spf_aligned,
              spf_result: spf_result, spf_domain: spf_domain,
              dkim_results: dkim_results.to_s.scrub.truncate(500).presence,
              policy_p: policy_p, policy_sp: policy_sp,
              policy_adkim: policy_adkim, policy_aspf: policy_aspf, policy_pct: policy_pct,
              occurred_at: Time.current)
    rescue StandardError => e
      Rails.logger.error "[mail_on_rails] DMARC aggregate event for #{policy_domain} not recorded: #{e.class}: #{e.message}"
      nil
    end

    scope :on_day, ->(date) { where(occurred_at: date.beginning_of_day..date.end_of_day) }

    # The write rate is set by inbound volume; reports only ever look one
    # day back, so retention is enforced daily.
    def self.prune!(now: Time.current)
      where("occurred_at <= ?", now - RETENTION).delete_all
    end
  end
end
