# One outbound delivery attempt's TLS outcome, recorded by
# OutboundDeliverer and rolled up into the daily RFC 8460 reports
# (SendTlsRptReportsJob) for recipient domains that publish a TLS-RPT
# policy. result_type nil is a successful session; otherwise it is one of
# the RFC 8460 section 4.3 result types (starttls-not-supported,
# validation-failure, sts-policy-fetch-error, tlsa-invalid, ...).
class TlsRptEvent < ApplicationRecord
  RETENTION = 7.days

  POLICY_TYPES = %w[tlsa sts no-policy-found].freeze

  # Recording is telemetry riding on the delivery path - it must never
  # take a delivery down with it.
  def self.record!(policy_domain:, policy_type:, mx: nil, result_type: nil, detail: nil)
    create!(policy_domain: policy_domain.to_s.downcase, policy_type: policy_type,
            receiving_mx: mx, result_type: result_type,
            failure_detail: detail&.to_s&.scrub&.truncate(200), occurred_at: Time.current)
  rescue StandardError => e
    Rails.logger.error "[mail_on_rails] TLS-RPT event for #{policy_domain} not recorded: #{e.class}: #{e.message}"
    nil
  end

  scope :on_day, ->(date) { where(occurred_at: date.beginning_of_day..date.end_of_day) }
  scope :successes, -> { where(result_type: nil) }
  scope :failures, -> { where.not(result_type: nil) }

  # The write rate is set by outbound volume; reports only ever look one
  # day back, so retention is enforced daily.
  def self.prune!(now: Time.current)
    where("occurred_at <= ?", now - RETENTION).delete_all
  end
end
