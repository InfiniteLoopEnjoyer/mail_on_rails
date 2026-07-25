# One <record> row from a DMARC aggregate report (RFC 7489): how many
# messages one source IP sent as the domain during the report window, and
# whether they passed the ALIGNED dkim/spf checks (policy_evaluated - a
# record passes DMARC when either is "pass"). Rows are written by
# DmarcReportParser#ingest!, idempotently per (reporter, report_id).
class DmarcReport < ApplicationRecord
  belongs_to :domain

  WINDOW = 30.days

  scope :recent, -> { where(begin_at: WINDOW.ago..) }

  def pass?
    dkim == "pass" || spf == "pass"
  end

  # Aggregate view of the last 30 days, feeding the domain page's
  # "ready to tighten?" indicator.
  def self.stats(domain)
    rows = recent.where(domain: domain).to_a
    total = rows.sum(&:count)
    passed = rows.select(&:pass?).sum(&:count)
    {
      total: total,
      passed: passed,
      aligned_pct: total.zero? ? nil : (passed * 100.0 / total),
      sources: rows.map(&:source_ip).uniq.size,
      reporters: rows.map(&:reporter).uniq.size,
      failing: rows.reject(&:pass?).group_by(&:source_ip)
                   .transform_values { |group| group.sum(&:count) },
      span_days: rows.empty? ? 0 : ((rows.map(&:end_at).max - rows.map(&:begin_at).min) / 1.day).ceil
    }
  end
end
