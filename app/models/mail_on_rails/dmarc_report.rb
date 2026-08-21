# One <record> row from a DMARC aggregate report (RFC 7489): how many
# messages one source IP sent as the domain during the report window, and
# whether they passed the ALIGNED dkim/spf checks (policy_evaluated - a
# record passes DMARC when either is "pass"). Rows are written by
# DmarcReportParser#ingest!, idempotently per (reporter, report_id).
module MailOnRails
  class DmarcReport < Record
    belongs_to :domain

    WINDOW = 30.days
    # Comfortably past the stats window; the raw report mail stays in the
    # dmarc@ mailbox regardless.
    RETENTION = 90.days

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
        by_source: rows.group_by(&:source_ip).map do |ip, group|
          { ip: ip,
            count: group.sum(&:count),
            passed: group.select(&:pass?).sum(&:count),
            dkim_passed: group.select { |r| r.dkim == "pass" }.sum(&:count),
            spf_passed: group.select { |r| r.spf == "pass" }.sum(&:count),
            dispositions: group.filter_map(&:disposition).uniq.sort }
        end.sort_by { |source| -source[:count] },
        span_days: rows.empty? ? 0 : ((rows.map(&:end_at).max - rows.map(&:begin_at).min) / 1.day).ceil
      }
    end

    # External reporters set the write rate, so retention is enforced
    # rather than assumed (recurring.yml).
    def self.prune!(now: Time.current)
      where("end_at <= ?", now - RETENTION).delete_all
    end
  end
end
