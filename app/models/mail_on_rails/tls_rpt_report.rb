# One policy block from an inbound TLS-RPT aggregate report (RFC 8460)
# mailed to a hosted domain's tls-rpt@ account: how many SMTP sessions a
# reporter attempted to our MXs under one policy (sts / tlsa /
# no-policy-found) during the report window, and how many failed to
# negotiate TLS. failure_details is a bounded jsonb array of
# {"result_type", "count", "receiving_mx", "sending_mta_ip"} entries.
# Rows are written by TlsRptReportParser#ingest, idempotently per
# (domain, reporter, report_id). Distinct from TlsRptEvent, which is our
# OUTBOUND per-attempt telemetry about other people's domains.
module MailOnRails
  class TlsRptReport < Record
    belongs_to :domain

    # MySQL JSON columns cannot carry the [] default the other adapters
    # declare in the schema, so the model supplies it uniformly.
    attribute :failure_details, default: -> { [] }

    WINDOW = 30.days
    # Comfortably past the stats window; the raw report mail stays in the
    # tls-rpt@ mailbox regardless.
    RETENTION = 90.days

    scope :recent, -> { where(begin_at: WINDOW.ago..) }

    # Aggregate view of the last 30 days, feeding the domain page's TLS-RPT
    # monitoring section.
    def self.stats(domain)
      rows = recent.where(domain: domain).to_a
      sessions = rows.sum { |row| row.success_count + row.failure_count }
      failed = rows.sum(&:failure_count)
      {
        sessions: sessions,
        failed: failed,
        success_pct: sessions.zero? ? nil : ((sessions - failed) * 100.0 / sessions),
        reporters: rows.map(&:reporter).uniq.size,
        failure_types: rows.flat_map(&:failure_details)
                           .group_by { |detail| detail["result_type"].to_s }
                           .transform_values { |group| group.sum { |detail| detail["count"].to_i } }
                           .sort_by { |_, count| -count }.to_h,
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
