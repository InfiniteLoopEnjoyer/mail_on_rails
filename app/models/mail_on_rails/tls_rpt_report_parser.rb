require "zlib"
require "stringio"

# Turns one TLS-RPT aggregate report attachment (RFC 8460: .json.gz from
# most reporters, bare .json occasionally, .zip from the sloppy ones)
# into TlsRptReport rows - one per policy block about a domain we host.
# Ingestion is idempotent per (domain, reporter, report_id): reporters
# re-send reports, and a report is replaced wholesale rather than
# duplicated. Payloads that aren't TLS reports (or are about domains we
# don't host) are skipped, never raised - ingestion runs against
# whatever lands in a tls-rpt@ mailbox.
#
# The payload is attacker-influenced even behind the sender-verified
# gate (IngestTlsRptReportJob), so every dimension is bounded:
# decompressed size, JSON nesting depth, policies per report, failure
# details per policy, session counts, and string lengths.
module MailOnRails
  class TlsRptReportParser
    # Decompression-bomb guard: a legitimate report is a few hundred bytes
    # to a few KB of JSON.
    MAX_JSON_BYTES = 5.megabytes
    # A legitimate report nests 4 levels deep.
    MAX_JSON_DEPTH = 20
    # Entry-count guard: glob touches every central-directory entry, and a
    # central-directory record costs the sender ~46 bytes, so a small zip
    # can declare hundreds of thousands of entries. A real report archive
    # holds one file.
    MAX_ZIP_ENTRIES = 100
    MAX_POLICIES = 100
    MAX_FAILURE_DETAILS = 50
    MAX_COUNT = 10_000_000
    # RFC 8460 section 4.3; anything else is stored as "other" so a hostile
    # value never reaches the UI or groupings verbatim.
    POLICY_TYPES = %w[tlsa sts no-policy-found].freeze

    def self.ingest(bytes, filename: nil)
      new(bytes, filename: filename).ingest
    end

    def initialize(bytes, filename: nil)
      @bytes = bytes.to_s.b
      @filename = filename.to_s
    end

    # Returns the number of TlsRptReport rows written, or nil when the
    # payload was not an ingestable report.
    def ingest
      report = parse_json
      return nil unless report.is_a?(Hash)

      reporter = str(report["organization-name"], 200)
      report_id = str(report["report-id"], 200)
      range = report["date-range"]
      range = {} unless range.is_a?(Hash)
      begin_at = time(range["start-datetime"])
      end_at = time(range["end-datetime"])
      return nil if reporter.blank? || report_id.blank? || begin_at.nil? || end_at.nil?

      policies = report["policies"]
      return nil unless policies.is_a?(Array)

      rows = policies.first(MAX_POLICIES).filter_map { |block| policy_row(block) }
      return nil if rows.empty?

      TlsRptReport.transaction do
        TlsRptReport.where(domain_id: rows.map { |row| row[:domain_id] }.uniq,
                           reporter: reporter, report_id: report_id).delete_all
        now = Time.current
        TlsRptReport.insert_all!(rows.map do |row|
          row.merge(reporter: reporter, report_id: report_id, begin_at: begin_at, end_at: end_at,
                    created_at: now, updated_at: now)
        end)
      end
      Rails.logger.info "[mail_on_rails] ingested tls-rpt report #{reporter}/#{report_id} (#{rows.size} rows)"
      rows.size
    end

    private

    def policy_row(block)
      return nil unless block.is_a?(Hash)

      policy = block["policy"]
      return nil unless policy.is_a?(Hash)

      domain_name = str(policy["policy-domain"], 253).to_s.downcase
      domain = Domain.find_by(name: domain_name)
      unless domain
        Rails.logger.info "[mail_on_rails] tls-rpt policy for unhosted domain #{domain_name.inspect} skipped"
        return nil
      end

      summary = block["summary"]
      summary = {} unless summary.is_a?(Hash)
      { domain_id: domain.id,
        policy_type: POLICY_TYPES.include?(policy["policy-type"]) ? policy["policy-type"] : "other",
        success_count: count(summary["total-successful-session-count"]),
        failure_count: count(summary["total-failure-session-count"]),
        failure_details: failure_details(block["failure-details"]) }
    end

    def failure_details(list)
      return [] unless list.is_a?(Array)

      list.first(MAX_FAILURE_DETAILS).filter_map do |detail|
        next unless detail.is_a?(Hash)

        { "result_type" => str(detail["result-type"], 64) || "unknown",
          "count" => count(detail["failed-session-count"]).clamp(1, MAX_COUNT),
          "receiving_mx" => str(detail["receiving-mx-hostname"], 253),
          "sending_mta_ip" => str(detail["sending-mta-ip"], 45) }.compact
      end
    end

    def parse_json
      json = extract_json
      return nil if json.blank?

      JSON.parse(json.force_encoding(Encoding::UTF_8).scrub, max_nesting: MAX_JSON_DEPTH)
    rescue JSON::ParserError => e
      Rails.logger.warn "[mail_on_rails] tls-rpt attachment #{@filename.inspect} unparseable: #{e.class}: #{e.message}"
      nil
    end

    # Sniff by content, not filename - reporters are sloppy with names. An
    # over-limit payload comes back truncated and fails JSON parsing, which
    # is the rejection we want.
    def extract_json
      if @bytes.start_with?("PK\x03\x04")
        unzip
      elsif @bytes.start_with?("\x1f\x8b".b)
        gunzip
      elsif @bytes.lstrip.start_with?("{")
        @bytes[0, MAX_JSON_BYTES]
      end
    rescue Zip::Error, Zlib::Error => e
      Rails.logger.warn "[mail_on_rails] tls-rpt attachment #{@filename.inspect} unreadable: #{e.class}: #{e.message}"
      nil
    end

    def unzip
      Zip::File.open_buffer(StringIO.new(@bytes)) do |zip|
        return nil if zip.entries.size > MAX_ZIP_ENTRIES

        entry = zip.glob("*.json").first || zip.entries.first
        return nil unless entry
        # entry.size is the central directory's claim, so it only serves as
        # a quick skip - the read cap below is the enforced bound.
        return nil if entry.size > MAX_JSON_BYTES

        return entry.get_input_stream.read(MAX_JSON_BYTES)
      end
    end

    def gunzip
      Zlib::GzipReader.new(StringIO.new(@bytes)).read(MAX_JSON_BYTES)
    end

    def str(value, max)
      value.to_s.scrub.strip.truncate(max).presence if value.is_a?(String)
    end

    def count(value)
      return 0 unless value.is_a?(Numeric) || value.is_a?(String)

      value.to_i.clamp(0, MAX_COUNT)
    end

    def time(value)
      Time.zone.iso8601(value) if value.is_a?(String)
    rescue ArgumentError
      nil
    end
  end
end
