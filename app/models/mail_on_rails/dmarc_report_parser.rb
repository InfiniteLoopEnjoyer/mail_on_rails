require "zlib"
require "stringio"

# Turns one DMARC aggregate report attachment (RFC 7489: .zip from most
# reporters, .xml.gz from some, bare .xml occasionally) into DmarcReport
# rows. Ingestion is idempotent per (domain, reporter, report_id) -
# reporters re-send reports, and a report is replaced wholesale rather
# than duplicated. Payloads that aren't aggregate reports (or are about a
# domain we don't host) are skipped, never raised - ingestion runs against
# whatever lands in a dmarc@ mailbox.
module MailOnRails
  class DmarcReportParser
    # Zip-bomb guard: a legitimate aggregate report is a few KB to a few MB.
    MAX_XML_BYTES = 20.megabytes
    # Entry-count guard: glob touches every central-directory entry, and a
    # central-directory record costs the sender ~46 bytes, so a small zip
    # can declare hundreds of thousands of entries. A real report archive
    # holds one file.
    MAX_ZIP_ENTRIES = 100
    # Row-count guard: the payload is attacker-influenced even behind the
    # sender-verified gate, and one report must not be able to insert an
    # unbounded number of rows. Real reports carry a few dozen records.
    MAX_RECORDS = 10_000

    def self.ingest(bytes, filename: nil)
      new(bytes, filename: filename).ingest
    end

    def initialize(bytes, filename: nil)
      @bytes = bytes.to_s.b
      @filename = filename.to_s
    end

    # Returns the number of DmarcReport rows written, or nil when the
    # payload was not an ingestable report.
    def ingest
      xml = extract_xml
      return nil if xml.blank?

      # Explicit parse options rather than library defaults: nonet must
      # hold (attacker-supplied XML must never trigger network fetches)
      # and noent must stay off (no entity expansion) even if a future
      # Nokogiri changes its defaults.
      feedback = Nokogiri::XML(xml) { |config| config.nonet.noblanks }.at_xpath("/feedback")
      return nil unless feedback

      domain_name = feedback.at_xpath("policy_published/domain")&.text.to_s.strip.downcase
      domain = Domain.find_by(name: domain_name)
      unless domain
        Rails.logger.info "[mail_on_rails] dmarc report for unhosted domain #{domain_name.inspect} skipped"
        return nil
      end

      # Truncations bound what a hostile-but-verified reporter can store
      # (the string columns have no database-side limit).
      reporter = feedback.at_xpath("report_metadata/org_name")&.text.to_s.strip.truncate(200)
      report_id = feedback.at_xpath("report_metadata/report_id")&.text.to_s.strip.truncate(200)
      begin_at = epoch(feedback.at_xpath("report_metadata/date_range/begin")&.text)
      end_at = epoch(feedback.at_xpath("report_metadata/date_range/end")&.text)
      return nil if reporter.blank? || report_id.blank? || begin_at.nil? || end_at.nil?

      rows = feedback.xpath("record").first(MAX_RECORDS).filter_map do |record|
        source_ip = record.at_xpath("row/source_ip")&.text.to_s.strip
        next if source_ip.blank?

        { domain_id: domain.id, reporter: reporter, report_id: report_id,
          begin_at: begin_at, end_at: end_at, source_ip: source_ip.truncate(45),
          count: record.at_xpath("row/count")&.text.to_i.clamp(1, 10_000_000),
          disposition: record.at_xpath("row/policy_evaluated/disposition")&.text.to_s.strip.truncate(32).presence,
          dkim: record.at_xpath("row/policy_evaluated/dkim")&.text.to_s.strip.downcase.truncate(16).presence,
          spf: record.at_xpath("row/policy_evaluated/spf")&.text.to_s.strip.downcase.truncate(16).presence }
      end
      return nil if rows.empty?

      DmarcReport.transaction do
        DmarcReport.where(domain: domain, reporter: reporter, report_id: report_id).delete_all
        now = Time.current
        DmarcReport.insert_all!(rows.map { |row| row.merge(created_at: now, updated_at: now) })
      end
      Rails.logger.info "[mail_on_rails] ingested dmarc report #{reporter}/#{report_id} for #{domain.name} (#{rows.size} rows)"
      rows.size
    end

    private

    # Sniff by content, not filename - reporters are sloppy with names.
    def extract_xml
      if @bytes.start_with?("PK\x03\x04")
        unzip
      elsif @bytes.start_with?("\x1f\x8b".b)
        gunzip
      elsif @bytes.lstrip.start_with?("<")
        @bytes[0, MAX_XML_BYTES]
      end
    rescue Zip::Error, Zlib::Error => e
      Rails.logger.warn "[mail_on_rails] dmarc attachment #{@filename.inspect} unreadable: #{e.class}: #{e.message}"
      nil
    end

    def unzip
      Zip::File.open_buffer(StringIO.new(@bytes)) do |zip|
        return nil if zip.entries.size > MAX_ZIP_ENTRIES

        entry = zip.glob("*.xml").first || zip.entries.first
        return nil unless entry
        # entry.size is the central directory's claim, so it only serves as
        # a quick skip - the read cap below is the enforced bound.
        return nil if entry.size > MAX_XML_BYTES

        return entry.get_input_stream.read(MAX_XML_BYTES)
      end
    end

    def gunzip
      Zlib::GzipReader.new(StringIO.new(@bytes)).read(MAX_XML_BYTES)
    end

    def epoch(text)
      value = text.to_s.strip
      Time.zone.at(Integer(value)) if value.match?(/\A\d+\z/)
    end
  end
end
