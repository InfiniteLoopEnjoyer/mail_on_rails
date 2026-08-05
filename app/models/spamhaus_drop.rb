# Imports the Spamhaus DROP list ("Don't Route Or Peer": hijacked and
# criminal-controlled netblocks, free to download and redistribute) into
# BannedIp, so those ranges ride the same enforcement path as manual bans
# - the shared banned_ips file for exim and the IMAP daemon, plus the web
# login check. The list is small (hundreds of CIDRs) and changes slowly;
# SpamhausDropRefreshJob runs this daily.
#
# DROP is deliberately narrow - it will not list a random botnet member
# brute-forcing IMAP; those still get banned by hand from the auth
# attempts page.
class SpamhausDrop
  SOURCES = %w[
    https://www.spamhaus.org/drop/drop_v4.json
    https://www.spamhaus.org/drop/drop_v6.json
  ].freeze

  # (injectable for tests, DnsPublisher-style)
  DEFAULT_FETCH = lambda do |url|
    response = Net::HTTP.get_response(URI(url))
    raise "Spamhaus DROP fetch failed: #{url} returned #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    response.body
  end

  def self.refresh!(fetch: DEFAULT_FETCH)
    cidrs = SOURCES.flat_map { |url| parse(fetch.call(url), url) }.uniq

    # A refresh must never wipe the imported rows because of a bad fetch -
    # fetch raised on HTTP errors above, and an empty parse is treated the
    # same way (Spamhaus without a single listed netblock is not a
    # plausible state of the world).
    raise "Spamhaus DROP parsed to an empty list, keeping existing rows" if cidrs.empty?

    now = Time.current
    BannedIp.transaction do
      BannedIp.spamhaus_drop.where.not(cidr: cidrs).delete_all
      # insert_all skips rows whose cidr already exists (imported earlier,
      # or banned manually - the manual row wins and keeps its note).
      BannedIp.insert_all(
        cidrs.map { |cidr| { cidr: cidr, source: "spamhaus_drop", created_at: now, updated_at: now } },
        unique_by: :cidr
      )
      # The auth attempts page reads "refreshed X ago" off updated_at.
      BannedIp.spamhaus_drop.update_all(updated_at: now)
    end
    BannedIpsFile.sync!
    cidrs.size
  end

  # One DROP file: newline-delimited JSON, one {"cidr": ...} object per
  # listed netblock plus copyright/timestamp metadata lines without a
  # cidr key. Entries are canonicalized so they can never collide with a
  # differently-written manual row.
  def self.parse(body, url)
    body.each_line.filter_map do |line|
      cidr = JSON.parse(line)["cidr"] rescue nil
      next if cidr.blank?

      begin
        BannedIp.canonicalize(cidr)
      rescue IPAddr::Error
        Rails.logger.warn("[mail_on_rails] unparseable DROP entry #{cidr.inspect} from #{url}")
        nil
      end
    end
  end
end
