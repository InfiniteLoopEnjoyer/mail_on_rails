# Imports the Spamhaus DROP list ("Don't Route Or Peer": hijacked and
# criminal-controlled netblocks, free to download and redistribute) into
# BannedIp, so those ranges ride the same enforcement path as manual bans
# - the accept-side denylist the SMTP and IMAP listeners poll, plus the
# web login check. The list is small (hundreds of CIDRs) and changes
# slowly; SpamhausDropRefreshJob runs this daily.
#
# DROP is deliberately narrow - it will not list a random botnet member
# brute-forcing IMAP; those still get banned by hand from the auth
# attempts page.
module MailOnRails
  class SpamhausDrop
    class FetchError < StandardError; end

    SOURCES = %w[
      https://www.spamhaus.org/drop/drop_v4.json
      https://www.spamhaus.org/drop/drop_v6.json
    ].freeze

    HTTP_TIMEOUT = 20
    # DROP v4+v6 are hundreds of KB today; 10 MB is generous headroom
    # without letting a hostile or misbehaving endpoint stream unbounded
    # bytes into the refresh job's memory.
    MAX_BODY_BYTES = 10 * 1024 * 1024

    # (injectable for tests, DnsPublisher-style)
    DEFAULT_FETCH = ->(url) { fetch_capped(url) }

    # Streams the response with timeouts and a hard byte cap. Net::HTTP#get
    # buffers the whole body before any size check runs, so a slow or
    # oversized endpoint could exhaust the worker; reading in chunks lets
    # the cap abort mid-stream.
    def self.fetch_capped(url, limit: MAX_BODY_BYTES)
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = HTTP_TIMEOUT
      http.read_timeout = HTTP_TIMEOUT
      http.max_retries = 0
      body = +""
      http.request_get(uri.request_uri) do |response|
        unless response.is_a?(Net::HTTPSuccess)
          raise FetchError, "Spamhaus DROP fetch failed: #{url} returned #{response.code}"
        end

        response.read_body do |chunk|
          body << chunk
          raise FetchError, "Spamhaus DROP body from #{url} exceeded #{limit} bytes" if body.bytesize > limit
        end
      end
      body
    rescue Timeout::Error, IOError, SystemCallError, SocketError, OpenSSL::SSL::SSLError, Net::ProtocolError => e
      raise FetchError, "Spamhaus DROP fetch failed: #{url} (#{e.class}: #{e.message})"
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
        # MySQL rejects unique_by but its plain insert_all already skips
        # duplicate-key rows, so the conflict target goes only where it is
        # supported.
        BannedIp.insert_all(
          cidrs.map { |cidr| { cidr: cidr, source: "spamhaus_drop", created_at: now, updated_at: now } },
          **(BannedIp.connection.supports_insert_conflict_target? ? { unique_by: :cidr } : {})
        )
        # The auth attempts page reads "refreshed X ago" off updated_at.
        BannedIp.spamhaus_drop.update_all(updated_at: now)
      end
      # insert_all/delete_all skip callbacks, so poke any same-process
      # listeners explicitly, like BannedIp's after_commit would have.
      MailOnRails.refresh_denylists
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
end
