# Per-IP attribution cache for the live connection pages: the CymruLookup
# blob (ASN, AS name, country, prefix, reverse DNS) honeypot events store
# per event, cached per address so /smtp and /imap can annotate every IP
# they show without a blocking DNS lookup on the request. Pages call
# ensure_all with the addresses they are about to render: known rows come
# back immediately, unknown or stale ones get a background IpEnrichmentJob
# and fill in on a later refresh (the pages re-render constantly anyway).
module MailOnRails
  class IpEnrichment < Record
    # How long a completed lookup stays fresh. ASN and rDNS move slowly;
    # a week keeps steady-state DNS traffic near zero.
    TTL = 7.days
    # How long an enqueued lookup blocks re-enqueueing. Covers job-queue
    # latency and retries; a lost job re-enqueues after this.
    REQUEST_DEBOUNCE = 15.minutes
    # Upper bound on lookups one ensure_all call may schedule - a page
    # full of never-seen scanner addresses fills in over a few refreshes
    # instead of flooding the queue.
    MAX_REQUESTS_PER_CALL = 20

    validates :ip, presence: true, uniqueness: true

    class << self
      # { ip => enrichment hash } for the addresses already looked up,
      # scheduling background lookups for the rest. Order matters to the
      # caller: earlier ips win the per-call request budget.
      def ensure_all(ips)
        ips = ips.compact.uniq
        return {} if ips.empty?

        rows = where(ip: ips).index_by(&:ip)
        ips.select { |ip| needs_lookup?(rows[ip]) }
           .first(MAX_REQUESTS_PER_CALL)
           .each { |ip| request(ip) }
        rows.filter_map { |ip, row| [ ip, row.enrichment ] if row.enrichment.present? }.to_h
      end

      def prune!(now: Time.current)
        where(updated_at: ...(now - 30.days)).delete_all
      end

      private

      def needs_lookup?(row)
        return true if row.nil? || row.looked_up_at.nil? || row.looked_up_at < TTL.ago

        false
      end

      # Creates the placeholder row (the unique index arbitrates races -
      # losing a race just means the other request enqueued) and schedules
      # the lookup unless one is already in flight.
      def request(ip)
        row = find_or_create_by!(ip: ip)
        return if row.requested_at && row.requested_at > REQUEST_DEBOUNCE.ago

        row.update_columns(requested_at: Time.current)
        IpEnrichmentJob.perform_later(ip)
      rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
        nil
      end
    end
  end
end
