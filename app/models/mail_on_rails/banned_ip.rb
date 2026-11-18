# A permanent IP/CIDR ban, created from the auth attempts page, imported
# from the Spamhaus DROP list, or written automatically: with auth_auto_ban
# on, for the source of a failed SMTP/IMAP login; with protocol_auto_ban on,
# for the source of a honeypot probe hit (HTTP at a mail port, garbage
# bytes, an exploit payload); with idle_auto_ban on, for an address that
# keeps connecting and never does any mail work (census scanners, banner
# and certificate grabbers). AuthThrottle already blocks brute-force
# sources automatically, but only for minutes at a time; this is "and stay
# out" - rows persist until deleted from the UI.
#
# Enforcement is deliberately spread over every surface a banned address
# can reach: the in-process SMTP and IMAP listeners drop matching
# connections in their accept loops (Netserv::Denylist, which polls this
# table through the stores' banned_cidrs and is refreshed immediately by
# the after_commit below), and SessionsController checks `covering`
# before the web login. None of those readers restart.
require "mail_on_rails/netserv/ip"
require "mail_on_rails/sender_auth/confirmed_ptr"

module MailOnRails
  class BannedIp < Record
    SOURCES = %w[manual spamhaus_drop auth_failure protocol_abuse idle_scanner].freeze
    # The sources a setting writes rather than a person.
    AUTOMATIC_SOURCES = %w[auth_failure protocol_abuse idle_scanner].freeze

    # How long after an address reaches the idle threshold the ban is
    # decided (IdleBanJob). A mail client's account setup bare-connects
    # every port it might use seconds BEFORE the first login; the wait
    # lets that login land, so the history guard sees it. It also takes
    # the blocking reverse-DNS lookup off the connection thread.
    IDLE_BAN_GRACE = 10.minutes

    # Below these prefix lengths a typo bans most of the internet
    # (0.0.0.0/0-class mistakes); a deliberate /8 is already 16M addresses.
    # Imported DROP rows are exempt - Spamhaus lists what it lists.
    MIN_IPV4_PREFIX = 8
    MIN_IPV6_PREFIX = 32

    # Automatic /64 bans inside one /48 before they are replaced by a ban
    # on the /48. A /48 is what one site is assigned (RFC 6177) and what a
    # tunnel broker hands anyone for free: its holder has 65,536 /64s to
    # be banned from one at a time. Set high because some providers carve
    # customer /64s out of a shared /48 - this many separately banned
    # sources in one is an operator, not a coincidence.
    COLLAPSE_THRESHOLD = 256
    COLLAPSE_PREFIX = 48

    # Ceiling on automatic rows altogether (an attacker with many /48s, or
    # a spread of IPv4 addresses, is not stopped by the collapse). Past it
    # the oldest automatic rows are dropped: every listener holds the list
    # in memory and the admin pages list it, and an old automatic ban is
    # the one most likely to sit on a reassigned address by now. A source
    # that comes back earns its ban again on the first offence.
    AUTOMATIC_ROWS_MAX = 20_000

    scope :manual, -> { where(source: "manual") }
    scope :spamhaus_drop, -> { where(source: "spamhaus_drop") }
    scope :auth_failure, -> { where(source: "auth_failure") }
    scope :protocol_abuse, -> { where(source: "protocol_abuse") }
    scope :idle_scanner, -> { where(source: "idle_scanner") }
    # Bans a person can lift on the auth attempts page (DROP rows come back
    # on the next import).
    scope :removable, -> { where.not(source: "spamhaus_drop") }
    scope :automatic, -> { where(source: AUTOMATIC_SOURCES) }

    before_validation :normalize_cidr

    validates :cidr, presence: true, uniqueness: true
    validates :source, inclusion: { in: SOURCES }
    validate :cidr_must_parse
    validate :cidr_not_too_broad, unless: -> { source == "spamhaus_drop" }

    after_commit :refresh_denylists

    class << self
      def collapse_threshold = COLLAPSE_THRESHOLD
      def automatic_rows_max = AUTOMATIC_ROWS_MAX

      def auto_ban? = MailOnRails::Settings[:auth_auto_ban]
      def auto_ban_failures = MailOnRails::Settings[:auth_auto_ban_failures]

      # The automatic ban behind the auth_auto_ban setting, called by the
      # stores after every failed credential check (AuthThrottle has
      # already counted it). Once the address's failures in the live
      # window reach auth_auto_ban_failures it gets a permanent row - the
      # same kind a manual ban writes, so every listener drops it from the
      # next accept and its live sessions on the next ops tick. Keyed like
      # the throttle (the address for IPv4, the /64 for IPv6) so a v6
      # guesser cannot rotate inside its prefix. Deliberately no
      # exceptions: the operator chose "anyone", their own devices
      # included - with the one carve-out every automatic ban shares, a
      # local address (see create_auto_ban). Best-effort - a listener
      # thread calls this, and the login refusal it follows must never
      # fail on the bookkeeping. Returns the new row, or nil when nothing
      # was banned.
      def auto_ban_after_failure(ip:, email: nil, source: nil, now: Time.current)
        return unless auto_ban? && ip.present?
        return if AuthThrottle.ip_failures(ip, now: now) < auto_ban_failures
        return if covering(ip)

        create_auto_ban(ip, source: "auth_failure", note: auto_ban_note(email, source))
      rescue StandardError => e
        auto_ban_failed(ip, e)
      end

      # "auto: failed imap login as bob@example.test" - the username is
      # attacker-supplied, so it is reduced to printable characters and
      # cut short before it lands on the admin page.
      def auto_ban_note(email, source)
        note = "auto: failed #{source.presence || 'mail'} login"
        user = email.to_s.gsub(/[^[:graph:]]/, "")[0, 80]
        note += " as #{user}" unless user.empty?
        note
      end

      # The automatic ban behind the protocol_auto_ban setting, called from
      # HoneypotEvent's response for a probe-type trigger. The setting
      # check stays with the caller so the event's response column can say
      # what happened. Same permanent row and throttle keying as
      # auto_ban_after_failure, same best-effort discipline (a listener
      # thread is underneath this) - and the collateral checks
      # auto_ban_for_idle makes (probe_ban_exemption): a probe signature
      # is a regex, and RFC-legal mail can match it (a quoted local-part
      # like "${run{...}}"@ relayed by a third party's MX), so the source
      # is left alone when it is a local address or has done real mail
      # work lately. The event itself is recorded either way. Returns the
      # new row, or nil when the address was exempt, already covered or
      # nothing could be written.
      def auto_ban_for_probe(ip:, protocol:, trigger:, signature: nil, now: Time.current)
        return if ip.blank?
        return if probe_ban_exemption(ip, now: now)
        return if covering(ip)

        create_auto_ban(ip, source: "protocol_abuse", note: probe_ban_note(protocol, trigger, signature))
      rescue StandardError => e
        auto_ban_failed(ip, e)
      end

      # Why a probe-type hit from +ip+ must not become a permanent ban, as
      # a short phrase for the event's response column, or nil when it
      # may: a local address (behind a proxy or bridge it is every
      # client), or one that logged in or delivered mail within
      # honeypot_collateral_days - closed connections and open ones alike,
      # the same two checks the idle ban makes. The PTR exemption the
      # idle ban also has is deliberately not repeated here: that lookup
      # blocks, and this runs on the connection thread that just tripped
      # the probe (the idle ban defers to a job for exactly that reason).
      def probe_ban_exemption(ip, now: Time.current)
        return "local address" if Netserv.local?(ip)

        since = now - HoneypotEvent.collateral_days.days
        return "shared address" if ClosedConnection.worked_from?(ip, since: since) || OpenConnection.working_from?(ip)

        nil
      end

      # "auto: http request on smtp". The trigger and signature are our own
      # names (ProbeSignatures), never attacker bytes. A TLS handshake is the
      # one shape a misconfigured real client also produces, so its note
      # says so - that row is the one an operator may want to lift.
      def probe_ban_note(protocol, trigger, signature)
        what = (signature.presence || trigger).to_s.tr("_", " ")
        note = "auto: #{what} on #{protocol}"
        note += " (a mail client on the wrong port or security type looks like this)" if signature == "tls_handshake"
        note
      end

      def idle_auto_ban? = MailOnRails::Settings[:idle_auto_ban]
      def idle_auto_ban_sessions = MailOnRails::Settings[:idle_auto_ban_sessions]
      def idle_auto_ban_window = MailOnRails::Settings[:idle_auto_ban_window]

      # The first half of the idle_auto_ban setting, called by the stores
      # after ClosedConnection has recorded a connection that did no mail
      # work (see Server#idle_reason for the shapes). Bans nothing itself:
      # one quiet connection is what a big sender's spare socket, a TLS
      # tester and a phone between networks all look like, so the signal
      # is repetition - and even then the decision waits IDLE_BAN_GRACE
      # (see there) in IdleBanJob. Cheap checks only; a dying connection
      # thread is underneath this, and like every automatic ban it is
      # best-effort. Returns true when a decision was scheduled.
      #
      # Scheduled across the whole first band of strikes past the
      # threshold, then on every multiple: five ports swept at once close
      # concurrently and can step over any single exact count, while a
      # source hammering away for the full grace must not queue a job per
      # connection. The job is idempotent.
      def idle_strike(ip:, protocol:, reason:, now: Time.current)
        return false unless (strikes = idle_strikes_due(ip, now))

        threshold = idle_auto_ban_sessions
        return false unless strikes < threshold * 2 || (strikes % threshold).zero?

        IdleBanJob.set(wait: IDLE_BAN_GRACE).perform_later(ip.to_s, protocol.to_s, reason.to_s)
        true
      rescue StandardError => e
        auto_ban_failed(ip, e)
        false
      end

      # The second half, run by IdleBanJob once the grace has passed: the
      # cheap checks again (the setting, the allowlist or the window may
      # have moved on), then the two that say "this is not a scanner":
      #
      #   - the address logged in or delivered mail within
      #     honeypot_collateral_days, or is doing so right now - a real
      #     client or a real MX whose other connections went quiet;
      #   - its forward-confirmed reverse DNS falls under
      #     idle_auto_ban_exempt_ptr - a big sender's spare connection, a
      #     TLS tester. Confirmed names only: a bare PTR is the scanner's
      #     own to write. A resolver failure means no ban THIS time; a
      #     scanner comes back, and the next strike asks again.
      #
      # Same permanent row and throttle keying as the other automatic
      # bans. Returns the new row, or nil when nothing was banned.
      def auto_ban_for_idle(ip:, protocol:, reason:, now: Time.current, resolver: SenderAuth::Dns.shared)
        return unless (strikes = idle_strikes_due(ip, now))

        since = now - HoneypotEvent.collateral_days.days
        return if ClosedConnection.worked_from?(ip, since: since) || OpenConnection.working_from?(ip)
        return if idle_exempt_ptr?(ip, resolver)

        create_auto_ban(ip, source: "idle_scanner", note: idle_ban_note(strikes, protocol, reason))
      rescue SenderAuth::Dns::TempError => e
        MailOnRails.logger.info("[mail_on_rails] idle ban of #{ip} put off: #{e.message}")
        nil
      rescue StandardError => e
        auto_ban_failed(ip, e)
      end

      # "auto: 3 idle sessions in 24h (last: tls only on smtp)" - the reason
      # and protocol are our own names, never peer bytes. A failed TLS
      # handshake is the one shape every real client produces too once the
      # certificate has expired or the client is set to the wrong security
      # type, so its note says so - that row is the one an operator may
      # want to lift.
      def idle_ban_note(strikes, protocol, reason)
        note = "auto: #{strikes} idle sessions in #{idle_window_words} " \
               "(last: #{reason.to_s.tr('_', ' ')} on #{protocol})"
        if reason.to_s == "tls_handshake_failed"
          note += " - an expired certificate or a mail client on the wrong security type looks like this"
        end
        note
      end

      # The ban covering +ip+, or nil (also nil for unparseable input - an
      # address we can't read is an address we can't match); the broadest
      # one when several do. This runs on every failed login and before
      # every web sign-in, against a table strangers can add to, so it
      # never reads the table: rows are stored in canonical form
      # (canonicalize, on every write path), which makes "is there a row
      # for one of the networks containing this address" a lookup of at
      # most 129 exact strings in the unique cidr index.
      def covering(ip)
        addr = IPAddr.new(ip.to_s)
        # A v4-mapped address (an IPv4 peer seen through a dual-stack
        # socket) is an IPv4 ban's business.
        addr = addr.native if addr.ipv4_mapped?
        where(cidr: containing_cidrs(addr)).select { |ban| ban.covers_addr?(addr) }
                                           .min_by { |ban| ban.network.prefix }
      rescue IPAddr::Error
        nil
      end

      # Every network that contains +addr+ (an address or a range), one per
      # prefix length, spelled the way a row for it would be stored.
      def containing_cidrs(addr)
        full = addr.ipv4? ? 32 : 128
        (0..addr.prefix).map do |prefix|
          net = addr.mask(prefix)
          prefix == full ? net.to_s : "#{net}/#{prefix}"
        end
      end

      # Canonical form: bare address for host entries (/32, /128), otherwise
      # the masked network with its prefix - so "1.2.3.4/24" and "1.2.3.0/24"
      # can't coexist as distinct rows. A v4-mapped spelling ("::ffff:1.2.3.4",
      # "::ffff:1.2.3.0/120") is stored as the IPv4 it names: peers are
      # unmapped on every surface, so a row kept in the mapped form would
      # never match anything. Raises IPAddr::Error on garbage.
      def canonicalize(input)
        addr = IPAddr.new(input.to_s.strip)
        addr = addr.native if addr.ipv4_mapped?
        full = addr.ipv4? ? 32 : 128
        addr.prefix == full ? addr.to_s : "#{addr}/#{addr.prefix}"
      end
    end

    def network
      @network ||= IPAddr.new(cidr)
    rescue IPAddr::Error
      nil
    end

    def covers_addr?(addr)
      net = network
      addr = addr.native if addr.ipv4_mapped?
      !net.nil? && net.ipv4? == addr.ipv4? && net.include?(addr)
    end

    class << self
      private

      # The address's idle strikes when the cheap idle_auto_ban checks all
      # pass and the threshold is met, otherwise nil. A local address is
      # never a candidate: behind a userland proxy every client arrives as
      # the bridge gateway, and that one ban would cover them all.
      def idle_strikes_due(ip, now)
        return nil unless idle_auto_ban? && ip.present?
        return nil if Netserv.local?(ip) || HoneypotEvent.allowlisted?(ip)

        strikes = ClosedConnection.idle_strikes(ip, since: now - idle_auto_ban_window)
        return nil if strikes < idle_auto_ban_sessions || covering(ip)

        strikes
      end

      def idle_exempt_ptr?(ip, resolver)
        suffixes = MailOnRails::Settings[:idle_auto_ban_exempt_ptr]
                     .map { |entry| entry.to_s.downcase.strip.delete_prefix(".") }.reject(&:empty?)
        return false if suffixes.empty?

        name = SenderAuth::ConfirmedPtr.names(ip, resolver: resolver).find do |ptr|
          suffixes.any? { |entry| ptr == entry || ptr.end_with?(".#{entry}") }
        end
        MailOnRails.logger.info("[mail_on_rails] idle ban of #{ip} skipped: #{name} is exempt") if name
        !name.nil?
      end

      def idle_window_words
        seconds = idle_auto_ban_window
        return "#{seconds / 3600}h" if (seconds % 3600).zero?

        (seconds % 60).zero? ? "#{seconds / 60}m" : "#{seconds}s"
      end

      # The tail every automatic ban shares: the permanent row, keyed like
      # the throttles (the address for IPv4, the /64 for IPv6). Never for
      # a local address, whatever the setting (idle_strikes_due screens
      # those earlier; this is the backstop for the auth and probe paths):
      # behind a userland proxy, a TCP load balancer without proxy
      # protocol or a Docker bridge without ip6tables, every client
      # arrives as the gateway address, and that one row would ban them
      # all. Loud, because the failure that led here was real and the
      # operator should know their listener sits behind such a hop.
      def create_auto_ban(ip, source:, note:)
        if Netserv.local?(ip)
          MailOnRails.logger.warn("[mail_on_rails] refusing to auto-ban local address #{ip} (#{source}: #{note}) - " \
                                  "behind a proxy or bridge that address is every client; ban by hand if it is " \
                                  "really one machine")
          return nil
        end

        row = create!(cidr: Netserv.throttle_key(ip), source: source, note: note)
        MailOnRails.logger.warn("[mail_on_rails] auto-banned #{row.cidr}: #{row.note}")
        bound_automatic_rows(row) || row
      rescue ActiveRecord::RecordNotUnique
        nil # another edge banned it first
      end

      # Keeps the automatic rows bounded after one more was written (see
      # the class comment). Returns the /48 row when +row+ was folded into
      # one, otherwise nil. Best-effort: the ban that led here is already
      # in force, and tidying must not undo it.
      def bound_automatic_rows(row)
        collapsed = collapse_into_prefix(row)
        drop_oldest_automatic_rows
        collapsed
      rescue StandardError => e
        MailOnRails.logger.error("[mail_on_rails] bounding automatic bans failed: #{e.class}: #{e.message}")
        nil
      end

      # Once collapse_threshold automatic /64 bans sit inside +row+'s /48,
      # one automatic ban on the /48 replaces them. Only automatic /64
      # rows are counted and only those are removed - a manual ban inside
      # the /48 stays exactly as its author wrote it - and nothing is
      # widened over a honeypot-allowlisted network. Lifting the /48 row
      # lifts what it replaced.
      def collapse_into_prefix(row)
        net = row.network
        return nil unless net&.ipv6? && net.prefix == 64

        wider = net.mask(COLLAPSE_PREFIX)
        inside = automatic_64s_within(wider)
        return nil if inside.size < collapse_threshold
        return nil if HoneypotEvent.allowlist_networks.any? { |allowed| overlap?(allowed, wider) }

        note = "auto: #{inside.size} banned /64s in this /#{COLLAPSE_PREFIX} folded into one ban " \
               "(last - #{row.note.to_s.delete_prefix('auto: ')})"
        collapsed = transaction do
          where(id: inside.map(&:first)).delete_all
          create!(cidr: "#{wider}/#{COLLAPSE_PREFIX}", source: row.source, note: note.first(255))
        end
        MailOnRails.logger.warn("[mail_on_rails] auto-banned #{collapsed.cidr}: #{collapsed.note}")
        collapsed
      rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
        covering(row.cidr) # another edge folded the same /48 first
      end

      # [ id, cidr ] of the automatic /64 rows inside +wider+. A /64 has no
      # fixed string prefix once its address is compressed, so SQL only
      # narrows (the leading groups that are spelled out in every member,
      # as in HoneypotEvent.cap_scope) and the membership test is exact,
      # in Ruby, over that narrowed set.
      def automatic_64s_within(wider)
        groups = wider.to_string.split(":").first(COLLAPSE_PREFIX / 16)
        leading = groups.take_while { |group| group != "0000" }.map { |group| group.to_i(16).to_s(16) }
        prefix = leading.empty? ? "" : "#{leading.join(':')}:"
        automatic.where(arel_table[:cidr].matches("#{sanitize_sql_like(prefix)}%/64", nil, true))
                 .pluck(:id, :cidr).select do |_id, cidr|
          wider.include?(IPAddr.new(cidr))
        rescue IPAddr::Error
          false
        end
      end

      def overlap?(a, b)
        a.ipv4? == b.ipv4? && (a.include?(b) || b.include?(a))
      end

      def drop_oldest_automatic_rows
        excess = automatic.count - automatic_rows_max
        return unless excess.positive?

        doomed = automatic.order(:created_at, :id).limit(excess).pluck(:id)
        where(id: doomed).delete_all
        MailOnRails.logger.warn("[mail_on_rails] automatic bans over #{automatic_rows_max}: dropped the #{doomed.size} oldest")
        MailOnRails.refresh_denylists
      end

      def auto_ban_failed(ip, error)
        MailOnRails.logger.error("[mail_on_rails] auto-ban of #{ip} failed: #{error.class}: #{error.message}")
        nil
      end
    end

    private

    # Unparseable input is left alone (only stripped) for the format
    # validation to reject with a real message.
    def normalize_cidr
      self.cidr = BannedIp.canonicalize(cidr)
    rescue IPAddr::Error
      self.cidr = cidr.to_s.strip
    end

    def cidr_must_parse
      return if cidr.blank? || network

      errors.add(:cidr, "is not an IP address or CIDR range")
    end

    def cidr_not_too_broad
      net = network
      return if net.nil?

      min = net.ipv4? ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX
      errors.add(:cidr, "is too broad (narrowest allowed is /#{min})") if net.prefix < min
    end

    # The listeners' denylists poll this table anyway (Denylist::TTL), but
    # servers in this very process can pick the change up on the very next
    # connection; a no-server boot no-ops.
    def refresh_denylists
      MailOnRails.refresh_denylists
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_banned_ip, MailOnRails::BannedIp
