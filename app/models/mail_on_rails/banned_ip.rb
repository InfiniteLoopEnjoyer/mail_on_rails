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

    scope :manual, -> { where(source: "manual") }
    scope :spamhaus_drop, -> { where(source: "spamhaus_drop") }
    scope :auth_failure, -> { where(source: "auth_failure") }
    scope :protocol_abuse, -> { where(source: "protocol_abuse") }
    scope :idle_scanner, -> { where(source: "idle_scanner") }
    # Bans a person can lift on the auth attempts page (DROP rows come back
    # on the next import).
    scope :removable, -> { where.not(source: "spamhaus_drop") }

    before_validation :normalize_cidr

    validates :cidr, presence: true, uniqueness: true
    validates :source, inclusion: { in: SOURCES }
    validate :cidr_must_parse
    validate :cidr_not_too_broad, unless: -> { source == "spamhaus_drop" }

    after_commit :refresh_denylists

    class << self
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
      # included. Best-effort - a listener thread calls this, and the
      # login refusal it follows must never fail on the bookkeeping.
      # Returns the new row, or nil when nothing was banned.
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
      # thread is underneath this). Returns the new row, or nil when the
      # address was already covered or nothing could be written.
      def auto_ban_for_probe(ip:, protocol:, trigger:, signature: nil)
        return if ip.blank?
        return if covering(ip)

        create_auto_ban(ip, source: "protocol_abuse", note: probe_ban_note(protocol, trigger, signature))
      rescue StandardError => e
        auto_ban_failed(ip, e)
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
      # address we can't read is an address we can't match). Loads the whole
      # table; bans are a small set and this only runs on admin pages and
      # failed-login paths.
      def covering(ip)
        addr = IPAddr.new(ip.to_s)
        # A v4-mapped address (an IPv4 peer seen through a dual-stack
        # socket) is an IPv4 ban's business.
        addr = addr.native if addr.ipv4_mapped?
        all.detect { |ban| ban.covers_addr?(addr) }
      rescue IPAddr::Error
        nil
      end

      # Canonical form: bare address for host entries (/32, /128), otherwise
      # the masked network with its prefix - so "1.2.3.4/24" and "1.2.3.0/24"
      # can't coexist as distinct rows. Raises IPAddr::Error on garbage.
      def canonicalize(input)
        addr = IPAddr.new(input.to_s.strip)
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
      # the throttles (the address for IPv4, the /64 for IPv6).
      def create_auto_ban(ip, source:, note:)
        row = create!(cidr: Netserv.throttle_key(ip), source: source, note: note)
        MailOnRails.logger.warn("[mail_on_rails] auto-banned #{row.cidr}: #{row.note}")
        row
      rescue ActiveRecord::RecordNotUnique
        nil # another edge banned it first
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
