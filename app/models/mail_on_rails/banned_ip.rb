# A permanent IP/CIDR ban, created from the auth attempts page, imported
# from the Spamhaus DROP list, or - with auth_auto_ban switched on -
# written automatically for the source of a failed SMTP/IMAP login.
# AuthThrottle already blocks brute-force sources automatically, but only
# for minutes at a time; this is "and stay out" - rows persist until
# deleted from the UI.
#
# Enforcement is deliberately spread over every surface a banned address
# can reach: the in-process SMTP and IMAP listeners drop matching
# connections in their accept loops (Netserv::Denylist, which polls this
# table through the stores' banned_cidrs and is refreshed immediately by
# the after_commit below), and SessionsController checks `covering`
# before the web login. None of those readers restart.
module MailOnRails
  class BannedIp < Record
    SOURCES = %w[manual spamhaus_drop auth_failure].freeze

    # Below these prefix lengths a typo bans most of the internet
    # (0.0.0.0/0-class mistakes); a deliberate /8 is already 16M addresses.
    # Imported DROP rows are exempt - Spamhaus lists what it lists.
    MIN_IPV4_PREFIX = 8
    MIN_IPV6_PREFIX = 32

    scope :manual, -> { where(source: "manual") }
    scope :spamhaus_drop, -> { where(source: "spamhaus_drop") }
    scope :auth_failure, -> { where(source: "auth_failure") }
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

        row = create!(cidr: Netserv.throttle_key(ip), source: "auth_failure",
                      note: auto_ban_note(email, source))
        MailOnRails.logger.warn("[mail_on_rails] auto-banned #{row.cidr} after failed #{source || 'mail'} login")
        row
      rescue ActiveRecord::RecordNotUnique
        nil # another edge banned it first
      rescue StandardError => e
        MailOnRails.logger.error("[mail_on_rails] auto-ban of #{ip} failed: #{e.class}: #{e.message}")
        nil
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
