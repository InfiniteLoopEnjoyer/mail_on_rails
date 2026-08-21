# A permanent IP/CIDR ban, created from the auth attempts page (or imported
# from the Spamhaus DROP list). AuthThrottle already blocks brute-force
# sources automatically, but only for minutes at a time; this is the
# admin's "and stay out" - rows persist until deleted from the UI.
#
# Enforcement is deliberately spread over every surface a banned address
# can reach: the in-process SMTP and IMAP listeners drop matching
# connections in their accept loops (Netserv::Denylist, which polls this
# table through the stores' banned_cidrs and is refreshed immediately by
# the after_commit below), and SessionsController checks `covering`
# before the web login. None of those readers restart.
module MailOnRails
  class BannedIp < Record
    SOURCES = %w[manual spamhaus_drop].freeze

    # Below these prefix lengths a typo bans most of the internet
    # (0.0.0.0/0-class mistakes); a deliberate /8 is already 16M addresses.
    # Imported DROP rows are exempt - Spamhaus lists what it lists.
    MIN_IPV4_PREFIX = 8
    MIN_IPV6_PREFIX = 32

    scope :manual, -> { where(source: "manual") }
    scope :spamhaus_drop, -> { where(source: "spamhaus_drop") }

    before_validation :normalize_cidr

    validates :cidr, presence: true, uniqueness: true
    validates :source, inclusion: { in: SOURCES }
    validate :cidr_must_parse
    validate :cidr_not_too_broad, if: -> { source == "manual" }

    after_commit :refresh_denylists

    class << self
      # The ban covering +ip+, or nil (also nil for unparseable input - an
      # address we can't read is an address we can't match). Loads the whole
      # table; bans are a small set and this only runs on admin pages and
      # failed-login paths.
      def covering(ip)
        addr = IPAddr.new(ip.to_s)
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
