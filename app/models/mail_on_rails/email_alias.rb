# An extra address that delivers into an existing account's INBOX. An
# alias has no mailboxes and no credentials of its own: the SMTP server
# accepts it at RCPT time (Store::SmtpBackend#local_rcpts) and the
# mailroom resolves it to its account at delivery time.
#
# Two kinds share the table, told apart by the pattern flag:
#
#   exact   - a literal address ("sales@example.com"). The account may
#             also send as it (RFC 6409 MSA send-as-alias).
#   pattern - the local part is a Ruby regular expression and the domain
#             part a literal hosted domain ("shop-.*@example.com"): every
#             address at that domain whose local part matches (whole
#             local part, case-insensitive) delivers here. ".*" makes the
#             account the domain's catch-all. Receive only - a pattern
#             never grants send-as, so sender-side checks use the exact
#             scope.
#
# Resolution order, fixed everywhere an address is looked up
# (EmailAccount.for_address, MailroomMailbox#resolve_account,
# Store::SmtpBackend#hosted_address?): exact account, exact alias, signed
# VERP bounce+ sub-address, then the lowest-id matching pattern. System
# addresses (postmaster@, dmarc@, honeypot canaries, ...) are exact rows,
# so a catch-all can never shadow them.
module MailOnRails
  class EmailAlias < Record
    # Bounds the regex source. Regexp.timeout does not cover compilation,
    # so size is the only guard against a pathological pattern's compile
    # cost; a real alias family never needs more.
    MAX_PATTERN_LENGTH = 200

    # Per-regex match budget, independent of the host's global
    # Regexp.timeout backstop (seconds, generous for RCPT): the pattern is
    # operator-written, but the local part it runs over is attacker-chosen.
    MATCH_TIMEOUT = 0.1

    belongs_to :email_account

    scope :exact, -> { where(pattern: false) }
    scope :patterns, -> { where(pattern: true) }

    validates :email, presence: true, uniqueness: { case_sensitive: false }
    validate :email_not_an_account_address
    validate :pattern_well_formed, if: :pattern?

    # The domain part is always a hostname, lowercased for both kinds. The
    # local part is lowercased only for exact rows (before_validation
    # below): a regex is case-sensitive source, where downcasing "\D"
    # changes its meaning. Matching is case-insensitive anyway.
    normalizes :email, with: ->(email) {
      local, at, domain = email.to_s.strip.rpartition("@")
      at.empty? ? local : "#{local}@#{domain.downcase}"
    }
    before_validation :downcase_exact_address

    # Turbo broadcasts attach via ActiveSupport.on_load(:mail_on_rails_email_alias).

    # The account a pattern alias routes +address+ to, or nil. The last
    # resort of every recipient lookup: callers check exact rows (and
    # VERP) first. Patterns are scoped to the address's domain by the
    # stored "@domain" suffix, then tried in id order so the oldest match
    # wins deterministically.
    def self.account_for_pattern(address)
      local, at, domain = address.to_s.rpartition("@")
      return nil if at.empty? || local.empty? || domain.empty?

      # "!" as the explicit LIKE escape, as in Store::SmtpBackend#hosted_domain?
      like = "%@#{sanitize_sql_like(domain, "!")}"
      patterns.where(arel_table[:email].matches(like, "!")).order(:id)
              .find { |row| row.match?(local) }&.email_account
    end

    # Whether this pattern row matches a local part. A match that blows
    # the budget counts as no match (logged): the address is then simply
    # unknown, never a hang on the RCPT path.
    def match?(local_part)
      return false unless pattern?

      regexp.match?(local_part.to_s)
    rescue Regexp::TimeoutError
      Rails.logger.warn "[mail_on_rails] alias pattern ##{id} (#{email}) timed out matching a local part"
      false
    end

    def local_part
      email.to_s.rpartition("@").first
    end

    def domain
      email.to_s.rpartition("@").last
    end

    # Anchored over the whole local part; the regex is never left to
    # match a substring.
    def self.compile(source)
      Regexp.new("\\A(?:#{source})\\z", Regexp::IGNORECASE, timeout: MATCH_TIMEOUT)
    end

    private

    def regexp
      @regexp ||= self.class.compile(local_part)
    end

    def downcase_exact_address
      self.email = email.downcase if email.present? && !pattern?
    end

    # An address can be an account or an alias, never both: the mailroom
    # resolves accounts first, so an alias shadowing an account would
    # silently never receive mail.
    def email_not_an_account_address
      errors.add(:email, "is already an account address") if email.present? && EmailAccount.exists?(email: email)
    end

    # A pattern needs a local-part regex that compiles within the size
    # cap, at a domain we host: anywhere else it could never receive mail
    # (RCPT only reads patterns for addresses in a hosted domain), and
    # hosted_domain? must not have to consult patterns to stay correct.
    def pattern_well_formed
      return if email.blank?

      local, at, domain_name = email.rpartition("@")
      if at.empty? || local.empty?
        errors.add(:email, "must be a pattern followed by @ and a domain")
        return
      end
      if local.length > MAX_PATTERN_LENGTH
        errors.add(:email, "pattern is too long (maximum is #{MAX_PATTERN_LENGTH} characters before the @)")
        return
      end
      errors.add(:email, "must be on a hosted domain") unless Domain.exists?(name: domain_name)
      begin
        self.class.compile(local)
      rescue RegexpError => e
        errors.add(:email, "is not a valid pattern: #{e.message}")
      end
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_email_alias, MailOnRails::EmailAlias
