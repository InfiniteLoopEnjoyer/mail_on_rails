# A durable log of failed credential checks across all three auth surfaces
# (IMAP, SMTP AUTH, the web login), kept so the shape of an attack can be
# looked at after the fact.
#
# The listeners already log their own failures - the SMTP server logs a
# line per 535, the IMAP server likewise - but those live in container
# logs capped at 10 MB and rotate away, and nothing can query across the
# three surfaces. This table
# exists for retention and queryability, not because the data is otherwise
# unavailable.
#
# **No password material is stored unless the operator opts in.** Most
# failed attempts are real users mistyping or retrying a stale password, so
# the column fills with current, working credentials for these very
# mailboxes; the rest is credential stuffing carrying passwords harvested
# elsewhere, which users reuse. Hashing does not rescue it: the only reason
# to keep password material is comparison across attempts, which needs a
# deterministic hash, and a deterministic hash of a password from a spray
# dictionary is reversible by anyone who obtains this table. So the default
# is to keep nothing. With auth_log_passwords on, the plaintext of a failed
# login to an address that *exists here* is kept (encrypted at rest, pruned
# with the row) so the operator can tell an old breached password from a
# fresh guess. Dictionary noise against unknown addresses never carries
# one, and SCRAM logins cannot: the daemon only ever sees a proof.
#
# Successes are deliberately not recorded either: a single iOS folder
# refresh opens ~5 connections and authenticates on each, so legitimate
# traffic would bury the signal and dominate the table.
require "mail_on_rails/netserv/ip"

module MailOnRails
  class AuthAttempt < Record
    SOURCES = %w[imap smtp web].freeze
    OUTCOMES = %w[unknown_account bad_credentials throttled].freeze

    # One address's aggregate inside a range drill-down (range_detail).
    RangeIp = Data.define(:ip, :attempts, :last_seen, :usernames, :sources, :real_account)

    # Longest password kept; anything past it is a paste, not a typo.
    MAX_PASSWORD_LENGTH = 256

    scope :recent, ->(since) { where(occurred_at: since..) }
    scope :against_real_accounts, -> { where(account_exists: true) }

    # Plaintext of a failed guess (see the file comment): a working
    # credential for a real mailbox more often than not, so at rest it
    # gets the same protection as the SCRAM verifiers and TOTP secrets.
    encrypts :password

    # The per-source cap counts by Netserv.throttle_key (the /64 for IPv6),
    # derived here so every writer keys the same way. A rollup row's ip is
    # already the key.
    before_validation { self.throttle_key ||= Netserv.throttle_key(ip) if ip }

    class << self
      def retention_days = MailOnRails::Settings[:auth_log_retention_days]

      # Rows one address may insert per window before its noise is collapsed.
      def max_rows_per_ip = MailOnRails::Settings[:auth_log_max_rows_per_ip]

      def rollup_window = MailOnRails::Settings[:auth_log_rollup_window]

      def log_passwords? = MailOnRails::Settings[:auth_log_passwords]

      # Records one failed attempt. Never raises: this sits on the auth path,
      # and losing an audit row is always better than failing a login (or
      # handing an attacker a way to make logins fail).
      # +outcome+ of "bad_credentials" is downgraded to "unknown_account" when
      # the address doesn't resolve, so callers don't each repeat that lookup
      # on the auth path just to pick a label.
      # +password+ is the plaintext the client offered, when the caller has
      # one; it is kept only for a bad_credentials verdict against a real
      # address, and only while auth_log_passwords is on.
      def record(ip:, username:, source:, outcome:, now: Time.current, password: nil)
        real = account_exists?(username, source)
        outcome = "unknown_account" if outcome.to_s == "bad_credentials" && !real
        if real || under_cap?(ip, now)
          kept = real && outcome.to_s == "bad_credentials" ? keepable_password(password) : nil
          create!(occurred_at: now, ip: ip.presence, username: normalize(username),
                  source: source.to_s, outcome: outcome.to_s, account_exists: real, password: kept)
        else
          roll_up(ip, source, now)
        end
        nil
      rescue StandardError => e
        Rails.logger.error("[mail_on_rails] auth attempt log failed: #{e.class}: #{e.message}")
        nil
      end

      # An unauthenticated stranger decides how fast this table grows, so the
      # write rate has to be bounded or the audit log becomes the outage.
      # Attempts against an address that actually exists are exempt above -
      # they are the whole point of keeping this, and they are rare. Only the
      # dictionary noise gets collapsed.
      #
      # The cap and the rollup row key on Netserv.throttle_key - the /64 for
      # IPv6 - because a guesser with a /64 can otherwise mint a fresh
      # address per attempt and never trip a per-address cap. Individual
      # rows keep the full address in ip and the key in throttle_key; the
      # rollup row's ip IS the key ("2001:db8::/64"), which is also how
      # top_ranges spells the range.
      def under_cap?(ip, now)
        return true if ip.blank?

        where(throttle_key: Netserv.throttle_key(ip), occurred_at: window_start(now)..)
          .sum(:attempt_count) < max_rows_per_ip
      end

      def roll_up(ip, source, now)
        row = find_or_create_by!(ip: Netserv.throttle_key(ip), source: source.to_s, rollup: true,
                                 occurred_at: window_start(now)) do |r|
          r.outcome = "unknown_account"
          r.attempt_count = 0
        end
        increment_counter(:attempt_count, row.id)
      rescue ActiveRecord::RecordNotUnique
        retry
      end

      # Rollup rows are keyed to the start of their window, so a window's
      # worth of noise from one address collapses to a single row.
      def window_start(now)
        Time.zone.at((now.to_i / rollup_window) * rollup_window)
      end

      def prune!(now: Time.current)
        where(occurred_at: ...(now - retention_days.days)).delete_all
      end

      def normalize(username) = username.to_s.strip.downcase.presence

      # nil unless the operator opted in. SASL hands the listeners raw
      # bytes, so the value is scrubbed to valid UTF-8 (encryption
      # serializes it as text) and cut at MAX_PASSWORD_LENGTH.
      def keepable_password(password)
        return nil unless log_passwords?

        password.to_s.dup.force_encoding(Encoding::UTF_8).scrub("�").first(MAX_PASSWORD_LENGTH).presence
      end

      # "Real" means an address mail would actually be accepted for (an
      # account or an alias), or - on the web surface - a login that exists.
      def account_exists?(username, source)
        name = normalize(username)
        return false if name.blank?

        if source.to_s == "web"
          # The web login surface belongs to the host app; it tells us which
          # logins are real via config.mail_on_rails.web_login_lookup.
          !!MailOnRails.web_login_lookup&.call(name)
        else
          EmailAccount.exists?(email: name) || EmailAlias.exists?(email: name)
        end
      end

      # -- analysis ----------------------------------------------------------

      # The query this table is for: addresses that exist here and are being
      # attempted anyway. Everything else is someone reciting a dictionary at
      # the internet; this is someone who did reconnaissance first.
      def targeted_accounts(since: 7.days.ago, limit: 20)
        against_real_accounts.recent(since)
          .group(:username)
          .order(Arel.sql("SUM(attempt_count) DESC"))
          .limit(limit)
          .sum(:attempt_count)
      end

      def top_sources(since: 7.days.ago, limit: 20)
        recent(since).where.not(ip: nil)
          .group(:ip)
          .order(Arel.sql("SUM(attempt_count) DESC"))
          .limit(limit)
          .sum(:attempt_count)
      end

      # Groups IPv4 sources into /24s and IPv6 sources into /64s, which is
      # the unit a spray actually arrives in - 21 addresses from one hosting
      # range read as noise one at a time and as a single campaign together.
      # Aggregated in Ruby because the set is already bounded by the row
      # cap, and inet casts on a string column would tie this to Postgres.
      def top_ranges(since: 7.days.ago, limit: 15)
        counts = Hash.new(0)
        recent(since).where.not(ip: nil).group(:ip).sum(:attempt_count).each do |ip, n|
          counts[range_for(ip)] += n
        end
        counts.sort_by { |range, n| [ -n, range ] }.first(limit)
      end

      # IPv6 ranges are the throttle key ("2001:db8::/64"), which is also
      # how their rollup rows are already stored, so a rollup row maps to
      # itself. Anything unparseable passes through as its own range.
      def range_for(ip)
        octets = ip.to_s.split(".")
        return "#{octets.first(3).join(".")}.0/24" if octets.size == 4

        Netserv.throttle_key(ip.to_s)
      end

      # The drill-down behind top_ranges: one range's individual addresses
      # with per-IP totals, so a specific machine can be banned on its own
      # or the whole range once its spread is plain. Aggregated in SQL per
      # distinct IP - the output is bounded by the range's size (and the
      # row cap), not by how noisy each address was.
      def range_detail(range, since: 7.days.ago)
        scope = recent(since).where.not(ip: nil)
        scope = if (prefix = range.to_s[%r{\A(\d{1,3}\.\d{1,3}\.\d{1,3})\.0/24\z}, 1])
          scope.where("ip LIKE ?", "#{prefix}.%")
        else
          # An IPv6 /64 has no stable string prefix once compressed, so
          # its members are picked out in Ruby from the (row-capped) set
          # of distinct sources; an unparseable "range" is one address.
          scope.where(ip: scope.distinct.pluck(:ip).select { |ip| range_for(ip) == range.to_s })
        end

        sources = Hash.new { |h, k| h[k] = [] }
        scope.distinct.pluck(:ip, :source).each { |ip, source| sources[ip] << source }

        scope.group(:ip).pluck(
          :ip,
          Arel.sql("SUM(attempt_count)"),
          Arel.sql("MAX(occurred_at)"),
          Arel.sql("COUNT(DISTINCT username)"),
          Arel.sql("MAX(CASE WHEN account_exists THEN 1 ELSE 0 END)")
        ).map do |ip, attempts, last_seen, usernames, real|
          RangeIp.new(ip: ip, attempts: attempts, last_seen: last_seen,
                      usernames: usernames, sources: sources[ip].sort,
                      real_account: real == 1)
        end.sort_by { |row| [ -row.attempts, row.ip ] }
      end

      def top_usernames(since: 7.days.ago, limit: 20)
        recent(since).where.not(username: nil)
          .group(:username)
          .order(Arel.sql("SUM(attempt_count) DESC"))
          .limit(limit)
          .sum(:attempt_count)
      end

      def totals(since: 7.days.ago)
        scope = recent(since)
        {
          attempts: scope.sum(:attempt_count),
          sources: scope.where.not(ip: nil).distinct.count(:ip),
          usernames: scope.where.not(username: nil).distinct.count(:username),
          real_accounts: scope.against_real_accounts.sum(:attempt_count),
          by_source: scope.group(:source).sum(:attempt_count),
          collapsed: scope.where(rollup: true).sum(:attempt_count)
        }
      end
    end
  end
end

ActiveSupport.run_load_hooks :mail_on_rails_auth_attempt, MailOnRails::AuthAttempt
