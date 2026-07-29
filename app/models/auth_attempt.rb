# A durable log of failed credential checks across all three auth surfaces
# (IMAP, SMTP AUTH, the web login), kept so the shape of an attack can be
# looked at after the fact.
#
# The edges already log their own failures - exim writes a line per 535,
# the IMAP daemon likewise - but those live in container logs capped at
# 10 MB and rotate away, and nothing can query across the three. This table
# exists for retention and queryability, not because the data is otherwise
# unavailable.
#
# **No password material is stored, in any form.** Most failed attempts are
# real users mistyping or retrying a stale password, so the column would
# fill with current, working credentials for these very mailboxes; the rest
# is credential stuffing carrying passwords harvested elsewhere, which
# users reuse. Hashing does not rescue it: the only reason to keep password
# material is equality comparison across attempts, which needs a
# deterministic hash, and a deterministic hash of a password from a spray
# dictionary is reversible by anyone who obtains this table. It would be
# the liability without the protection. The spray/brute-force distinction
# it would buy is already legible from how usernames and addresses fan out.
#
# Successes are deliberately not recorded either: a single iOS folder
# refresh opens ~5 connections and authenticates on each, so legitimate
# traffic would bury the signal and dominate the table.
class AuthAttempt < ApplicationRecord
  SOURCES = %w[imap smtp web].freeze
  OUTCOMES = %w[unknown_account bad_credentials throttled].freeze

  scope :recent, ->(since) { where(occurred_at: since..) }
  scope :against_real_accounts, -> { where(account_exists: true) }

  class << self
    def retention_days = Integer(ENV.fetch("MAIL_ON_RAILS_AUTH_LOG_RETENTION_DAYS", 30))

    # Rows one address may insert per window before its noise is collapsed.
    def max_rows_per_ip = Integer(ENV.fetch("MAIL_ON_RAILS_AUTH_LOG_MAX_ROWS_PER_IP", 50))

    def rollup_window = Integer(ENV.fetch("MAIL_ON_RAILS_AUTH_LOG_ROLLUP_WINDOW", 3600))

    # Records one failed attempt. Never raises: this sits on the auth path,
    # and losing an audit row is always better than failing a login (or
    # handing an attacker a way to make logins fail).
    # +outcome+ of "bad_credentials" is downgraded to "unknown_account" when
    # the address doesn't resolve, so callers don't each repeat that lookup
    # on the auth path just to pick a label.
    def record(ip:, username:, source:, outcome:, now: Time.current)
      real = account_exists?(username, source)
      outcome = "unknown_account" if outcome.to_s == "bad_credentials" && !real
      if real || under_cap?(ip, now)
        create!(occurred_at: now, ip: ip.presence, username: normalize(username),
                source: source.to_s, outcome: outcome.to_s, account_exists: real)
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
    def under_cap?(ip, now)
      return true if ip.blank?

      where(ip: ip, occurred_at: window_start(now)..).sum(:attempt_count) < max_rows_per_ip
    end

    def roll_up(ip, source, now)
      row = find_or_create_by!(ip: ip, source: source.to_s, rollup: true,
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

    # "Real" means an address mail would actually be accepted for (an
    # account or an alias), or - on the web surface - a login that exists.
    def account_exists?(username, source)
      name = normalize(username)
      return false if name.blank?

      if source.to_s == "web"
        User.exists?(email_address: name)
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

    # Groups IPv4 sources into /24s, which is the unit a spray actually
    # arrives in - 21 addresses from one hosting range read as noise one at
    # a time and as a single campaign together. Aggregated in Ruby because
    # the set is already bounded by the row cap, and inet casts on a string
    # column would tie this to Postgres.
    def top_ranges(since: 7.days.ago, limit: 15)
      counts = Hash.new(0)
      recent(since).where.not(ip: nil).group(:ip).sum(:attempt_count).each do |ip, n|
        counts[range_for(ip)] += n
      end
      counts.sort_by { |range, n| [ -n, range ] }.first(limit)
    end

    def range_for(ip)
      octets = ip.to_s.split(".")
      octets.size == 4 ? "#{octets.first(3).join(".")}.0/24" : ip.to_s
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
