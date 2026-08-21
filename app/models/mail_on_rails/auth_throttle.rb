# Brute-force throttling for the mail edges' credential checks, counted in
# two independent scopes: per source IP and per account.
#
# The edges each cap failures *per connection* (the IMAP daemon drops a
# session after MAX_AUTH_ATTEMPTS), which bounds one connection but not an
# attacker who reconnects. This table is the cross-connection counter, and
# it lives in the app rather than in a daemon because the daemon serves
# sessions from one worker Ractor per core with no shared memory between
# them - an in-process counter would be per-worker, and connections are
# dispatched round-robin, so a fleet of N workers would multiply any local
# cap by N. The app is also where SMTP AUTH lands (Store::SmtpBackend
# authenticates through the same plumbing), so both protocols share one
# budget, and the counters survive a restart.
#
# The check runs *before* the bcrypt comparison, so a blocked attacker
# costs a single indexed lookup rather than a KDF - this is a CPU
# exhaustion control as much as a credential-guessing one.
#
# Two scopes, deliberately different:
#
#   ip      - the primary defense. Generous enough that a mail client's
#             reconnect storm never reaches it, blocked long enough that
#             guessing is hopeless.
#   account - a backstop for a distributed guess against one mailbox.
#             Blocking an account is a self-inflicted denial of service if
#             the user's own device holds a stale password (iOS opens ~5
#             connections per folder refresh, so a stale device burns
#             failures fast), so its block is deliberately short and any
#             successful login clears the counter outright.
module MailOnRails
  class AuthThrottle < Record
    IP = "ip"
    ACCOUNT = "account"

    class << self
      # Failures older than this stop counting.
      def window_seconds = MailOnRails::Settings[:auth_window]

      def max_failures_per_ip = MailOnRails::Settings[:auth_max_ip_failures]

      def max_failures_per_account = MailOnRails::Settings[:auth_max_account_failures]

      def ip_block_seconds = MailOnRails::Settings[:auth_ip_block]

      def account_block_seconds = MailOnRails::Settings[:auth_account_block]

      # nil when the attempt may proceed, otherwise
      # { retry_after: <seconds>, scope: "ip" | "account" }. When both scopes
      # are blocked the longer block is reported, so a client that honors
      # retry_after doesn't come back into a still-live block.
      def check(ip:, email:, now: Time.current)
        blocked = entries_for(ip: ip, email: email)
                    .where(blocked_until: now..)
                    .order(blocked_until: :desc)
                    .first
        return nil unless blocked

        { retry_after: (blocked.blocked_until - now).ceil, scope: blocked.scope }
      end

      # The blocks currently in force across both scopes, longest remaining
      # first - the Security page's "temporary blocks" section. A relation,
      # so callers can count or list it.
      def active_blocks(now: Time.current)
        where(blocked_until: now..).order(blocked_until: :desc)
      end

      # Counts one failed credential check against both scopes. Safe to call
      # concurrently: each row is bumped under a row lock, and a lost
      # create race is retried.
      def record_failure(ip:, email:, now: Time.current)
        targets(ip: ip, email: email).each do |scope, key, limit, block_seconds|
          bump(scope, key, limit, block_seconds, now)
        end
        nil
      end

      # Directly applies a temporary IP block - a deliberate action (a
      # honeypot hit), not a counted credential failure. Auto-expiring like
      # every block here, so a reassigned address heals itself; re-arms a
      # shorter or lapsed block but never shortens a longer live one. Caller
      # is responsible for the collateral decision (do not block a shared
      # address); this only writes the block.
      def block_ip!(ip, seconds:, now: Time.current)
        seconds = seconds.to_i
        return if ip.blank? || seconds <= 0

        until_at = now + seconds
        row = find_or_create_by!(scope: IP, key: ip.to_s) do |r|
          r.window_started_at = now
          r.blocked_until = until_at
        end
        transaction do
          row.lock!
          row.update!(blocked_until: until_at) if row.blocked_until.nil? || row.blocked_until < until_at
        end
        nil
      rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordNotFound
        retry
      end

      # A successful login clears that account's counter. The IP counter is
      # left alone on purpose: one lucky guess must not hand an attacker a
      # fresh budget, and the IP limit is set high enough that a legitimate
      # client sharing a NAT never reaches it.
      def clear_account(email)
        return 0 if email.blank?

        where(scope: ACCOUNT, key: normalize(email)).delete_all
      end

      # Drops rows whose window has expired and whose block (if any) has
      # lapsed - the table is otherwise unbounded under a sustained attack.
      def prune!(now: Time.current)
        where(window_started_at: ...(now - window_seconds))
          .where("blocked_until IS NULL OR blocked_until < ?", now)
          .delete_all
      end

      def normalize(email) = email.to_s.strip.downcase

      private

      def targets(ip:, email:)
        list = []
        list << [ IP, ip.to_s, max_failures_per_ip, ip_block_seconds ] if ip.present?
        list << [ ACCOUNT, normalize(email), max_failures_per_account, account_block_seconds ] if email.present?
        list
      end

      def entries_for(ip:, email:)
        relations = []
        relations << where(scope: IP, key: ip.to_s) if ip.present?
        relations << where(scope: ACCOUNT, key: normalize(email)) if email.present?
        return none if relations.empty?

        relations.reduce { |a, b| a.or(b) }
      end

      def bump(scope, key, limit, block_seconds, now)
        row = find_or_create_by!(scope: scope, key: key) { |r| r.window_started_at = now }
        transaction do
          # FOR UPDATE on PostgreSQL/MySQL; SQLite ignores it but its
          # IMMEDIATE write transactions serialize this section anyway.
          row.lock!
          apply_failure(row, limit, block_seconds, now)
          row.save! if row.changed?
        end
      rescue ActiveRecord::RecordNotUnique
        # Another edge created the row between our read and insert.
        retry
      rescue ActiveRecord::RecordNotFound
        # ...or deleted it (prune!) between our find and our lock.
        retry
      end

      # An already-blocked row is left untouched: further attempts during a
      # block must not extend it, or a persistent attacker could hold a
      # shared IP (or someone else's account) blocked indefinitely.
      def apply_failure(row, limit, block_seconds, now)
        return if row.blocked_until && row.blocked_until > now

        # A lapsed block clears the slate, as does an expired window. Without
        # the first case the counter would still sit at the limit when the
        # block ends, so the very next failure would re-block - which for a
        # user whose own device holds a stale password is an endless lockout
        # rather than a throttle.
        if row.blocked_until || row.window_started_at < now - window_seconds
          row.blocked_until = nil
          row.window_started_at = now
          row.failure_count = 0
        end
        row.failure_count += 1
        row.blocked_until = now + block_seconds if row.failure_count >= limit
      end
    end
  end
end
