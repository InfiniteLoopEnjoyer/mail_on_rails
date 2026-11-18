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
#
# The ip scope keys on Netserv.throttle_key: the address for IPv4, the /64
# for IPv6 - an IPv6 guesser gets a fresh /128 per attempt for free, so a
# per-address budget would bound nothing. Callers still pass the full
# address; the key is derived here so every writer and reader agree.
#
# The account scope has one exemption, for the mail edges: a source that
# logged in to that same account lately (known_source?) is not refused by
# the account block. Ten wrong guesses from strangers would otherwise lock
# the owner out of their own mailbox for as long as the guessing goes on.
# The exemption skips that one refusal and nothing else - the password is
# still checked, the ip scope still applies to the source, and its
# failures are still counted.
#
# The mail stores check and count in one step (reserve) so that parallel
# guesses cannot all be adjudicated against the same remaining budget;
# check + record_failure remain for callers that adjudicate elsewhere.
require "mail_on_rails/netserv/ip"

module MailOnRails
  class AuthThrottle < Record
    IP = "ip"
    ACCOUNT = "account"

    # Longest key kept. A login name is client-chosen bytes; past this it
    # is no address (RFC 5321 paths stop at 256), and an unbounded one
    # would not fit the unique index it is looked up through.
    MAX_KEY_LENGTH = 320

    class << self
      # Failures older than this stop counting.
      def window_seconds = MailOnRails::Settings[:auth_window]

      def max_failures_per_ip = MailOnRails::Settings[:auth_max_ip_failures]

      def max_failures_per_account = MailOnRails::Settings[:auth_max_account_failures]

      def ip_block_seconds = MailOnRails::Settings[:auth_ip_block]

      def account_block_seconds = MailOnRails::Settings[:auth_account_block]

      # How far back a login still marks its source as the account's own
      # (known_source?): the same lookback the automatic bans use for "this
      # address does real mail work here".
      def known_source_days = MailOnRails::Settings[:honeypot_collateral_days]

      # nil when the attempt may proceed, otherwise
      # { retry_after: <seconds>, scope: "ip" | "account" }. When both scopes
      # are blocked the longer block is reported, so a client that honors
      # retry_after doesn't come back into a still-live block.
      #
      # +exempt_known_source+ is the mail edges' opt-in to the account-scope
      # exemption (see the class comment); it is only looked up when the
      # account block is the one thing in the way. The web login leaves it
      # off: a mail login is no evidence for the web credential. A caller
      # with evidence of its own (a surface with its own sessions) passes
      # a callable instead of true; it is asked just as lazily, and its
      # raising reads as "unknown" like any failed lookup.
      def check(ip:, email:, now: Time.current, exempt_known_source: false)
        blocks = entries_for(ip: ip, email: email).where(blocked_until: now..).to_a
        blocked = standing_block(blocks, ip, email, now, exempt_known_source)
        blocked && verdict(blocked, now)
      end

      # check and record_failure as one step, for a caller about to
      # adjudicate a credential: under the row locks, either the attempt is
      # refused ([ verdict, nil ] - nothing counted, as with check) or one
      # failure is counted in every scope up front ([ nil, holds ]). Counting
      # before the verdict is what makes the budget hold against parallel
      # guesses - each one sees the others' reservations. The caller hands
      # +holds+ back to refund when the credential turns out right, and
      # does nothing more when it turns out wrong: the failure is already
      # counted, once.
      def reserve(ip:, email:, now: Time.current, exempt_known_source: false)
        list = targets(ip: ip, email: email)
        return [ nil, [] ] if list.empty?

        rows = list.map do |scope, key, _limit, _block_seconds|
          find_or_create_by!(scope: scope, key: key) { |r| r.window_started_at = now }
        end
        transaction do
          # Always ip before account, so two reservations cannot deadlock.
          rows.each(&:lock!)
          blocks = rows.select { |row| row.blocked_until && row.blocked_until >= now }
          if (blocked = standing_block(blocks, ip, email, now, exempt_known_source))
            next [ verdict(blocked, now), nil ]
          end

          holds = rows.zip(list).filter_map do |row, (_scope, _key, limit, block_seconds)|
            # Only a known source gets here with a blocked row: its account
            # block stands as it is (apply_failure leaves it alone too).
            next if blocks.include?(row)

            apply_failure(row, limit, block_seconds, now)
            row.save!
            [ row.scope, row.key, row.window_started_at, row.blocked_until ]
          end
          [ nil, holds ]
        end
      rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordNotFound
        # A lost create race, or prune! between our find and our lock.
        retry
      end

      # Gives back what reserve counted, for an attempt whose credential
      # was right. Only its own count: a row whose window has since been
      # reset holds someone else's failures and is left alone, and a block
      # is lifted only when this very reservation tripped it (one applied
      # since - block_ip!, another failure - stands).
      def refund(holds)
        Array(holds).each do |scope, key, window_started_at, tripped_until|
          row = find_by(scope: scope, key: key)
          next unless row

          transaction do
            row.lock!
            next unless same_instant?(row.window_started_at, window_started_at) && row.failure_count.positive?

            row.failure_count -= 1
            row.blocked_until = nil if tripped_until && same_instant?(row.blocked_until, tripped_until)
            row.save!
          end
        rescue ActiveRecord::RecordNotFound
          next # pruned or cleared meanwhile: nothing left to give back
        end
        nil
      end

      # "Has this source logged in to this account lately?" - the evidence
      # behind the account-scope exemption, read from what the listeners
      # already keep: the connection history (written when a session ends)
      # and the live connection table (a phone holds one IMAP session open
      # for hours). Both carry the authenticated account, so neither a
      # failed login nor a login to some other account earns anything, and
      # both are asked about the source's throttle key - the unit every
      # other per-source control uses. Any error reads as "unknown": the
      # exemption must never be what lets an attempt through by accident.
      def known_source?(ip, email, now: Time.current)
        account = normalize(email)
        return false if ip.blank? || account.blank?

        ClosedConnection.logged_in_from?(ip, account, since: now - known_source_days.days) ||
          OpenConnection.logged_in_from?(ip, account)
      rescue StandardError => e
        MailOnRails.logger.error("[mail_on_rails] known-source lookup failed: #{e.class}: #{e.message}")
        false
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
        row = find_or_create_by!(scope: IP, key: ip_key(ip)) do |r|
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

      # Failures counted against an address's key in the live window - what
      # record_failure just bumped it to. Zero once the window has lapsed
      # (the next bump starts a fresh count); a block in force keeps its
      # count. Read by BannedIp's automatic ban.
      def ip_failures(ip, now: Time.current)
        return 0 if ip.blank?

        row = find_by(scope: IP, key: ip_key(ip))
        return 0 unless row
        return 0 if row.blocked_until.nil? && row.window_started_at < now - window_seconds

        row.failure_count
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

      # The account-scope key for a login name. Client-chosen bytes: made
      # storable (valid UTF-8, no control characters - PostgreSQL refuses a
      # NUL outright) and bounded before they reach the unique index.
      def normalize(email)
        email.to_s.dup.force_encoding(Encoding::UTF_8).scrub("?")
             .strip.downcase.gsub(/[[:cntrl:]]/, "?")[0, MAX_KEY_LENGTH]
      end

      # The ip-scope row key for a peer address (see the class comment).
      def ip_key(ip) = Netserv.throttle_key(ip.to_s)

      private

      def targets(ip:, email:)
        list = []
        list << [ IP, ip_key(ip), max_failures_per_ip, ip_block_seconds ] if ip.present?
        list << [ ACCOUNT, normalize(email), max_failures_per_account, account_block_seconds ] if email.present?
        list
      end

      # The block that refuses this attempt, or nil: the longest in force,
      # unless the account block is the only one and the source is known.
      def standing_block(blocks, ip, email, now, exempt_known_source)
        return nil if blocks.empty?
        if exempt_known_source && blocks.all? { |row| row.scope == ACCOUNT } &&
           exempt?(exempt_known_source, ip, email, now)
          return nil
        end

        blocks.max_by(&:blocked_until)
      end

      def exempt?(evidence, ip, email, now)
        return known_source?(ip, email, now: now) unless evidence.respond_to?(:call)

        evidence.call ? true : false
      rescue StandardError => e
        MailOnRails.logger.error("[mail_on_rails] known-source lookup failed: #{e.class}: #{e.message}")
        false
      end

      def verdict(blocked, now)
        { retry_after: (blocked.blocked_until - now).ceil, scope: blocked.scope }
      end

      # Timestamps compared across a database round trip, which may round
      # them; two different stamps on one row are a block or a window
      # apart, never under a second.
      def same_instant?(a, b)
        !a.nil? && !b.nil? && (a - b).abs < 1.0
      end

      def entries_for(ip:, email:)
        relations = []
        relations << where(scope: IP, key: ip_key(ip)) if ip.present?
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
