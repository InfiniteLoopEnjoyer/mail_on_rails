# A durable log of closed SMTP/IMAP connections, shown as the history
# section of the live connection pages (/smtp, /imap). The live tables
# only cover what is connected right now; this is where a connection
# lands when it ends - who connected, from where, as whom, for how long.
#
# Written from the servers' connection-close path through
# Store::Base#record_closed_connection. Best-effort by design: losing a
# history row is always better than interfering with a mail connection.
#
# Port 25 sees constant scanner traffic, so an unauthenticated stranger
# decides how fast this table grows - the same problem AuthAttempt has,
# solved the same way: past a per-address cap inside a window, further
# anonymous closes collapse into one counter row per (protocol, ip,
# window). Connections that authenticated or delivered mail are exempt -
# they are the rows this table exists for, and they are rare.
#
# It is also what the idle_auto_ban setting counts. The servers mark a
# connection that did no mail work with the shape it had (info[:idle], see
# Server#idle_reason); that lands in idle_reason on an individual row and
# in idle_count on both kinds - 1 on an idle row, the idle share of
# connection_count on a rollup row - so BannedIp can sum an address's idle
# connections across both protocols however noisy it was.
require "mail_on_rails/netserv/ip"

module MailOnRails
  class ClosedConnection < Record
    PROTOCOLS = %w[smtp imap].freeze

    scope :recent, ->(since) { where(closed_at: since..) }

    # The per-source cap counts by Netserv.throttle_key (the /64 for IPv6),
    # derived here so every writer - record, the rollup, a console insert -
    # keys the same way. A rollup row's ip is already the key.
    before_validation { self.throttle_key ||= Netserv.throttle_key(ip) if ip }

    class << self
      def retention_days = MailOnRails::Settings[:conn_log_retention_days]

      # Rows one address may insert per protocol and window before its noise
      # is collapsed.
      def max_rows_per_ip = MailOnRails::Settings[:conn_log_max_rows_per_ip]

      def rollup_window = MailOnRails::Settings[:conn_log_rollup_window]

      # Records one closed connection from the payload the servers assemble
      # (see Server#report_closed). Never raises: this runs on a dying
      # connection thread, and losing an audit row is always better than
      # disturbing the connection teardown.
      def record(info)
        info = info.symbolize_keys
        protocol = info[:protocol].to_s
        ip = info[:ip].presence
        now = info[:closed_at] || Time.current
        idle = info[:idle].presence
        if notable?(info) || under_cap?(protocol, ip, now)
          # A captured transcript (smtp_trace_capture) rides along in the
          # payload; it is only stored for connections that get their own
          # history row, so the per-IP cap above also bounds transcript
          # growth - rolled-up scanner noise never stores one.
          transcript = SessionTranscript.record(info) if info[:transcript].present?
          create!(closed_at: now, protocol: protocol, ip: ip,
                  port: info[:port], role: info[:role]&.to_s,
                  username: info[:user].presence, tls: !!info[:tls],
                  helo: info[:helo].presence, messages: info[:messages],
                  final_state: info[:state].presence,
                  connected_at: info[:connected_at],
                  duration_seconds: info[:duration_seconds],
                  tarpit_seconds: info[:tarpit_seconds],
                  idle_count: idle ? 1 : 0, idle_reason: idle&.to_s,
                  transcript_id: transcript&.id)
        else
          roll_up(protocol, ip, now, idle: !idle.nil?)
        end
        nil
      rescue StandardError => e
        Rails.logger.error("[mail_on_rails] connection log failed: #{e.class}: #{e.message}")
        nil
      end

      # The rows worth keeping individually no matter how noisy the source:
      # someone authenticated, or an MX peer actually delivered mail.
      def notable?(info)
        info[:user].present? || info[:messages].to_i.positive?
      end

      # The cap and the rollup row key on Netserv.throttle_key (the /64 for
      # IPv6, same reasoning as AuthAttempt): individual rows keep the full
      # address in ip and the key in throttle_key; the rollup row's ip is
      # the key itself.
      def under_cap?(protocol, ip, now)
        return true if ip.blank?

        where(protocol: protocol, throttle_key: Netserv.throttle_key(ip), closed_at: window_start(now)..)
          .sum(:connection_count) < max_rows_per_ip
      end

      def roll_up(protocol, ip, now, idle: false)
        row = find_or_create_by!(protocol: protocol, ip: Netserv.throttle_key(ip), rollup: true,
                                 closed_at: window_start(now)) do |r|
          r.connection_count = 0
        end
        update_counters(row.id, connection_count: 1, idle_count: idle ? 1 : 0)
      rescue ActiveRecord::RecordNotUnique
        retry
      end

      # Rollup rows are keyed to the start of their window, so a window's
      # worth of noise from one address collapses to a single row.
      def window_start(now)
        Time.zone.at((now.to_i / rollup_window) * rollup_window)
      end

      def prune!(now: Time.current)
        where(closed_at: ...(now - retention_days.days)).delete_all
      end

      # Idle connections from an address's throttle key since +since+, both
      # protocols together - a scanner sweeping 25/465/587/143/993 is one
      # source, not five. A rollup row sits at the start of its window, so
      # the far edge of the count is off by at most one rollup window,
      # toward counting less.
      def idle_strikes(ip, since:)
        return 0 if ip.blank?

        where(protocol: PROTOCOLS, throttle_key: Netserv.throttle_key(ip), closed_at: since..).sum(:idle_count)
      end

      # "Has this address done real mail work lately?" - a connection that
      # logged in (canary accounts aside) or delivered a message since
      # +since+. Asked of the whole throttle key, like the ban it guards.
      # Not HoneypotEvent.legitimate_traffic_from?: that asks whether a
      # tenant lives behind the address, and an MX peer that delivers mail
      # is no tenant but is just as wrong to ban for going quiet.
      def worked_from?(ip, since:)
        return false if ip.blank?

        scope = where(closed_at: since..)
        worked = scope.where.not(username: nil)
        canaries = EmailAccount.honeypots.pluck(:email)
        worked = worked.where.not(username: canaries) if canaries.any?
        worked = worked.or(scope.where(messages: 1..))
        worked.where(ip: ip).or(worked.where(throttle_key: Netserv.throttle_key(ip))).exists?
      end

      # The history list on a live connections page: one protocol, newest
      # first, rollup counter rows included (rendered collapsed).
      def recent_list(protocol, since:, limit: 25)
        where(protocol: protocol.to_s).recent(since)
          .order(closed_at: :desc).limit(limit)
      end

      # Repeat offenders for a live connections page: total connections
      # per address in the window, busiest first. SUM(connection_count)
      # counts individual rows (default 1) and rollup counters alike, so
      # collapsed scanner noise still weighs in exactly; idle is the same
      # sum over idle_count (see the class comment). Aggregates are
      # normalized in Ruby because SQLite hands MAX(closed_at) back as a
      # string.
      def top_sources(protocol, since:, limit: 10)
        where(protocol: protocol.to_s).recent(since).where.not(ip: nil)
          .group(:ip)
          .order(Arel.sql("SUM(connection_count) DESC"))
          .limit(limit)
          .pluck(:ip,
                 Arel.sql("SUM(connection_count)"),
                 Arel.sql("MAX(closed_at)"),
                 Arel.sql("SUM(CASE WHEN username IS NOT NULL THEN 1 ELSE 0 END)"),
                 Arel.sql("SUM(idle_count)"))
          .map do |ip, connections, last_seen, authenticated, idle|
            { ip: ip, connections: connections.to_i,
              last_seen: last_seen.is_a?(String) ? Time.zone.parse(last_seen) : last_seen,
              authenticated: authenticated.to_i, idle: idle.to_i }
          end
      end
    end
  end
end
