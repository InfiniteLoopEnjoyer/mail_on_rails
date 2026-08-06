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
class ClosedConnection < ApplicationRecord
  PROTOCOLS = %w[smtp imap].freeze

  scope :recent, ->(since) { where(closed_at: since..) }

  class << self
    def retention_days = Integer(ENV.fetch("MAIL_ON_RAILS_CONN_LOG_RETENTION_DAYS", 90))

    # Rows one address may insert per protocol and window before its noise
    # is collapsed.
    def max_rows_per_ip = Integer(ENV.fetch("MAIL_ON_RAILS_CONN_LOG_MAX_ROWS_PER_IP", 50))

    def rollup_window = Integer(ENV.fetch("MAIL_ON_RAILS_CONN_LOG_ROLLUP_WINDOW", 3600))

    # Records one closed connection from the payload the servers assemble
    # (see Server#report_closed). Never raises: this runs on a dying
    # connection thread, and losing an audit row is always better than
    # disturbing the connection teardown.
    def record(info)
      info = info.symbolize_keys
      protocol = info[:protocol].to_s
      ip = info[:ip].presence
      now = info[:closed_at] || Time.current
      if notable?(info) || under_cap?(protocol, ip, now)
        create!(closed_at: now, protocol: protocol, ip: ip,
                port: info[:port], role: info[:role]&.to_s,
                username: info[:user].presence, tls: !!info[:tls],
                helo: info[:helo].presence, messages: info[:messages],
                final_state: info[:state].presence,
                connected_at: info[:connected_at],
                duration_seconds: info[:duration_seconds])
      else
        roll_up(protocol, ip, now)
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

    def under_cap?(protocol, ip, now)
      return true if ip.blank?

      where(protocol: protocol, ip: ip, closed_at: window_start(now)..)
        .sum(:connection_count) < max_rows_per_ip
    end

    def roll_up(protocol, ip, now)
      row = find_or_create_by!(protocol: protocol, ip: ip, rollup: true,
                               closed_at: window_start(now)) do |r|
        r.connection_count = 0
      end
      increment_counter(:connection_count, row.id)
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

    # The history list on a live connections page: one protocol, newest
    # first, rollup counter rows included (rendered collapsed).
    def recent_list(protocol, since:, limit: 25)
      where(protocol: protocol.to_s).recent(since)
        .order(closed_at: :desc).limit(limit)
    end
  end
end
