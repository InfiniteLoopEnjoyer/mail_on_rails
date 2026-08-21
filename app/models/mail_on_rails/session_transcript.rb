# A stored wire transcript of one abnormally ended mail session, captured
# when smtp_trace_capture is on. This is the same bounded, redacted dialogue
# buffer every session already keeps for the honeypot (Netserv::Transcript):
# AUTH arguments and challenge responses are redacted at the tap and DATA
# payloads never enter it, so a row holds the command/reply exchange only -
# no message content, no credentials.
#
# Unlike HoneypotEvent this records *real* peers' sessions, so it is scoped
# hard: capture is opt-in, only sessions with something to diagnose qualify
# (timeouts, dropped connections, protocol errors, failed auth - see
# Session#capture_reason), a session that would roll up in ClosedConnection
# stores nothing (the same per-IP cap bounds both tables), and retention is
# short (transcript_retention_days, default 7) because envelope metadata of
# legitimate traffic should not accumulate.
#
# Rows are created inside ClosedConnection.record, which links the history
# row to its transcript via closed_connections.transcript_id - that link is
# what makes a row on the /smtp page clickable. A pruned transcript leaves a
# dangling transcript_id behind; the UI treats that as "no longer retained".
module MailOnRails
  class SessionTranscript < Record
    PROTOCOLS = %w[smtp imap].freeze

    class << self
      def retention_days = MailOnRails::Settings[:transcript_retention_days]

      # Creates one transcript row from the closed-connection payload.
      # Best-effort like everything on the teardown path: returns nil on
      # any failure so the ClosedConnection row still lands without it.
      def record(info)
        create!(protocol: info[:protocol].to_s, ip: info[:ip].presence,
                port: info[:port], username: info[:user].presence,
                helo: info[:helo].presence,
                close_reason: info[:close_reason].presence,
                connected_at: info[:connected_at],
                closed_at: info[:closed_at] || Time.current,
                transcript: info[:transcript].to_s)
      rescue StandardError => e
        Rails.logger.error("[mail_on_rails] session transcript failed: #{e.class}: #{e.message}")
        nil
      end

      def prune!(now: Time.current)
        where(closed_at: ...(now - retention_days.days)).delete_all
      end
    end
  end
end
