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

    # Peer lines shown inline on the live pages' captured-sessions table,
    # and how long that preview may run. Enough to tell an EHLO probe from
    # an AUTH spray from an exploit payload without opening each one.
    PREVIEW_LINES = 3
    PREVIEW_CHARS = 120

    scope :recent, ->(since) { where(closed_at: since..) }

    class << self
      def retention_days = MailOnRails::Settings[:transcript_retention_days]

      # The captured-sessions table on /smtp and /imap: every retained
      # capture for the protocol in the window, newest first. Bounded by
      # +limit+ on top of the short retention, since a spray night can
      # capture a row per connection up to the per-IP history cap.
      def recent_list(protocol, since:, limit: 200)
        where(protocol: protocol.to_s).recent(since).order(closed_at: :desc, id: :desc).limit(limit)
      end

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

    # Lines in the captured dialogue, both directions.
    def line_count
      transcript.to_s.count("\n") + (transcript.to_s.empty? ? 0 : 1)
    end

    # What the peer sent, for the inline preview: the first PREVIEW_LINES
    # inbound lines ("<= " prefix stripped, see Netserv::Transcript) joined
    # with a separator and cut at PREVIEW_CHARS. Credentials were redacted
    # at the tap, so this is as safe to show as the full transcript.
    def preview
      lines = transcript.to_s.each_line(chomp: true)
                        .filter_map { |line| line.delete_prefix("<= ").strip.presence if line.start_with?("<= ") }
                        .first(PREVIEW_LINES)
      text = lines.join(" · ")
      text.length > PREVIEW_CHARS ? "#{text[0, PREVIEW_CHARS - 1]}…" : text
    end
  end
end
