# frozen_string_literal: true

module MailOnRails
  module Netserv
    # A bounded ring buffer of one session's redacted wire dialogue, kept so a
    # honeypot hit can flush the whole exchange into a HoneypotEvent. Every
    # session owns one; a real user's is simply dropped unread when the session
    # ends, so the only cost of always keeping one is a small capped buffer.
    #
    # Owned by a single connection thread - no lock. It is never read from
    # another thread (deliberately excluded from live_info, which the ops UI
    # reads racily); the only reader is the same thread at teardown.
    #
    # Only the command/reply dialogue lands here. DATA/APPEND payloads are
    # captured separately by the session (an attacker's relay attempt is intel,
    # but a megabyte of it should not sit in this buffer), so the cap bounds
    # memory even on a canary IMAP session an attacker holds open for minutes.
    # The cap holds before AND after a trigger fires.
    class Transcript
      DEFAULT_MAX_LINES = 1_000
      DEFAULT_MAX_BYTES = 128 * 1024

      def initialize(max_lines: DEFAULT_MAX_LINES, max_bytes: DEFAULT_MAX_BYTES)
        @max_lines = max_lines
        @max_bytes = max_bytes
        @lines = []
        @bytes = 0
      end

      def inbound(text)
        push("<= ", text)
      end

      def outbound(text)
        push("=> ", text)
      end

      # The flush: the dialogue so far, oldest first. NUL bytes are stripped
      # and invalid UTF-8 scrubbed here (not on every push - this runs only on
      # a honeypot hit): a PostgreSQL text column rejects NUL, so without this
      # an attacker could embed a NUL in a command and make the event insert
      # raise, losing the very record meant to capture them.
      def to_s
        @lines.map { |line| line.b.force_encoding("UTF-8").scrub("").delete("\u0000") }.join("\n")
      end

      def empty?
        @lines.empty?
      end

      private

      def push(direction, text)
        line = "#{direction}#{text}"
        @lines << line
        @bytes += line.bytesize + 1
        drop_oldest while over_cap?
        nil
      end

      def over_cap?
        @lines.size > @max_lines || (@bytes > @max_bytes && @lines.size > 1)
      end

      def drop_oldest
        dropped = @lines.shift
        @bytes -= dropped.bytesize + 1 if dropped
      end
    end
  end
end
