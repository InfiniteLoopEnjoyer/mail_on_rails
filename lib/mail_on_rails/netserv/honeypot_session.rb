# frozen_string_literal: true

require_relative "transcript"

module MailOnRails
  module Netserv
    # Honeypot behavior shared by the SMTP and IMAP session classes. A session
    # becomes a honeypot when it authenticates against a canary account or
    # throws an exploit-probe payload; from then on it keeps running so we
    # observe what the attacker does, while the trigger has already recorded a
    # HoneypotEvent and banned the source IP.
    #
    # Everything here is best-effort and rescues into nothing: a honeypot bug
    # must never disturb the protocol loop or the connection teardown, the same
    # discipline Server#report_closed keeps.
    #
    # The including session provides three tiny hooks: honeypot_protocol
    # ("smtp"/"imap"), honeypot_username (the authenticated identity or nil),
    # and honeypot_helo (SMTP HELO name, or nil for IMAP). It also owns @store
    # and @spec, and mixes in the transport helpers' #peer_ip.
    module HoneypotSession
      # How much of a blackholed message body to keep in the transcript: the
      # header and a sample of the spam, not the whole payload.
      HONEYPOT_BODY_SAMPLE = 8 * 1024

      # The per-session dialogue buffer. Always allocated (a real user's is
      # dropped unread at close), so the pre-trigger context is present the
      # moment a probe fires.
      def honeypot_transcript
        @honeypot_transcript ||= Transcript.new
      end

      def honeypot?
        @honeypot
      end

      # The fake product/version fingerprint for this listener's greeting, or
      # nil to keep the real banner. Set per-listener from
      # MAIL_ON_RAILS_HONEYPOT_BANNER; empty/unset ships the deception dormant.
      # CR/LF stripped so an operator's value can never inject extra protocol
      # lines into the greeting (the IMAP greeting writes it unsanitized).
      def honeypot_banner
        banner = @spec[:honeypot_banner].to_s.gsub(/[\r\n]/, " ")
        banner unless banner.empty?
      end

      def honeypot_fired?
        @honeypot_fired
      end

      # Called from the auth success path when the account is a canary: the
      # session continues (normal 235 / OK) but every later action is observed
      # and its submitted mail is blackholed.
      def honeypot_login!
        @honeypot = true
        trigger_honeypot("canary_auth")
      end

      # Records the hit and (via HoneypotEvent) bans the source IP. Idempotent
      # per session, so a canary that then also throws a probe is one event.
      # Fired immediately rather than at teardown so the ban lands now - a
      # probe hangs up fast, and a canary IMAP session may idle for minutes.
      def trigger_honeypot(trigger, signature: nil)
        return if @honeypot_fired

        @honeypot_fired = true
        @honeypot_trigger = trigger
        @honeypot_signature = signature
        return unless @store.respond_to?(:record_honeypot_event)

        result = @store.record_honeypot_event(honeypot_info)
        @honeypot_event_id = result[:id] if result.is_a?(Hash)
      rescue StandardError => e
        @store.log(:error, "honeypot trigger failed: #{e.class}: #{e.message}")
      end

      # Called by Server#report_honeypot at teardown to capture the full
      # post-trigger dialogue (a canary's FETCH/SEARCH, an SMTP relay attempt).
      # No-ops unless the session actually triggered.
      def finalize_honeypot
        return unless @honeypot_fired && @honeypot_event_id
        return unless @store.respond_to?(:update_honeypot_transcript)

        @store.update_honeypot_transcript(@honeypot_event_id, transcript: honeypot_transcript.to_s)
      rescue StandardError
        nil
      end

      private

      def honeypot_info
        { protocol: honeypot_protocol, trigger: @honeypot_trigger,
          signature: @honeypot_signature, ip: honeypot_ip, port: @spec[:port],
          username: honeypot_username, helo: honeypot_helo,
          transcript: honeypot_transcript.to_s, occurred_at: Time.now }
      end

      # peer_ip, but nil for the "?" placeholder or a blank - so a honeypot hit
      # with no usable address records an event (ip: nil) and skips the ban
      # rather than trying to canonicalize a non-address.
      def honeypot_ip
        ip = peer_ip
        ip if ip && ip != "?"
      end
    end
  end
end
