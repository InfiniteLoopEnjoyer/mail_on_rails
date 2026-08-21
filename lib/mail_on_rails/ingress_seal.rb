# frozen_string_literal: true

require "openssl"
require "base64"
require "digest"

module MailOnRails
  # Authenticates the trusted routing/auth headers the in-process SMTP
  # edge stamps onto inbound mail (Store::SmtpBackend#stamp). Those
  # headers - X-Original-To, X-MailOnRails-Authenticated, -Client-Ip,
  # -Helo, Return-Path - decide routing and whether spam analysis runs,
  # so anything that reaches MailroomMailbox by a route *other* than the
  # edge (a re-opened Action Mailbox HTTP/cloud ingress) would inherit
  # full trust for free. The prepend-and-strip stamp is not
  # authentication; this seal is.
  #
  # The edge computes an HMAC over the whole stamped message (headers and
  # body both, so tampering with any of them or the routing headers
  # breaks it) and prepends it as the first header. The mailroom peels
  # that header off, recomputes over the remainder, and compares in
  # constant time. Stamper and verifier both run inside the host Rails
  # process, so the key derives from secret_key_base - no new secret to
  # provision, and it is stable across restarts.
  #
  # The timestamp bounds replay: a captured sealed message can only be
  # re-injected within max_age, and only re-delivers the identical bytes
  # to the identical recipients (Message-ID dedupe covers the rest). It
  # is intentionally coarse - the seal proves internal origin, it is not
  # a nonce ledger.
  module IngressSeal
    HEADER = "X-MailOnRails-Seal"
    # Prepended, so it is the first physical line; also matched by
    # SmtpBackend::TRUSTED_HEADERS, so a forged copy in submitted DATA is
    # stripped before the edge stamps its own.
    LINE = /\A#{HEADER}:[ \t]*(.*)\r?\n/i
    VERSION = "v1"
    # Replay bound: a captured sealed blob verifies only this long, and
    # re-injecting it re-delivers identical bytes to identical recipients
    # (Message-ID dedupe covers the rest). Six hours dwarfs any healthy
    # routing-job backlog; the mailroom passes the mailroom_seal_max_age
    # setting (same default), so an incident that backs the queue up past
    # it is answered by raising that setting - a bounded lever - rather
    # than the blunt MAILROOM_REQUIRE_SEAL=0.
    DEFAULT_MAX_AGE = 21_600

    class << self
      # The seal header line (with trailing CRLF) for an already-stamped
      # message. now is injectable for tests; production passes the real
      # epoch second.
      def seal(stamped, now: Time.now.to_i, key: default_key)
        mac = mac_for(stamped, now, key)
        "#{HEADER}: #{VERSION}; t=#{now}; d=#{mac}\r\n"
      end

      # True when source carries a valid, unexpired seal over its own
      # remaining bytes. Any parse failure, bad MAC, or stale timestamp is
      # simply false - the caller decides whether that drops the message.
      def verify(source, now: Time.now.to_i, max_age: DEFAULT_MAX_AGE, key: default_key)
        raw = source.to_s
        match = raw.match(LINE)
        return false unless match

        attrs = parse(match[1])
        stamp = attrs["t"].to_i
        return false if attrs["v"] != VERSION || stamp <= 0
        return false if (now - stamp).abs > max_age

        remainder = raw.byteslice(match.end(0)..).to_s
        expected = mac_for(remainder, stamp, key)
        secure_compare(attrs["d"].to_s, expected)
      end

      private

      # HMAC-SHA256 over version, timestamp and a digest of the payload -
      # digesting the payload keeps the MAC input small and fixed-size
      # regardless of message size while still binding every byte.
      def mac_for(payload, timestamp, key)
        data = "#{VERSION}:#{timestamp}:#{Digest::SHA256.hexdigest(payload)}"
        OpenSSL::HMAC.hexdigest("SHA256", key, data)
      end

      def parse(value)
        value.split(";").each_with_object({}) do |part, attrs|
          k, _, v = part.strip.partition("=")
          attrs[k] = v unless k.empty?
        end.tap { |attrs| attrs["v"] ||= VERSION if value.strip.start_with?(VERSION) }
      end

      def secure_compare(given, expected)
        return false if given.empty? || given.bytesize != expected.bytesize

        OpenSSL.fixed_length_secure_compare(given, expected)
      rescue StandardError
        false
      end

      # Both endpoints are inside the host app, so secret_key_base is
      # present. KeyGenerator stretches it into a purpose-specific key so
      # this HMAC key is not reused anywhere else that touches
      # secret_key_base.
      def default_key
        @default_key ||= begin
          base = Rails.application.secret_key_base
          ActiveSupport::KeyGenerator.new(base).generate_key("mail_on_rails ingress seal", 32)
        end
      end
    end
  end
end
