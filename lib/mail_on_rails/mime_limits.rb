# frozen_string_literal: true

require "mail_on_rails/header_field"

module MailOnRails
  # Bounds on the MIME structure the mail-processing pipeline is willing
  # to walk. The Mail gem parses a message's body lazily and then walks
  # the multipart tree recursively (text_part / all_parts / attachments):
  # cost grows quadratically with nesting depth and a few thousand nested
  # multipart/* levels raise SystemStackError - which, not being a
  # StandardError, sails past every ordinary rescue. The SMTP edge only
  # bounds size. So before any tree walk the inbound path measures the
  # structure here, on the raw bytes, in one linear pass that never
  # recurses: a message over either cap is stored and shown as opaque
  # (headers, raw source) rather than parsed.
  #
  # Depth is the deepest stack of open multipart boundaries; parts is the
  # number of part-delimiter lines (`--boundary`) that belong to a declared
  # boundary. Real mail sits at depth 2-4 and a few dozen parts; nothing
  # legitimate approaches these caps, which are set well below the point
  # where the Mail gem's walk becomes measurable (depth 200 ~ 0.2 s CPU).
  module MimeLimits
    MAX_DEPTH = 50
    MAX_PARTS = 1000

    Measurement = Data.define(:depth, :parts) do
      def too_complex?
        depth > MAX_DEPTH || parts > MAX_PARTS
      end
    end

    # A Content-Type header line, or a folded continuation line, carrying a
    # boundary parameter. Folding means the parameter can sit on its own
    # line, so a leading WSP line counts too; a body line that happens to
    # say "boundary=" can only over-count, never under-count.
    #
    # Under-counting is the failure that matters, so the match is as wide
    # as the Mail gem's own reading: the gap it allows around the header's
    # name (HeaderField - "Content-Type :" is the same field to it), WSP
    # around the "=", and the RFC 2231 "boundary*" spellings (capture 1).
    BOUNDARY_PARAM = /\A(?:#{HeaderField::GAP}Content-Type#{HeaderField::GAP}:|[ \t]).*?
                      boundary(\*[\d*]*)?[ \t]*=[ \t]*(?:"((?:[^"\\]|\\.)*)"|([^;\s"]+))/ix

    module_function

    # True when the raw message's MIME structure is past what the pipeline
    # will parse.
    def too_complex?(raw)
      measure(raw).too_complex?
    end

    # Measures depth and part count with an explicit boundary stack. Stops
    # early once either cap is crossed - the result is then "over the cap",
    # not an exact count - so the pass is bounded even on a 24 MiB message.
    def measure(raw)
      stack = []
      depth = 0
      parts = 0
      # Binary view: the regexes are ASCII-only and must not raise on
      # invalid UTF-8 (raw mail is whatever the wire carried).
      raw.to_s.b.each_line do |line|
        if line.start_with?("--")
          # "--name--" closes a boundary; "--name" opens a part of it. A
          # delimiter of an outer boundary implicitly closes every inner
          # part still open (the Mail gem tolerates a missing close
          # delimiter the same way). Lines matching no declared boundary
          # are body text (a "-- " signature separator, say).
          token = line.chomp.rstrip
          if token.end_with?("--") && (index = stack.rindex(token[2...-2]))
            stack.slice!(index..)
          elsif (index = stack.rindex(token[2..]))
            stack.slice!((index + 1)..)
            parts += 1
            break if parts > MAX_PARTS
          end
        elsif (match = BOUNDARY_PARAM.match(line))
          # An RFC 2231 boundary (continued, or charset-encoded) is put
          # together by the gem from pieces a line-at-a-time pass cannot
          # follow, so its delimiters could not be matched below. Nothing
          # legitimate spells a boundary that way: past the cap, unparsed.
          return Measurement.new(depth: MAX_DEPTH + 1, parts: parts) if match[1]

          name = match[2] ? match[2].gsub(/\\(.)/m, '\1') : match[3]
          next if name.empty?

          stack << name
          depth = stack.size if stack.size > depth
          break if depth > MAX_DEPTH
        end
      end
      Measurement.new(depth: depth, parts: parts)
    end
  end
end
