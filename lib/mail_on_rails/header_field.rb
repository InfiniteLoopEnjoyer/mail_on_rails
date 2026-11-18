# frozen_string_literal: true

module MailOnRails
  # Where a header field's name ends - one answer for every scanner that
  # looks for a field by name on raw message bytes.
  #
  # RFC 5322 says a name is printable ASCII (33-126, no colon) and that
  # the colon follows it directly; obs-syntax also allows WSP in between.
  # Parsers are more generous than that, each in its own way: the Mail
  # gem ends a name with Ruby's rstrip, which drops NUL, TAB, LF, VT, FF,
  # CR and SP. A scanner that only tolerates [ \t]* before the colon
  # therefore reads "X-Original-To\v: victim" as some unknown field while
  # the mailroom reads it as X-Original-To - a forged trusted header the
  # strip keeps and the seal covers; and "From\f: ceo@bank" is no From to
  # the DMARC/MSA checks and the one the reader is shown.
  #
  # So the scanners here take the widest reading anything downstream
  # could: every byte outside printable ASCII around the name - between
  # it and the colon, or in front of it (the gem lstrips the first field,
  # and a reader that strips both sides is easy to write) - belongs to
  # the gap, not to a different name. The SMTP edge refuses messages that
  # carry such a field at all (control_in_name?), which leaves "Name :" -
  # space or tab, the obs-syntax - as the only gap a stored message can
  # contain.
  #
  # Stdlib-only: the SMTP session and the sender-auth primitives load it
  # without Rails.
  module HeaderField
    # Regexp source for the bytes that may sit around a name.
    GAP = '[^\x21-\x7e]*'

    # A C0 control other than HT/LF/CR, or DEL. LF and CR only reach a
    # field through a fold, which is WSP to every reader.
    CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/

    module_function

    # Matches a field (one header, folded or unfolded) carrying one of
    # +names+ - each a String, or a Regexp source fragment such as
    # "X-MailOnRails-[\\w-]+" when +literal+ is false.
    def matcher(*names, literal: true)
      alternatives = names.map { |name| literal ? Regexp.escape(name) : name }.join("|")
      /\A#{GAP}(?:#{alternatives})#{GAP}:/i
    end

    # The field's name as the most lenient reader takes it: the text
    # before the first colon, minus the gap on either side. nil for a
    # line with no colon (no reader makes a field of that).
    def name(field)
      before, colon, = field.to_s.b.partition(":")
      colon.empty? ? nil : before.gsub(/\A[^\x21-\x7e]+|[^\x21-\x7e]+\z/, "")
    end

    # The header block of a CRLF-canonical message as bytes: everything
    # before the first empty line, the last field's CRLF included. Empty
    # when the message opens with the empty line (all body).
    def block(data)
      data = data.to_s
      data = data.b unless data.encoding == Encoding::BINARY
      return "".b if data.start_with?("\r\n")

      stop = data.index("\r\n\r\n")
      stop ? data.byteslice(0, stop + 2) : data
    end

    # One element per header field, folds left in place.
    def fields(data)
      block(data).split(/\r\n(?![ \t])/)
    end

    # True when some header field of +data+ (CRLF-canonical) has a control
    # byte in or around its name - before the colon, anywhere. No sender
    # writes that by accident, and it is exactly the shape that splits one
    # parser's reading from another's. Space and tab are not controls
    # here: "Name :" stays legal.
    def control_in_name?(data)
      fields(data).any? do |field|
        before, colon, = field.partition(":")
        !colon.empty? && before.match?(CONTROL)
      end
    end
  end
end
