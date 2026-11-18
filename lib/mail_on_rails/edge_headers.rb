# frozen_string_literal: true

module MailOnRails
  # The trusted headers the SMTP edge prepends to a message (the ingress
  # seal, then Store::SmtpBackend#stamp's Return-Path / X-Original-To /
  # X-MailOnRails-* lines), read from where the edge put them and nowhere
  # else: the unbroken run of such lines at the very top of the source.
  # The first line that is anything else - the message's own first header -
  # ends it.
  #
  # Deliberately not a mail parser's reading of these names. The edge
  # strips forged copies from the submitted DATA, but "the same field" is
  # whatever each parser makes of the bytes: the Mail gem takes
  # "X-Original-To\v: victim" as a recipient and lets a later
  # "Return-Path\f:" REPLACE the stamped one (singular field, last wins),
  # and before that it was a lone CR. Whatever a strip misses next, a copy
  # below the block is not read here - so the worst a forged trusted
  # header can be is an unknown header in the message.
  #
  # Stdlib-only: the mailroom and the jobs that read these facts back out
  # of a stored message (which keeps the block at its top) share it.
  module EdgeHeaders
    # One line of the block: the name, a colon, the value, on a single
    # physical line - the only shape stamp writes (sanitize_header drops
    # CR/LF, so a value never folds).
    LINE = /\A(X-MailOnRails-[\w-]+|Return-Path|X-Original-To):[ \t]*(.*?)\r?\n?\z/i

    module_function

    # => { "x-original-to" => [values...], ... } keyed by lowercased name.
    def read(source)
      headers = Hash.new { |hash, name| hash[name] = [] }
      source.to_s.b.each_line do |line|
        match = LINE.match(line)
        break unless match

        headers[match[1].downcase] << match[2].force_encoding(Encoding::UTF_8).scrub
      end
      headers
    end
  end
end
