# frozen_string_literal: true

module MailOnRails
  # IDNA conversion for internationalized domain names (SMTPUTF8 / RFC
  # 6531 envelopes may carry U-labels; DNS wants A-labels/punycode).
  # Degrades gracefully: without the simpleidn gem, or for a name that
  # will not convert, the input comes back unchanged - the DNS lookup
  # then simply finds nothing, which every caller already handles.
  module Idn
    module_function

    def to_ascii(name)
      text = name.to_s
      return text if text.ascii_only?

      require "simpleidn"
      SimpleIDN.to_ascii(text.dup.force_encoding(Encoding::UTF_8))
    rescue StandardError
      text
    end
  end
end
