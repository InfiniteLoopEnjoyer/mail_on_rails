# frozen_string_literal: true

module MailOnRails
  module Smtp
    # Wire-safe framing for mail we send. RFC 5321 2.3.8: an SMTP client
    # MUST NOT transmit NUL, or CR/LF except as the two-byte CRLF sequence.
    # Canonicalizing before DKIM and Net::SMTP#send_message also closes
    # outbound SMTP smuggling: a stored `\r\n\x00.\r\n` would otherwise
    # reach a NUL-stripping next hop as the real DATA terminator.
    module OutboundData
      module_function

      def canonicalize(raw)
        data = raw.to_s.b
        data.delete!("\0")
        data.gsub!("\r\n", "\n")
        data.gsub!("\r", "\n")
        data.gsub!("\n", "\r\n")
        data
      end
    end
  end
end
