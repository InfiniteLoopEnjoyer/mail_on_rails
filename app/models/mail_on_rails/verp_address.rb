require "openssl"

# VERP (Variable Envelope Return Path) addresses for outbound list mail:
# the envelope sender becomes bounce+m<row id>-<mac>@<sender domain>, so
# any asynchronous bounce - however garbled its body - identifies the
# exact SmtpOutboundMessage by the address it comes back to. The MAC
# (HMAC-SHA256 over the row id, keyed from the app secret, truncated)
# keeps the local part inside RFC 5321's 64-octet budget while making
# forged bounce+ addresses unguessable - without it, anyone could mail
# bounce+m<n>-x@us and fabricate bounce evidence against arbitrary
# recipients. The row id (not the recipient) is encoded so decode hands
# back the authoritative (recipient, sender) pair from the queue row.
module MailOnRails
  class VerpAddress
    LOCAL_PATTERN = /\A#{Domain::BOUNCE_LOCAL_PART}\+m(\d{1,18})-(\h{12})\z/
    MAC_BYTES = 6 # 12 hex chars: unforgeable in practice, tiny on the wire

    # "bounce+m42-a1b2c3d4e5f6@example.test" for the message's sender domain.
    def self.encode(message)
      domain = message.mail_from.to_s.split("@").last.to_s.strip.downcase
      "#{Domain::BOUNCE_LOCAL_PART}+m#{message.id}-#{mac(message.id)}@#{domain}"
    end

    # Structurally a VERP address with a valid MAC? Cheap (no database) -
    # the edge uses this at RCPT time, so junk mailed at bounce+garbage
    # never even counts as a local recipient.
    def self.valid?(address)
      local, _, _domain = address.to_s.strip.downcase.partition("@")
      match = LOCAL_PATTERN.match(local)
      !match.nil? && secure_compare(match[2], mac(match[1]))
    end

    # The SmtpOutboundMessage a bounce is about, or nil (bad MAC, or the
    # row has since been deleted).
    def self.decode(address)
      local, _, _domain = address.to_s.strip.downcase.partition("@")
      match = LOCAL_PATTERN.match(local)
      return nil unless match && secure_compare(match[2], mac(match[1]))

      SmtpOutboundMessage.find_by(id: match[1])
    end

    def self.mac(id)
      OpenSSL::HMAC.hexdigest("SHA256", Rails.application.secret_key_base.to_s, "mail_on_rails/verp:#{id.to_i}")[0, MAC_BYTES * 2]
    end

    def self.secure_compare(a, b)
      OpenSSL.secure_compare(a.to_s, b.to_s)
    end
  end
end
