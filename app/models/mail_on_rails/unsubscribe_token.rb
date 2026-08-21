# The signed, self-contained capability behind both List-Unsubscribe
# surfaces: it binds one (recipient, sender) pair, so possessing a token
# proves you received that sender's mail - no session, account, or
# lookup involved. OutboundDeliverer mints one per outbound list message;
# UnsubscribesController (the RFC 8058 https one-click endpoint) and
# IngestUnsubscribeJob (the mailto: fallback) verify it and record the
# sender-scoped suppression.
#
# Long expiry on purpose: RFC 8058 wants unsubscribe links to keep
# working long after delivery - people act on months-old newsletters.
module MailOnRails
  class UnsubscribeToken
    PURPOSE = "mail_on_rails/unsubscribe"
    TTL = 1.year

    def self.generate(recipient:, sender:)
      verifier.generate({ "r" => recipient.to_s.strip.downcase, "s" => sender.to_s.strip.downcase },
                        purpose: PURPOSE, expires_in: TTL)
    end

    # { recipient:, sender: } for a valid token; nil for anything
    # tampered, expired, or malformed - never raises.
    def self.verify(token)
      data = verifier.verified(token.to_s, purpose: PURPOSE)
      return nil unless data.is_a?(Hash) && data["r"].present? && data["s"].present?

      { recipient: data["r"], sender: data["s"] }
    rescue StandardError
      nil
    end

    # Derived from the host app's secret_key_base, so tokens survive
    # restarts and verify in any of the app's processes.
    def self.verifier
      Rails.application.message_verifier(PURPOSE)
    end
  end
end
