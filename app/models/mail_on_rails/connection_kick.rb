# frozen_string_literal: true

module MailOnRails
  # A command row: "drop this source's live connections now", without
  # persisting a ban (the honeypot kick). The admin UI inserts one row per
  # protocol (request!); each listener's Netserv::OpsSync picks up the rows
  # for its protocol, kicks matching sessions and acknowledges with the
  # count. Rows expire so a listener that is down cannot queue kicks
  # forever, and the UI never waits on processed_at inside a request -
  # the flash is fire-and-forget by design.
  #
  # Banning an IP does NOT insert a kick: the BannedIp row itself is the
  # command - every listener kicks sessions matching its denylist on each
  # sync tick.
  class ConnectionKick < Record
    PROTOCOLS = %w[smtp imap].freeze
    DEFAULT_TTL = 60 # seconds a kick stays claimable

    scope :for_protocol, ->(protocol) { where(protocol: protocol.to_s) }
    scope :pending, -> { where(processed_at: nil).where(expires_at: Time.current..) }

    class << self
      # Queues a kick for +ip+ on each of +protocols+. Returns the rows.
      def request!(ip, protocols: PROTOCOLS, requested_by: nil, ttl: DEFAULT_TTL)
        now = Time.current
        Array(protocols).map do |protocol|
          create!(protocol: protocol.to_s, ip: ip.to_s, requested_by: requested_by,
                  expires_at: now + ttl)
        end
      end

      # Plain-values view of the unprocessed, unexpired kicks for a
      # protocol - what the daemon's sync tick consumes.
      def pending_for(protocol)
        for_protocol(protocol).pending.order(:id).pluck(:id, :ip).map { |id, ip| { id: id, ip: ip } }
      end

      # The daemon's acknowledgement. update_all: no callbacks, no
      # optimistic-lock surprises, and a row that vanished meanwhile is a
      # no-op.
      def acknowledge!(id, kicked:, processed_by: nil)
        where(id: id).update_all(processed_at: Time.current, kicked_count: kicked,
                                 processed_by: processed_by, updated_at: Time.current)
      end

      # Housekeeping: processed or expired rows older than +age+.
      def prune!(age = 1.day)
        where(created_at: ...(Time.current - age)).delete_all
      end
    end
  end
end
