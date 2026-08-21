# frozen_string_literal: true

module MailOnRails
  # Display-only projection of the accept-side per-IP auth lockouts
  # (Netserv::AuthThrottle#locked_ips): addresses the listener refuses
  # before a session exists, so they never appear in open_connections.
  # Written by Netserv::OpsSync alongside the live connections; the accept
  # path itself never reads this table (refusing a banned scanner must
  # not cost a database checkout).
  #
  # Not to be confused with the AR AuthThrottle model, which is the
  # store-level credential budget shared by IMAP, SMTP AUTH and the web
  # login. Both can appear on an ops page; they are different things.
  class AcceptLockout < Record
    belongs_to :listener, primary_key: :listener_id, foreign_key: :listener_id, inverse_of: :accept_lockouts

    scope :for_protocol, ->(protocol) { where(protocol: protocol.to_s) }

    class << self
      # { ip => seconds remaining } for a protocol, across live listeners.
      def active(protocol, stale_after = Listener.stale_after)
        now = Time.current
        live_ids = Listener.for_protocol(protocol).fresh(stale_after).select(:listener_id)
        for_protocol(protocol).where(listener_id: live_ids).where(locked_until: now..)
                              .order(:locked_until).pluck(:ip, :locked_until)
                              .each_with_object({}) { |(ip, until_at), h| h[ip] = [ h[ip].to_i, (until_at - now).ceil ].max }
      end

      # Replaces one listener's rows. +lockouts+ is { ip => locked_until }.
      def replace_for!(listener_id, protocol, lockouts)
        now = Time.current
        records = lockouts.map do |ip, locked_until|
          { listener_id: listener_id, protocol: protocol.to_s, ip: ip.to_s,
            locked_until: locked_until, created_at: now, updated_at: now }
        end
        transaction do
          where(listener_id: listener_id).delete_all
          insert_all(records) if records.any?
        end
      end
    end
  end
end
