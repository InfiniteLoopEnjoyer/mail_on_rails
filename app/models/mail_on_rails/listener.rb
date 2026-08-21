# frozen_string_literal: true

module MailOnRails
  # One row per running mail server (an SMTP or IMAP Netserv::Server
  # instance), written and heartbeated by that server's Netserv::OpsSync
  # thread. The admin UI reads it to say "SMTP is up (3 ports, pid N on
  # host H)" no matter which container the listener lives in; the live
  # connection and lockout tables hang off it by listener_id.
  #
  # A listener that stops heartbeating for STALE_AFTER (default, see
  # Settings[:ops_stale_after]) is presumed dead - a killed container
  # that never ran its shutdown - and every other live listener's sync
  # tick sweeps it and its rows (prune_stale!).
  class Listener < Record
    PROTOCOLS = %w[smtp imap].freeze

    has_many :open_connections, primary_key: :listener_id, foreign_key: :listener_id,
                                inverse_of: :listener, dependent: :delete_all
    has_many :accept_lockouts, primary_key: :listener_id, foreign_key: :listener_id,
                               inverse_of: :listener, dependent: :delete_all

    scope :for_protocol, ->(protocol) { where(protocol: protocol.to_s) }
    scope :fresh, ->(stale_after = Listener.stale_after) { where(heartbeat_at: (Time.current - stale_after)..) }

    class << self
      def stale_after = MailOnRails::Settings[:ops_stale_after]

      # The live listeners for a protocol (usually one; more if an
      # operator runs several containers).
      def alive(protocol)
        for_protocol(protocol).fresh.order(:started_at).to_a
      end

      # Insert-or-heartbeat for one server's row. +attrs+ is the plain
      # hash Netserv::OpsSync assembles (listener_id, protocol, pid,
      # hostname, ports, max_connections, ready, started_at).
      def touch!(attrs)
        attrs = attrs.symbolize_keys
        now = Time.current
        updates = attrs.slice(:pid, :hostname, :ports, :max_connections, :ready)
                       .merge(heartbeat_at: now, updated_at: now)
        updated = where(listener_id: attrs.fetch(:listener_id)).update_all(updates)
        return if updated.positive?

        create!(attrs.slice(:listener_id, :protocol, :pid, :hostname, :ports, :max_connections, :ready)
                     .merge(started_at: attrs[:started_at] || now, heartbeat_at: now))
      rescue ActiveRecord::RecordNotUnique
        retry
      end

      # Removes a listener and everything it projected (clean shutdown).
      def remove!(listener_id)
        OpenConnection.where(listener_id: listener_id).delete_all
        AcceptLockout.where(listener_id: listener_id).delete_all
        where(listener_id: listener_id).delete_all
      end

      # Sweeps listeners whose heartbeat is older than +stale_after+
      # seconds, with their rows. Returns how many listeners went.
      def prune_stale!(stale_after = Listener.stale_after)
        cutoff = Time.current - stale_after
        ids = where(heartbeat_at: ...cutoff).pluck(:listener_id)
        return 0 if ids.empty?

        OpenConnection.where(listener_id: ids).delete_all
        AcceptLockout.where(listener_id: ids).delete_all
        where(listener_id: ids).delete_all
      end
    end

    def stale?(stale_after = self.class.stale_after)
      heartbeat_at < Time.current - stale_after
    end
  end
end
