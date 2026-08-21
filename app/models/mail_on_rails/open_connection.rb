# frozen_string_literal: true

module MailOnRails
  # The live connection table: what Netserv::Server#connections returns,
  # projected into the database by each server's Netserv::OpsSync so the
  # admin UI (and /metrics) can show live sessions from any process. One
  # row per open connection; replaced wholesale per listener whenever the
  # listener's picture changes, and gone when the connection closes (or
  # when its listener goes stale - see Listener.prune_stale!).
  #
  # The counterpart to ClosedConnection (history): this table is bounded
  # by the listeners' connection caps, so it needs no rollup.
  class OpenConnection < Record
    belongs_to :listener, primary_key: :listener_id, foreign_key: :listener_id, inverse_of: :open_connections

    scope :for_protocol, ->(protocol) { where(protocol: protocol.to_s) }

    class << self
      # Live rows for a protocol, oldest connection first, restricted to
      # listeners that are still heartbeating (a stale listener's rows are
      # swept shortly; until then they must not show as live).
      def live(protocol, stale_after = Listener.stale_after)
        live_ids = Listener.for_protocol(protocol).fresh(stale_after).select(:listener_id)
        for_protocol(protocol).where(listener_id: live_ids).order(:connected_at, :id)
      end

      # Replaces one listener's rows with +rows+ (the plain-values hashes
      # from Server#connections, keyed by connection_id). Delete + insert
      # in one transaction rather than an upsert: portable across the
      # three adapters and the set is small (at most the listener's cap).
      def replace_for!(listener_id, protocol, rows)
        now = Time.current
        records = rows.map do |row|
          row = row.symbolize_keys
          {
            listener_id: listener_id,
            connection_id: row.fetch(:connection_id),
            protocol: protocol.to_s,
            peer_ip: row[:peer_ip],
            port: row[:port],
            role: row[:role]&.to_s,
            connected_at: row[:connected_at],
            tarpit: row[:tarpit],
            username: row[:user] || row[:username],
            helo: row[:helo],
            messages: row[:messages],
            tls: row[:tls].nil? ? nil : row[:tls] ? true : false,
            state: row[:state],
            created_at: now,
            updated_at: now
          }
        end
        transaction do
          where(listener_id: listener_id).delete_all
          insert_all(records) if records.any?
        end
      end
    end

    def user = username
  end
end
