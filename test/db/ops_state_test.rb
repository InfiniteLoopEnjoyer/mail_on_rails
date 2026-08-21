# frozen_string_literal: true

require_relative "test_helper"

# The database side of the daemons' ops-state projection (Netserv::OpsSync
# writes through Store::Base): listener heartbeats and staleness, the live
# connection and lockout tables replaced per listener, kick commands, and
# the UI-facing readers that hide stale listeners.
class OpsStateTest < DbSuite::TestCase
  LISTENER = "11111111-1111-4111-8111-111111111111"
  OTHER = "22222222-2222-4222-8222-222222222222"

  def listener_attrs(id = LISTENER, protocol: "smtp", **extra)
    { listener_id: id, protocol: protocol, pid: 4242, hostname: "mx1", ports: [ 1025, 1587 ],
      max_connections: 100, ready: true, started_at: Time.current - 60 }.merge(extra)
  end

  def store = MailOnRails::Store::Base.new

  test "touch! inserts a listener then heartbeats it" do
    MailOnRails::Listener.touch!(listener_attrs(ready: false))
    row = MailOnRails::Listener.find_by!(listener_id: LISTENER)
    assert_equal "smtp", row.protocol
    assert_equal [ 1025, 1587 ], row.ports
    assert_equal 4242, row.pid
    refute row.ready
    first_beat = row.heartbeat_at

    sleep 0.01
    MailOnRails::Listener.touch!(listener_attrs(ready: true))
    row.reload
    assert row.ready
    assert_operator row.heartbeat_at, :>=, first_beat
    assert_equal 1, MailOnRails::Listener.count
  end

  test "alive hides listeners whose heartbeat went stale, and prune_stale! sweeps them with their rows" do
    MailOnRails::Listener.touch!(listener_attrs)
    MailOnRails::Listener.touch!(listener_attrs(OTHER, protocol: "imap"))
    MailOnRails::OpenConnection.replace_for!(OTHER, "imap", [ { connection_id: 1, peer_ip: "203.0.113.5", connected_at: Time.current } ])
    MailOnRails::AcceptLockout.replace_for!(OTHER, "imap", { "198.51.100.1" => Time.current + 600 })
    MailOnRails::Listener.where(listener_id: OTHER).update_all(heartbeat_at: Time.current - 120)

    assert_equal [ LISTENER ], MailOnRails::Listener.alive("smtp").map(&:listener_id)
    assert_empty MailOnRails::Listener.alive("imap"), "stale listener is not alive"
    assert_empty MailOnRails::OpenConnection.live("imap"), "a stale listener's connections are not live"
    assert_empty MailOnRails::AcceptLockout.active("imap")

    assert_equal 1, MailOnRails::Listener.prune_stale!(30)
    assert_nil MailOnRails::Listener.find_by(listener_id: OTHER)
    assert_equal 0, MailOnRails::OpenConnection.where(listener_id: OTHER).count
    assert_equal 0, MailOnRails::AcceptLockout.where(listener_id: OTHER).count
    assert MailOnRails::Listener.exists?(listener_id: LISTENER), "fresh listener untouched"
  end

  test "replace_for! swaps a listener's live connections wholesale, mapping the server's hash shape" do
    MailOnRails::Listener.touch!(listener_attrs)
    t0 = Time.current - 30
    rows = [
      { connection_id: 1, protocol: "SMTP", peer_ip: "203.0.113.9", port: 1025, role: :mx, connected_at: t0,
        tarpit: 1.5, user: nil, helo: "client.test", messages: 2, tls: true },
      { connection_id: 2, peer_ip: "198.51.100.7", port: 1587, role: :submission, connected_at: t0 + 5,
        user: "alice@example.test", tls: false }
    ]
    MailOnRails::OpenConnection.replace_for!(LISTENER, "smtp", rows)
    live = MailOnRails::OpenConnection.live("smtp").to_a
    assert_equal [ 1, 2 ], live.map(&:connection_id)
    first = live.first
    assert_equal "smtp", first.protocol
    assert_equal "mx", first.role
    assert_equal "client.test", first.helo
    assert_equal 2, first.messages
    assert_in_delta 1.5, first.tarpit
    assert first.tls
    assert_equal "alice@example.test", live.last.username
    assert_equal "alice@example.test", live.last.user
    refute live.last.tls

    MailOnRails::OpenConnection.replace_for!(LISTENER, "smtp", rows.last(1))
    assert_equal [ 2 ], MailOnRails::OpenConnection.live("smtp").map(&:connection_id)

    MailOnRails::OpenConnection.replace_for!(LISTENER, "smtp", [])
    assert_empty MailOnRails::OpenConnection.live("smtp")
  end

  test "accept lockouts read back as seconds remaining and expire on their own" do
    MailOnRails::Listener.touch!(listener_attrs)
    MailOnRails::AcceptLockout.replace_for!(LISTENER, "smtp",
                                            { "198.51.100.1" => Time.current + 600, "198.51.100.2" => Time.current - 5 })
    active = MailOnRails::AcceptLockout.active("smtp")
    assert_equal [ "198.51.100.1" ], active.keys
    assert_in_delta 600, active["198.51.100.1"], 2
  end

  test "kick commands: request per protocol, pending for the daemon, acknowledged with the count, expiring" do
    rows = MailOnRails::ConnectionKick.request!("203.0.113.9", requested_by: "admin@example.test", ttl: 60)
    assert_equal %w[smtp imap], rows.map(&:protocol)
    assert_equal [ { id: rows.first.id, ip: "203.0.113.9" } ], MailOnRails::ConnectionKick.pending_for("smtp")

    MailOnRails::ConnectionKick.acknowledge!(rows.first.id, kicked: 3, processed_by: LISTENER)
    assert_empty MailOnRails::ConnectionKick.pending_for("smtp")
    assert_equal 3, rows.first.reload.kicked_count
    assert_equal LISTENER, rows.first.processed_by

    MailOnRails::ConnectionKick.where(id: rows.last.id).update_all(expires_at: Time.current - 1)
    assert_empty MailOnRails::ConnectionKick.pending_for("imap"), "an expired kick is not offered"

    MailOnRails::ConnectionKick.where(id: rows.map(&:id)).update_all(created_at: Time.current - 2.days)
    assert_equal 2, MailOnRails::ConnectionKick.prune!(1.day)
  end

  test "Store::Base#sync_ops_state writes the listener, and connections/lockouts only when given" do
    result = store.sync_ops_state(listener: listener_attrs,
                                  connections: [ { connection_id: 9, peer_ip: "203.0.113.9", connected_at: Time.current } ],
                                  lockouts: { "198.51.100.1" => Time.current + 60 })
    assert_equal({}, result)
    assert_equal 1, MailOnRails::Listener.alive("smtp").size
    assert_equal [ 9 ], MailOnRails::OpenConnection.live("smtp").map(&:connection_id)
    assert_equal [ "198.51.100.1" ], MailOnRails::AcceptLockout.active("smtp").keys

    store.sync_ops_state(listener: listener_attrs) # heartbeat only
    assert_equal [ 9 ], MailOnRails::OpenConnection.live("smtp").map(&:connection_id), "nil leaves the rows alone"

    assert_equal [], store.pending_kicks("smtp")
    MailOnRails::ConnectionKick.request!("203.0.113.9", protocols: [ "smtp" ])
    kick = store.pending_kicks("smtp").first
    assert_equal "203.0.113.9", kick[:ip]
    assert_equal({}, store.ack_kick(kick[:id], kicked: 1, processed_by: LISTENER))
    assert_equal [], store.pending_kicks("smtp")

    assert_equal({ pruned: 0 }, store.prune_stale_listeners(30))
    assert_equal({}, store.remove_listener(LISTENER))
    assert_empty MailOnRails::Listener.alive("smtp")
    assert_empty MailOnRails::OpenConnection.where(listener_id: LISTENER)
  end
end
