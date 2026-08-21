# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/netserv/ops_sync"
require "mail_on_rails/netserv/denylist"

# Netserv::OpsSync against a scripted server and a recording store: the
# tick projects the live picture only when it changed, heartbeats every
# time, announces changes through the activity hook AFTER writing, kicks
# banned peers and pending kick commands, sweeps stale listeners, and
# survives a failing store. The database side of the same methods is
# test/db/ops_state_test.rb.
class OpsSyncTest < Minitest::Test
  class FakeServer
    attr_accessor :connections, :lockouts, :kicked, :denylist
    attr_reader :notified

    def initialize
      @connections = []
      @lockouts = {}
      @kicked = []
      @notified = 0
      @denylist = nil
    end

    def protocol_name = "SMTP"
    def ready? = true
    def dead? = false
    def listener_ports = [ 1025, 1587 ]
    def max_connections = 100

    def kick(&matcher)
      victims = @connections.select { |c| matcher.call(c[:peer_ip]) }
      @kicked.concat(victims.map { |c| c[:peer_ip] })
      @connections -= victims
      victims.size
    end

    def notify_activity
      @notified += 1
    end
  end

  class RecordingStore
    attr_reader :calls, :logs
    attr_accessor :kicks, :banned, :raise_on

    def initialize
      @calls = []
      @logs = []
      @kicks = []
      @banned = []
      @raise_on = nil
    end

    def log(level, message)
      @logs << [ level, message ]
    end

    def banned_cidrs = @banned

    def sync_ops_state(listener:, connections: nil, lockouts: nil)
      raise "db down" if @raise_on == :sync

      @calls << [ :sync, listener, connections, lockouts ]
      {}
    end

    def pending_kicks(protocol)
      raise "db down" if @raise_on == :kicks

      @calls << [ :pending_kicks, protocol ]
      @kicks
    end

    def ack_kick(id, kicked:, processed_by: nil)
      @calls << [ :ack_kick, id, kicked, processed_by ]
      {}
    end

    def prune_stale_listeners(stale_after)
      @calls << [ :prune, stale_after ]
      { pruned: 0 }
    end

    def remove_listener(listener_id)
      @calls << [ :remove, listener_id ]
      {}
    end
  end

  # A store with none of the optional ops methods - the memory stores.
  class BareStore
    attr_reader :logs

    def initialize = @logs = []
    def log(level, message) = @logs << [ level, message ]
  end

  def setup
    @server = FakeServer.new
    @store = RecordingStore.new
    @sync = MailOnRails::Netserv::OpsSync.new(@server, @store, interval: 0.05, stale_after: 30)
  end

  def syncs = @store.calls.select { |c| c.first == :sync }

  test "a connection id sequence is per listener and monotonic" do
    ids = Array.new(3) { @sync.next_connection_id }
    assert_equal [ 1, 2, 3 ], ids
    refute_empty @sync.listener_id
  end

  test "an unchanged empty picture only heartbeats the listener and announces nothing" do
    @sync.tick
    @sync.tick
    assert_equal 2, syncs.size
    syncs.each do |_, listener, connections, lockouts|
      assert_equal @sync.listener_id, listener[:listener_id]
      assert_equal "smtp", listener[:protocol]
      assert_equal [ 1025, 1587 ], listener[:ports]
      assert_equal 100, listener[:max_connections]
      assert listener[:ready]
      assert_nil connections, "unchanged picture writes no connection rows"
      assert_nil lockouts
    end
    assert_equal 0, @server.notified
  end

  test "a changed picture is written and then announced, once" do
    @server.connections = [ { connection_id: 1, peer_ip: "203.0.113.9", port: 1025, connected_at: Time.at(0) } ]
    @sync.tick
    assert_equal 1, @server.notified
    _, _, connections, lockouts = syncs.last
    assert_equal [ "203.0.113.9" ], connections.map { |c| c[:peer_ip] }
    assert_equal({}, lockouts)

    @sync.tick
    assert_equal 1, @server.notified, "steady state announces nothing"
    assert_nil syncs.last[2]

    @server.connections = []
    @sync.tick
    assert_equal 2, @server.notified, "the departure is a change"
    assert_equal [], syncs.last[2]
  end

  test "lockouts are projected as deadlines rounded to the second, so a countdown is not a change" do
    @server.lockouts = { "198.51.100.1" => 600.4 }
    @sync.tick
    _, _, _, lockouts = syncs.last
    assert_equal [ "198.51.100.1" ], lockouts.keys
    assert_kind_of Time, lockouts["198.51.100.1"]
    assert_equal 0, lockouts["198.51.100.1"].usec
    assert_equal 1, @server.notified

    @server.lockouts = { "198.51.100.1" => 600.35 } # a few ms later
    @sync.tick
    assert_equal 1, @server.notified, "the same deadline is not a change"
  end

  test "pending kicks drop the named peer and are acknowledged with the count" do
    @server.connections = [
      { connection_id: 1, peer_ip: "203.0.113.9" }, { connection_id: 2, peer_ip: "203.0.113.9" },
      { connection_id: 3, peer_ip: "198.51.100.7" }
    ]
    @store.kicks = [ { id: 42, ip: "203.0.113.9" } ]
    @sync.tick
    assert_equal %w[203.0.113.9 203.0.113.9], @server.kicked
    ack = @store.calls.find { |c| c.first == :ack_kick }
    assert_equal [ :ack_kick, 42, 2, @sync.listener_id ], ack
    assert_equal [ "198.51.100.7" ], @server.connections.map { |c| c[:peer_ip] }
  end

  test "a ban on the denylist drops live sessions from that address" do
    @store.banned = [ "203.0.113.0/24" ]
    @server.denylist = MailOnRails::Netserv::Denylist.new(@store, ttl: 0)
    @server.connections = [ { connection_id: 1, peer_ip: "203.0.113.9" }, { connection_id: 2, peer_ip: "198.51.100.7" } ]
    @sync.tick
    assert_equal [ "203.0.113.9" ], @server.kicked
    assert(@store.logs.any? { |_, m| m.include?("dropped 1 connection") })
  end

  test "every tick sweeps stale listeners" do
    @sync.tick
    assert_includes @store.calls, [ :prune, 30 ]
  end

  test "a failing store step does not stop the other steps or the next tick, and warns once" do
    @store.raise_on = :sync
    @store.kicks = [ { id: 7, ip: "203.0.113.9" } ]
    @sync.tick
    @sync.tick
    assert(@store.calls.any? { |c| c.first == :ack_kick }, "kicks still processed")
    warnings = @store.logs.select { |level, m| level == :warn && m.include?("ops sync sync failed") }
    assert_equal 1, warnings.size, "one warning for a repeating failure"
  end

  test "a store without the ops methods still gets change detection and the hook" do
    bare = BareStore.new
    sync = MailOnRails::Netserv::OpsSync.new(@server, bare, interval: 0.05)
    @server.connections = [ { connection_id: 1, peer_ip: "203.0.113.9" } ]
    sync.tick
    assert_equal 1, @server.notified
    assert_empty bare.logs
  end

  test "the thread ticks on its interval and cleanup removes the listener on stop" do
    @sync.start
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    sleep 0.01 until syncs.size >= 2 || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    assert_operator syncs.size, :>=, 2
    @sync.stop
    assert_equal [ :remove, @sync.listener_id ], @store.calls.last
  end

  test "the interval never goes below 50ms and survives a broken setting" do
    assert_in_delta 0.05, MailOnRails::Netserv::OpsSync.new(@server, @store, interval: 0).interval
    assert_in_delta 2.0, MailOnRails::Netserv::OpsSync.new(@server, @store, interval: -> { raise "x" }).interval,
                    0.001, "a broken resolver falls back to the default cadence"
    assert_in_delta 2.0, MailOnRails::Netserv::OpsSync.new(@server, @store).interval, 0.001
  end
end
