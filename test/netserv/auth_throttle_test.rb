# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/netserv/auth_throttle"

class AuthThrottleTest < Minitest::Test
  Throttle = MailOnRails::Netserv::AuthThrottle
  IP = "192.0.2.1"

  def setup
    @now = 1000.0
    @throttle = Throttle.new(limit: 3, window: 60, clock: -> { @now })
  end

  test "locks after the limit and reports the transition exactly once" do
    assert_nil @throttle.record(IP)
    assert_nil @throttle.record(IP)
    refute @throttle.locked?(IP), "below the limit must not lock"
    assert_equal :locked, @throttle.record(IP)
    assert @throttle.locked?(IP)
    assert_nil @throttle.record(IP), "the lock transition must be reported only once"
  end

  test "the lockout expires after the window" do
    3.times { @throttle.record(IP) }
    @now += 61

    refute @throttle.locked?(IP)
  end

  test "a quiet period forgives the failure count" do
    2.times { @throttle.record(IP) }
    @now += 61
    @throttle.record(IP) # would be the 3rd without decay

    refute @throttle.locked?(IP), "decayed failures must not count toward the lockout"
  end

  test "failures while locked extend the lockout" do
    3.times { @throttle.record(IP) }
    @now += 30
    @throttle.record(IP) # an in-flight session failing again
    @now += 45           # 75s past the original lock, 45s past the extension

    assert @throttle.locked?(IP)
  end

  test "ips are tracked independently" do
    3.times { @throttle.record(IP) }

    refute @throttle.locked?("192.0.2.2")
  end

  test "nil or zero limit disables the throttle" do
    [ nil, 0 ].each do |limit|
      throttle = Throttle.new(limit: limit, window: 60, clock: -> { @now })
      5.times { assert_nil throttle.record(IP) }

      refute throttle.locked?(IP)
    end
  end

  test "nil ip is ignored" do
    assert_nil @throttle.record(nil)
    refute @throttle.locked?(nil)
  end

  test "locked_ips snapshots current lockouts with seconds remaining" do
    assert_empty @throttle.locked_ips

    3.times { @throttle.record(IP) }
    2.times { @throttle.record("192.0.2.2") } # below the limit: not locked
    @now += 20

    locked = @throttle.locked_ips

    assert_equal [ IP ], locked.keys
    assert_in_delta 40.0, locked[IP]

    @now += 41

    assert_empty @throttle.locked_ips, "expired lockouts must drop out of the snapshot"
  end

  test "locked_ips is empty when the throttle is disabled" do
    throttle = Throttle.new(limit: nil, window: 60, clock: -> { @now })
    5.times { throttle.record(IP) }

    assert_empty throttle.locked_ips
  end

  test "ipv6 failures inside one /64 lock the /64; a neighbouring /64 is untouched" do
    assert_nil @throttle.record("2001:db8:1:2::1")
    assert_nil @throttle.record("2001:db8:1:2::2")
    assert_equal :locked, @throttle.record("2001:db8:1:2:ffff::3")

    assert @throttle.locked?("2001:db8:1:2::4"), "an address never seen before but inside the /64 is locked"
    refute @throttle.locked?("2001:db8:1:3::1")
    assert_equal [ "2001:db8:1:2::/64" ], @throttle.locked_ips.keys
  end

  test "ipv4 lockouts key on the address, v4-mapped spelling included" do
    2.times { @throttle.record(IP) }
    assert_equal :locked, @throttle.record("::ffff:#{IP}")
    assert @throttle.locked?(IP)
    assert_equal [ IP ], @throttle.locked_ips.keys
  end

  test "sweeps run at most once per second while the table is large" do
    threshold = Throttle::SWEEP_THRESHOLD
    (threshold + 1).times { |i| @throttle.record("10.#{i / 65_536}.#{(i / 256) % 256}.#{i % 256}") }
    @now += 61
    @throttle.record("192.0.2.99") # sweeps
    swept_at = @throttle.instance_variable_get(:@last_sweep)
    assert_in_delta @now, swept_at

    (threshold + 1).times { |i| @throttle.record("10.#{i / 65_536}.#{(i / 256) % 256}.#{i % 256}") }
    @now += 0.5
    @throttle.record("192.0.2.98")
    assert_in_delta swept_at, @throttle.instance_variable_get(:@last_sweep), 0.001, "no second sweep inside a second"
  end

  test "the table never grows past MAX_ENTRIES" do
    (Throttle::MAX_ENTRIES + 50).times { |i| @throttle.record("2001:db8:#{i >> 16}:#{i & 0xffff}::1") }

    entries = @throttle.instance_variable_get(:@entries)
    assert_equal Throttle::MAX_ENTRIES, entries.size
    refute entries.key?("2001:db8:0:0::/64"), "the least recently failing key is evicted first"
  end

  test "expired entries are swept once the table grows large" do
    threshold = Throttle::SWEEP_THRESHOLD
    (threshold + 1).times { |i| @throttle.record("10.#{i / 65_536}.#{(i / 256) % 256}.#{i % 256}") }
    @now += 61
    @throttle.record("192.0.2.99") # first record past the threshold sweeps

    assert_operator @throttle.instance_variable_get(:@entries).size, :<=, 2,
                    "expired entries must be purged, not retained forever"
  end
end
