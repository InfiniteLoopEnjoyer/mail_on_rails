# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/netserv/rate_limiter"

class RateLimiterTest < Minitest::Test
  Limiter = MailOnRails::Netserv::RateLimiter

  def limiter(limit: 3, window: 60, **kwargs)
    @now = 0.0
    Limiter.new(limit: limit, window: window, clock: -> { @now }, **kwargs)
  end

  test "connections within the budget see no delay" do
    l = limiter
    3.times { assert_in_delta 0.0, l.delay("192.0.2.1") }
  end

  test "delay escalates per connection over the limit and caps" do
    l = limiter
    3.times { l.delay("192.0.2.1") }

    assert_in_delta 1.0, l.delay("192.0.2.1")
    assert_in_delta 2.0, l.delay("192.0.2.1")
    assert_in_delta 4.0, l.delay("192.0.2.1")
    assert_in_delta 8.0, l.delay("192.0.2.1")
    assert_in_delta 16.0, l.delay("192.0.2.1")
    assert_in_delta 16.0, l.delay("192.0.2.1"), 0.001, "delay must cap at MAX_DELAY"
  end

  test "the window slides" do
    l = limiter(limit: 2, window: 60)
    2.times { l.delay("192.0.2.1") }
    assert_in_delta 1.0, l.delay("192.0.2.1")

    @now = 61.0 # everything above has aged out
    assert_in_delta 0.0, l.delay("192.0.2.1")
  end

  test "ips are tracked independently" do
    l = limiter(limit: 1)
    l.delay("192.0.2.1")
    assert_in_delta 1.0, l.delay("192.0.2.1")
    assert_in_delta 0.0, l.delay("192.0.2.2")
  end

  test "nil ip is never delayed" do
    l = limiter(limit: 1)
    5.times { assert_in_delta 0.0, l.delay(nil) }
  end

  test "loopback peers are exempt" do
    l = limiter(limit: 1)
    [ "127.0.0.1", "::1" ].each do |ip|
      5.times { assert_in_delta 0.0, l.delay(ip) }
    end
  end

  test "nil or zero limit disables the limiter" do
    [ nil, 0 ].each do |setting|
      @now = 0.0
      l = Limiter.new(limit: setting, window: 60, clock: -> { @now })
      5.times { assert_in_delta 0.0, l.delay("192.0.2.1") }
    end
  end

  test "per-ip timestamp memory is bounded" do
    l = limiter(limit: 3)
    500.times { l.delay("192.0.2.1") }

    stamps = l.instance_variable_get(:@entries)["192.0.2.1"]
    assert_operator stamps.size, :<=, 3 + Limiter::OVERAGE_MEMORY
    assert_in_delta 16.0, l.delay("192.0.2.1"), 0.001, "a deep flood must stay at max delay"
  end

  test "idle ips are swept from the table" do
    l = limiter(limit: 1, window: 10)
    (Limiter::SWEEP_THRESHOLD + 1).times { |i| l.delay("10.0.#{i / 250}.#{i % 250}") }

    @now = 100.0 # every stamp aged out
    l.delay("192.0.2.1")
    assert_operator l.instance_variable_get(:@entries).size, :<=, 2
  end

  test "ipv6 peers in one /64 share a rate budget; other /64s do not" do
    l = limiter(limit: 2)
    assert_in_delta 0.0, l.delay("2001:db8:1:2::1")
    assert_in_delta 0.0, l.delay("2001:db8:1:2::2")
    assert_in_delta 1.0, l.delay("2001:db8:1:2:aaaa::3"), 0.001, "the third connection from the /64 is over budget"
    assert_in_delta 0.0, l.delay("2001:db8:1:3::1"), 0.001, "a neighbouring /64 starts fresh"
    assert_equal [ "2001:db8:1:2::/64", "2001:db8:1:3::/64" ], l.instance_variable_get(:@entries).keys
  end

  test "ipv4 keys are unchanged" do
    l = limiter(limit: 1)
    l.delay("192.0.2.1")
    l.delay("::ffff:192.0.2.1")
    assert_equal [ "192.0.2.1" ], l.instance_variable_get(:@entries).keys
  end

  test "sweeps run at most once per second even while the table is large" do
    l = limiter(limit: 1, window: 10)
    (Limiter::SWEEP_THRESHOLD + 1).times { |i| l.delay("10.0.#{i / 250}.#{i % 250}") }

    @now = 100.0
    l.delay("192.0.2.1") # first call past the threshold sweeps (everything expired)
    assert_in_delta 100.0, l.instance_variable_get(:@last_sweep)

    (Limiter::SWEEP_THRESHOLD + 1).times { |i| l.delay("10.1.#{i / 250}.#{i % 250}") }
    @now = 100.9
    l.delay("192.0.2.2")
    assert_in_delta 100.0, l.instance_variable_get(:@last_sweep), 0.001, "a sweep within the same second is skipped"

    @now = 111.0 # a second has passed and the 10.1.* stamps have aged out
    l.delay("192.0.2.3")
    assert_in_delta 111.0, l.instance_variable_get(:@last_sweep)
    assert_operator l.instance_variable_get(:@entries).size, :<=, 3
  end

  test "the table never grows past MAX_ENTRIES; the least recently seen key goes first" do
    l = limiter(limit: 1, window: 3600)
    (Limiter::MAX_ENTRIES + 100).times { |i| l.delay("2001:db8:#{i >> 16}:#{i & 0xffff}::1") }

    entries = l.instance_variable_get(:@entries)
    assert_equal Limiter::MAX_ENTRIES, entries.size
    refute entries.key?("2001:db8:0:0::/64"), "the first key seen must have been evicted"
    assert entries.key?(MailOnRails::Netserv.throttle_key("2001:db8:0:#{Limiter::MAX_ENTRIES + 99}::1"))
  end
end
