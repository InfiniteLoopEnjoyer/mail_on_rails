# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/netserv/denylist"

# The store-backed ban list reader: matching, fail-soft parsing, and the
# TTL-throttled reload contract (see Denylist).
class DenylistTest < Minitest::Test
  # A minimal store: whatever sits in #cidrs is the ban list; an exception
  # or a non-array stands in for a database problem (Store::Base#db
  # returns an error hash then).
  class FakeStore
    attr_accessor :cidrs
    attr_reader :reads

    def initialize(cidrs = [])
      @cidrs = cidrs
      @reads = 0
    end

    def banned_cidrs
      @reads += 1
      raise @cidrs if @cidrs.is_a?(Class) && @cidrs <= StandardError

      @cidrs
    end
  end

  # ttl 0 re-reads the store on every pull, so tests never wait out the
  # throttle. Loaded once up front, the way Server#run does before its
  # first accept.
  def denylist(cidrs = [], ttl: 0)
    @store = FakeStore.new(cidrs)
    MailOnRails::Netserv::Denylist.new(@store, ttl: ttl).tap(&:refresh!)
  end

  test "disabled against a store without a ban list" do
    assert_not MailOnRails::Netserv::Denylist.new(Object.new).banned?("203.0.113.7")
  end

  test "an empty ban list means no bans" do
    assert_not denylist.banned?("203.0.113.7")
  end

  test "matches exact addresses and CIDR ranges" do
    list = denylist(%w[203.0.113.7 198.51.100.0/24])

    assert list.banned?("203.0.113.7")
    assert list.banned?("198.51.100.200")
    assert_not list.banned?("203.0.113.8")
    assert_not list.banned?("192.0.2.1")
  end

  test "matches IPv6 ranges, and IPv4 entries never match IPv6 peers" do
    list = denylist(%w[2001:db8::/32 0.0.0.0/8])

    assert list.banned?("2001:db8::1")
    assert_not list.banned?("::1")
  end

  # A dual-stack "::" listener reports IPv4 peers as v4-mapped IPv6; an
  # IPv4 ban must still catch them (the server canonicalizes at accept,
  # the gate repeats it so it never depends on that).
  test "IPv4 entries match v4-mapped peers off a dual-stack socket" do
    list = denylist(%w[203.0.113.0/24 198.51.100.7])

    assert list.banned?("::ffff:203.0.113.9")
    assert list.banned?("::ffff:198.51.100.7")
    assert_not list.banned?("::ffff:198.51.100.8")
  end

  test "garbage entries are skipped" do
    list = denylist([ "not-an-ip", "203.0.113.7" ])

    assert list.banned?("203.0.113.7")
    assert_not list.banned?("192.0.2.1")
  end

  test "an unreadable peer address never matches" do
    list = denylist(%w[0.0.0.0/8])

    assert_not list.banned?(nil)
    assert_not list.banned?("?")
  end

  test "pull picks up store changes" do
    list = denylist(%w[203.0.113.7])
    assert list.banned?("203.0.113.7")

    @store.cidrs = %w[192.0.2.1]
    assert list.pull
    assert_not list.banned?("203.0.113.7")
    assert list.banned?("192.0.2.1")
  end

  # The accept-path contract: banned? is a snapshot read. However stale
  # the snapshot, the store is never asked on that call and no lock is
  # taken - a slow database delays a ban, never a banner.
  test "banned? never reads the store, even once the ttl has lapsed" do
    list = denylist(%w[203.0.113.7]) # ttl 0: every pull is due
    reads = @store.reads
    @store.cidrs = %w[192.0.2.1]

    assert list.banned?("203.0.113.7"), "the snapshot keeps serving"
    assert_not list.banned?("192.0.2.1")
    assert_equal reads, @store.reads, "no store call on the accept path"

    mutex = list.instance_variable_get(:@mutex)
    mutex.synchronize { assert list.banned?("203.0.113.7"), "no lock either: this would deadlock" }
  end

  test "a fresh list serves no bans until its first load" do
    store = FakeStore.new(%w[203.0.113.7])
    list = MailOnRails::Netserv::Denylist.new(store, ttl: 0)

    assert_not list.banned?("203.0.113.7")
    assert_equal 0, store.reads
    list.refresh!
    assert list.banned?("203.0.113.7")
  end

  test "the store read is throttled to the ttl" do
    list = denylist(%w[203.0.113.7], ttl: 600)
    assert list.banned?("203.0.113.7")

    @store.cidrs = %w[192.0.2.1]
    # Within the ttl a pull is a no-op; the old list keeps serving.
    assert_not list.pull
    assert_equal 1, @store.reads
    assert list.banned?("203.0.113.7")
    assert_not list.banned?("192.0.2.1")
  end

  test "refresh! reloads immediately, bypassing the ttl" do
    list = denylist(%w[203.0.113.7], ttl: 600)
    assert list.banned?("203.0.113.7")

    @store.cidrs = %w[192.0.2.1]
    list.refresh!
    assert_not list.banned?("203.0.113.7")
    assert list.banned?("192.0.2.1")
  end

  test "a store error keeps the last good list" do
    list = denylist(%w[203.0.113.7])
    assert list.banned?("203.0.113.7")

    @store.cidrs = RuntimeError
    list.pull
    assert list.banned?("203.0.113.7")

    # Store::Base#db reports errors as a hash rather than raising.
    @store.cidrs = { error: "boom", code: :internal }
    list.pull
    assert list.banned?("203.0.113.7")

    @store.cidrs = []
    list.pull
    assert_not list.banned?("203.0.113.7")
  end

  # -- scaling (an automatic ban setting lets strangers add rows) ----------

  # A store that also offers the list's fingerprint, and counts both reads.
  class StampedStore < FakeStore
    attr_accessor :stamp
    attr_reader :stamp_reads

    def initialize(cidrs = [])
      super
      @stamp = [ cidrs.size, 1, "t0" ]
      @stamp_reads = 0
    end

    def banned_cidrs_stamp
      @stamp_reads += 1
      raise @stamp if @stamp.is_a?(Class)

      @stamp
    end
  end

  test "every prefix length matches, host bits and all" do
    list = denylist(%w[203.0.113.7 198.51.100.0/24 10.0.0.0/8 192.0.2.128/25 192.0.2.64/27
                       2001:db8:1:2::/64 2001:db8:5::/48 2a01:4f8::/32 2001:db8:9:9::1 2001:db8:7::/49 2400::/12])

    %w[203.0.113.7 198.51.100.255 10.255.0.1 192.0.2.129 192.0.2.95
       2001:db8:1:2:ffff:ffff:ffff:ffff 2001:db8:5:ffff::1 2a01:4f8:ffff::1 2001:db8:9:9::1
       2001:db8:7:7fff::1 240f:ffff::1].each { |ip| assert list.banned?(ip), ip }
    %w[203.0.113.8 198.51.101.0 11.0.0.1 192.0.2.127 192.0.2.96
       2001:db8:1:3::1 2001:db8:6::1 2a01:4f9::1 2001:db8:9:9::2 2001:db8:7:8000::1 2410::1].each do |ip|
      assert_not list.banned?(ip), ip
    end
  end

  # The accept thread's cost must not grow with the list: one probe per
  # prefix length that occurs, not one comparison per row.
  test "a lookup is keyed by prefix, not a scan of the list" do
    cidrs = Array.new(20_000) { |i| "2001:db8:#{(i / 65_536).to_s(16)}:#{(i % 65_536).to_s(16)}::/64" } +
            Array.new(20_000) { |i| "198.#{18 + i / 65_536}.#{(i / 256) % 256}.#{i % 256}" }
    list = denylist(cidrs)
    index = list.instance_variable_get(:@index)

    assert_equal [ 64 ], index.v6.keys, "one table for the /64s"
    assert_equal [ 0 ], index.v4.keys, "one table for the host entries"
    assert list.banned?("2001:db8:0:4e1f::1"), "the last /64"
    assert_not list.banned?("2001:db8:0:4e20::1")
    assert list.banned?("198.18.78.31"), "the last host"
    assert_not list.banned?("198.18.78.32")

    probes = 0
    counted = index.v6.transform_values do |networks|
      networks.dup.tap { |copy| copy.define_singleton_method(:include?) { |key| probes += 1; super(key) } }
    end
    list.instance_variable_set(:@index, index.class.new(index.v4, counted))
    list.banned?("2001:db9::1")
    assert_equal 1, probes, "a miss costs one hash probe per prefix length, whatever the row count"
  end

  test "an unchanged fingerprint skips the list read altogether" do
    @store = StampedStore.new(%w[203.0.113.7])
    list = MailOnRails::Netserv::Denylist.new(@store, ttl: 0).tap(&:refresh!)
    assert_equal 1, @store.reads

    3.times { list.pull }
    assert_equal 1, @store.reads, "the list is not re-read while the fingerprint holds"
    assert_operator @store.stamp_reads, :>=, 3
    assert list.banned?("203.0.113.7")

    @store.cidrs = %w[203.0.113.7 192.0.2.1]
    @store.stamp = [ 2, 2, "t1" ]
    list.pull
    assert_equal 2, @store.reads
    assert list.banned?("192.0.2.1")
  end

  test "refresh! reads the list even when the fingerprint has not moved" do
    @store = StampedStore.new(%w[203.0.113.7])
    list = MailOnRails::Netserv::Denylist.new(@store, ttl: 0).tap(&:refresh!)

    @store.cidrs = %w[192.0.2.1] # same count, and the stamp left stale on purpose
    list.refresh!
    assert list.banned?("192.0.2.1")
    assert_not list.banned?("203.0.113.7")
  end

  test "a fingerprint the store cannot give falls back to reading the list" do
    @store = StampedStore.new(%w[203.0.113.7])
    list = MailOnRails::Netserv::Denylist.new(@store, ttl: 0).tap(&:refresh!)

    [ RuntimeError, { error: "boom", code: :internal }, nil ].each do |broken|
      @store.stamp = broken
      reads = @store.reads
      list.pull
      assert_equal reads + 1, @store.reads, broken.inspect
    end
    assert list.banned?("203.0.113.7")
  end

  test "a failed list read does not adopt the new fingerprint" do
    @store = StampedStore.new(%w[203.0.113.7])
    list = MailOnRails::Netserv::Denylist.new(@store, ttl: 0).tap(&:refresh!)

    @store.stamp = [ 2, 2, "t1" ]
    @store.cidrs = RuntimeError
    list.pull
    assert list.banned?("203.0.113.7"), "the last good list keeps serving"

    @store.cidrs = %w[203.0.113.7 192.0.2.1]
    list.pull
    assert list.banned?("192.0.2.1"), "and the change is still picked up once the store answers"
  end

  # A reload after one new ban must not re-parse the other 65,535.
  test "a changed list only parses the entries it has not seen" do
    list = denylist(%w[203.0.113.7 198.51.100.0/24])
    parsed = []
    list.define_singleton_method(:parse) { |entry| parsed << entry; super(entry) }

    @store.cidrs = %w[203.0.113.7 198.51.100.0/24 192.0.2.1]
    list.pull
    assert_equal %w[192.0.2.1], parsed
    assert list.banned?("192.0.2.1")
    assert list.banned?("198.51.100.9")

    @store.cidrs = %w[192.0.2.1]
    list.pull
    assert_equal %w[192.0.2.1], parsed, "dropping entries parses nothing"
    assert_not list.banned?("203.0.113.7")
    assert_not list.banned?("198.51.100.9")
  end

  test "an identical list is not rebuilt" do
    list = denylist(%w[203.0.113.7])
    index = list.instance_variable_get(:@index)

    @store.cidrs = %w[203.0.113.7]
    list.pull
    assert_same index, list.instance_variable_get(:@index)
  end
end
