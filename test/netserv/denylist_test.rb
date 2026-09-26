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
end
