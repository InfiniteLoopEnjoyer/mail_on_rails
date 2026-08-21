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

    def initialize(cidrs = [])
      @cidrs = cidrs
    end

    def banned_cidrs
      raise @cidrs if @cidrs.is_a?(Class) && @cidrs <= StandardError

      @cidrs
    end
  end

  # ttl 0 re-reads the store on every call, so tests never wait out the
  # throttle.
  def denylist(cidrs = [], ttl: 0)
    @store = FakeStore.new(cidrs)
    MailOnRails::Netserv::Denylist.new(@store, ttl: ttl)
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

  test "picks up store changes" do
    list = denylist(%w[203.0.113.7])
    assert list.banned?("203.0.113.7")

    @store.cidrs = %w[192.0.2.1]
    assert_not list.banned?("203.0.113.7")
    assert list.banned?("192.0.2.1")
  end

  test "the store read is throttled to the ttl" do
    list = denylist(%w[203.0.113.7], ttl: 600)
    assert list.banned?("203.0.113.7")

    @store.cidrs = %w[192.0.2.1]
    # Within the ttl the old list keeps serving; no store read, no reload.
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
    assert list.banned?("203.0.113.7")

    # Store::Base#db reports errors as a hash rather than raising.
    @store.cidrs = { error: "boom", code: :internal }
    assert list.banned?("203.0.113.7")

    @store.cidrs = []
    assert_not list.banned?("203.0.113.7")
  end
end
