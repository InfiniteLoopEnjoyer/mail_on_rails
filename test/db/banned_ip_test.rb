# frozen_string_literal: true

require_relative "test_helper"
require "mail_on_rails/netserv/denylist"

# BannedIp's canonical CIDR form, and that every spelling of a ban matches
# the peers it names on every surface (covering, banned_cidrs).
class BannedIpTest < DbSuite::TestCase
  def store = @store ||= MailOnRails::Store::Base.new

  test "host entries store bare, ranges store the masked network with its prefix" do
    assert_equal "1.2.3.4", MailOnRails::BannedIp.canonicalize("1.2.3.4/32")
    assert_equal "1.2.3.0/24", MailOnRails::BannedIp.canonicalize(" 1.2.3.4/24 ")
    assert_equal "2001:db8::1", MailOnRails::BannedIp.canonicalize("2001:DB8:0:0:0:0:0:1/128")
    assert_equal "2001:db8::/32", MailOnRails::BannedIp.canonicalize("2001:db8:1::/32")
    assert_raises(IPAddr::Error) { MailOnRails::BannedIp.canonicalize("not an address") }
  end

  # I1: a v4-mapped spelling used to be stored as IPv6 and could never
  # match - peers are unmapped on every surface, and cross-family CIDRs
  # never match by design. It is stored as the IPv4 it names.
  test "a v4-mapped address or range is stored as native IPv4 and matches IPv4 peers" do
    assert_equal "1.2.3.4", MailOnRails::BannedIp.canonicalize("::ffff:1.2.3.4")
    assert_equal "1.2.3.4", MailOnRails::BannedIp.canonicalize("::ffff:1.2.3.4/128")
    assert_equal "1.2.3.0/24", MailOnRails::BannedIp.canonicalize("::ffff:1.2.3.0/120")
    assert_equal "1.2.3.0/24", MailOnRails::BannedIp.canonicalize("::FFFF:102:304/120"), "hex spelling too"

    host = MailOnRails::BannedIp.create!(cidr: "::ffff:203.0.113.7", source: "manual")
    range = MailOnRails::BannedIp.create!(cidr: "::ffff:198.51.100.0/120", source: "manual")
    assert_equal %w[198.51.100.0/24 203.0.113.7], [ range.cidr, host.cidr ]

    assert_equal host, MailOnRails::BannedIp.covering("203.0.113.7")
    assert_equal host, MailOnRails::BannedIp.covering("::ffff:203.0.113.7")
    assert_equal range, MailOnRails::BannedIp.covering("198.51.100.200")
    assert_nil MailOnRails::BannedIp.covering("198.51.101.1")
    assert_equal %w[198.51.100.0/24 203.0.113.7], store.banned_cidrs.sort

    denylist = MailOnRails::Netserv::Denylist.new(store).tap(&:refresh!)
    assert denylist.banned?("203.0.113.7")
    assert denylist.banned?("::ffff:198.51.100.9")
  end

  test "a mapped range is held to the IPv4 breadth floor" do
    row = MailOnRails::BannedIp.new(cidr: "::ffff:0.0.0.0/100", source: "manual")
    assert_not row.valid?
    assert_match(/too broad/, row.errors[:cidr].first)
  end

  test "the mapped and native spellings are one row" do
    MailOnRails::BannedIp.create!(cidr: "203.0.113.7", source: "manual")
    dup = MailOnRails::BannedIp.new(cidr: "::ffff:203.0.113.7", source: "manual")
    assert_not dup.valid?
  end
end
