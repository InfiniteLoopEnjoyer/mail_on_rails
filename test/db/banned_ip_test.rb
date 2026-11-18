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

  # -- covering as an indexed lookup (M4) -----------------------------------

  test "covering finds a ban of any prefix length, and the broadest when several cover" do
    host = MailOnRails::BannedIp.create!(cidr: "203.0.113.7", source: "manual")
    odd = MailOnRails::BannedIp.create!(cidr: "198.51.100.64/27", source: "manual")
    v6_64 = MailOnRails::BannedIp.create!(cidr: "2001:db8:1:2::/64", source: "auth_failure")
    v6_48 = MailOnRails::BannedIp.create!(cidr: "2001:db8:1::/48", source: "manual")
    v6_odd = MailOnRails::BannedIp.create!(cidr: "2a01:4f8:c0c::/47", source: "manual")
    v6_host = MailOnRails::BannedIp.create!(cidr: "2001:DB8:9:0:0:0:0:1", source: "manual")
    drop = MailOnRails::BannedIp.new(cidr: "2400::/12", source: "spamhaus_drop").tap(&:save!)

    assert_equal host, MailOnRails::BannedIp.covering("203.0.113.7")
    assert_equal odd, MailOnRails::BannedIp.covering("198.51.100.95")
    assert_nil MailOnRails::BannedIp.covering("198.51.100.96")
    assert_equal v6_48, MailOnRails::BannedIp.covering("2001:db8:1:2::5"), "the /48, not the /64 inside it"
    assert_equal v6_48, MailOnRails::BannedIp.covering("2001:db8:1:ffff::5")
    assert_equal v6_odd, MailOnRails::BannedIp.covering("2a01:4f8:c0d:1::1")
    assert_equal v6_host, MailOnRails::BannedIp.covering("2001:db8:9::1")
    assert_equal drop, MailOnRails::BannedIp.covering("240f::1")
    assert_nil MailOnRails::BannedIp.covering("2001:db8:2::1")
    assert_nil MailOnRails::BannedIp.covering("not an address")
    assert_nil MailOnRails::BannedIp.covering(nil)
    assert_equal v6_64.cidr, MailOnRails::BannedIp.where(id: v6_64.id).sole.cidr
  end

  test "covering answers for a range too: only a ban that contains all of it" do
    wide = MailOnRails::BannedIp.create!(cidr: "198.51.100.0/24", source: "manual")
    MailOnRails::BannedIp.create!(cidr: "203.0.113.7", source: "manual")

    assert_equal wide, MailOnRails::BannedIp.covering("198.51.100.128/25")
    assert_nil MailOnRails::BannedIp.covering("203.0.113.0/24"), "a host ban inside a range does not cover the range"
  end

  # Strangers add rows under an automatic ban setting, and this runs on
  # every failed login and every web sign-in.
  test "covering never loads the table" do
    now = Time.current
    MailOnRails::BannedIp.insert_all(Array.new(500) do |i|
      { cidr: "2001:db8:#{(i + 16).to_s(16)}:1::/64", source: "auth_failure", created_at: now, updated_at: now }
    end)
    hit = MailOnRails::BannedIp.create!(cidr: "192.0.2.0/24", source: "manual")

    loaded = 0
    queries = []
    counter = ActiveSupport::Notifications.subscribe("instantiation.active_record") { |*, payload| loaded += payload[:record_count] }
    sql = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| queries << payload[:sql] }
    begin
      assert_equal hit, MailOnRails::BannedIp.covering("192.0.2.77")
      assert_nil MailOnRails::BannedIp.covering("2001:db8:ffff::1")
      assert MailOnRails::BannedIp.covering("2001:db8:20:1::9")
    ensure
      ActiveSupport::Notifications.unsubscribe(counter)
      ActiveSupport::Notifications.unsubscribe(sql)
    end

    assert_equal 2, loaded, "only the rows that cover were read"
    assert_equal 3, queries.grep(/banned_ips/).size, "one query per lookup"
  end

  test "the denylist fingerprint moves with every kind of change to the list" do
    stamps = [ store.banned_cidrs_stamp ]
    a = MailOnRails::BannedIp.create!(cidr: "203.0.113.7", source: "manual")
    stamps << store.banned_cidrs_stamp
    b = MailOnRails::BannedIp.create!(cidr: "203.0.113.8", source: "manual")
    stamps << store.banned_cidrs_stamp
    a.destroy!
    stamps << store.banned_cidrs_stamp
    b.update_columns(updated_at: 1.hour.from_now)
    stamps << store.banned_cidrs_stamp

    stamps.each { |stamp| assert_kind_of Array, stamp }
    assert_equal stamps.size, stamps.uniq.size, stamps.inspect
    assert_equal stamps.last, store.banned_cidrs_stamp, "and holds still when nothing changes"
  end

  # -- automatic rows are bounded (M4) --------------------------------------

  def stubbed(receiver, name, body)
    original = receiver.method(name)
    receiver.define_singleton_method(name, &body)
    yield
  ensure
    receiver.define_singleton_method(name, original)
  end

  def probe_ban(ip)
    MailOnRails::BannedIp.auto_ban_for_probe(ip: ip, protocol: "smtp", trigger: "garbage", signature: "control_bytes")
  end

  def cidrs(scope = MailOnRails::BannedIp) = scope.order(:id).pluck(:cidr)

  test "many automatic /64 bans inside one /48 fold into a single /48 ban" do
    manual = MailOnRails::BannedIp.create!(cidr: "2001:db8:1:aa::/64", source: "manual", note: "by hand")
    manual_host = MailOnRails::BannedIp.create!(cidr: "2001:db8:1:bb::1", source: "manual")
    stubbed(MailOnRails::BannedIp, :collapse_threshold, -> { 4 }) do
      probe_ban("2001:db8:2:1::1") # a neighbouring /48: not counted, not touched
      3.times { |i| assert_equal "2001:db8:1:#{i + 1}::/64", probe_ban("2001:db8:1:#{i + 1}::7").cidr }
      assert_equal 6, MailOnRails::BannedIp.count, "below the threshold every /64 keeps its own row"

      folded = probe_ban("2001:db8:1:4::7")

      assert_equal "2001:db8:1::/48", folded.cidr, "the caller is told what is banned now"
      assert_equal "protocol_abuse", folded.source
      assert_match(/\Aauto: 4 banned \/64s in this \/48 folded into one ban \(last - control bytes on smtp\)/, folded.note)
      assert_equal %w[2001:db8:1:aa::/64 2001:db8:1:bb::1 2001:db8:2:1::/64 2001:db8:1::/48], cidrs
      assert_equal [ "by hand", "manual" ], [ manual.reload.note, manual.source ], "a manual ban is left exactly as written"
      assert manual_host.reload

      assert_nil probe_ban("2001:db8:1:ffff::1"), "the rest of the /48 is covered: no further rows"
      assert_equal 4, MailOnRails::BannedIp.count
      assert_equal folded, MailOnRails::BannedIp.covering("2001:db8:1:4::7")
    end
  end

  # The /64s of a /48 share no fixed string prefix once zero groups are
  # compressed; membership has to be decided on the addresses.
  test "folding counts by address, whatever the compressed spelling" do
    stubbed(MailOnRails::BannedIp, :collapse_threshold, -> { 3 }) do
      probe_ban("2001:db8:1:5::1")   # shares the "2001:db8:" spelling, different /48
      probe_ban("2001:db8:0:0:1::")  # stored as 2001:db8::/64
      probe_ban("2001:db8:0:5::1")
      assert_equal 3, MailOnRails::BannedIp.count, "two in 2001:db8:0::/48, one next door"

      folded = probe_ban("2001:db8:0:ffff::1")

      assert_equal "2001:db8::/48", folded.cidr
      assert_equal %w[2001:db8:1:5::/64 2001:db8::/48], cidrs
    end
  end

  test "nothing is folded over an allowlisted network, and ipv4 bans are never widened" do
    ENV["MAIL_ON_RAILS_HONEYPOT_ALLOWLIST"] = "2001:db8:1:99::/64"
    stubbed(MailOnRails::BannedIp, :collapse_threshold, -> { 2 }) do
      3.times { |i| probe_ban("2001:db8:1:#{i + 1}::7") }
      3.times { |i| probe_ban("203.0.113.#{i + 1}") }

      assert_equal 6, MailOnRails::BannedIp.count
      assert_empty cidrs.grep(%r{/48|/24})
    end
  ensure
    ENV.delete("MAIL_ON_RAILS_HONEYPOT_ALLOWLIST")
  end

  test "past the ceiling the oldest automatic rows make room; manual and DROP rows never do" do
    manual = MailOnRails::BannedIp.create!(cidr: "192.0.2.1", source: "manual", created_at: 3.years.ago)
    drop = MailOnRails::BannedIp.create!(cidr: "192.0.2.128/25", source: "spamhaus_drop", created_at: 3.years.ago)
    stubbed(MailOnRails::BannedIp, :automatic_rows_max, -> { 3 }) do
      3.times do |i|
        probe_ban("203.0.113.#{i + 1}")
        MailOnRails::BannedIp.where(cidr: "203.0.113.#{i + 1}").update_all(created_at: (10 - i).days.ago)
      end
      assert_equal 5, MailOnRails::BannedIp.count

      newest = probe_ban("203.0.113.50")

      assert_equal "203.0.113.50", newest.cidr
      assert_equal %w[203.0.113.2 203.0.113.3 203.0.113.50], cidrs(MailOnRails::BannedIp.automatic)
      assert manual.reload
      assert drop.reload
    end
  end
end
