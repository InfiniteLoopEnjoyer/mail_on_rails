# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/netserv/ip"

# The one canonical spelling of a peer address (Netserv.canonical_ip): a
# dual-stack "::" listener reports IPv4 peers as v4-mapped IPv6, which
# must read as plain IPv4 everywhere downstream.
class CanonicalIpTest < Minitest::Test
  test "unmaps v4-mapped IPv6 to plain IPv4" do
    assert_equal "203.0.113.5", MailOnRails::Netserv.canonical_ip("::ffff:203.0.113.5")
    assert_equal "203.0.113.5", MailOnRails::Netserv.canonical_ip("::FFFF:203.0.113.5")
    assert_equal "127.0.0.1", MailOnRails::Netserv.canonical_ip("::ffff:127.0.0.1")
  end

  test "leaves plain IPv4 alone" do
    assert_equal "203.0.113.5", MailOnRails::Netserv.canonical_ip("203.0.113.5")
  end

  test "compresses and lowercases IPv6" do
    assert_equal "2001:db8::25", MailOnRails::Netserv.canonical_ip("2001:DB8:0:0:0:0:0:25")
    assert_equal "::1", MailOnRails::Netserv.canonical_ip("::1")
  end

  test "passes unparseable input and nil through untouched" do
    assert_equal "?", MailOnRails::Netserv.canonical_ip("?")
    assert_equal "", MailOnRails::Netserv.canonical_ip("")
    assert_nil MailOnRails::Netserv.canonical_ip(nil)
  end
end

# The key the per-IP controls count against (Netserv.throttle_key): the
# address for IPv4, the /64 for IPv6 - a customer holds a whole /64 and
# can source every connection from a fresh /128 inside it.
class ThrottleKeyTest < Minitest::Test
  def key(ip) = MailOnRails::Netserv.throttle_key(ip)

  test "ipv4 keys on the canonical address, v4-mapped included" do
    assert_equal "203.0.113.5", key("203.0.113.5")
    assert_equal "203.0.113.5", key("::ffff:203.0.113.5")
  end

  test "ipv6 keys on the /64, spelled as a network" do
    assert_equal "2001:db8:1:2::/64", key("2001:db8:1:2::25")
    assert_equal "2001:db8:1:2::/64", key("2001:DB8:1:2:ffff:ffff:ffff:ffff")
    assert_equal "2001:db8:1:2::/64", key("2001:db8:1:2:0:0:0:1")
    refute_equal key("2001:db8:1:2::1"), key("2001:db8:1:3::1"), "different /64s are different keys"
  end

  test "the ipv6 key is idempotent" do
    assert_equal "2001:db8:1:2::/64", key(key("2001:db8:1:2::25"))
  end

  test "passes unparseable input and nil through untouched" do
    assert_equal "?", key("?")
    assert_nil key(nil)
  end
end

# The outbound SSRF fence (Netserv.routable? / NON_ROUTABLE): the set the
# MTA-STS fetcher already used, now shared with MX delivery.
class RoutableTest < Minitest::Test
  def routable?(ip) = MailOnRails::Netserv.routable?(ip)

  test "public addresses are routable" do
    assert routable?("93.184.216.34")
    assert routable?("2606:2800:220:1:248:1893:25c8:1946")
  end

  test "private, loopback, link-local, cgnat, ula and mapped space are not" do
    %w[10.1.2.3 172.16.0.9 192.168.1.1 127.0.0.1 169.254.169.254 100.64.0.1 0.0.0.0
       ::1 fe80::1 fd00:1234:5678::5 fc00::1 ::ffff:10.0.0.1 64:ff9b::a00:1 ff02::1].each do |ip|
      refute routable?(ip), "#{ip} must be refused"
    end
  end

  test "non-addresses are not routable" do
    refute routable?("mail.example.test")
    refute routable?(nil)
  end
end
