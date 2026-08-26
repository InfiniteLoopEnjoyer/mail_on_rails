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
