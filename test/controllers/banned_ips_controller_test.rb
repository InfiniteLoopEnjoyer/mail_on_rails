require "test_helper"
require "mail_on_rails/boot"

class BannedIpsControllerTest < ActionDispatch::IntegrationTest
  setup { sign_in_as users(:one) }

  # Swaps Boot.kick_connections for the block's duration (the repo's
  # hand-rolled stubbing convention). Records the matcher it was handed
  # so tests can probe which addresses the ban would have kicked.
  def with_kick(result)
    matchers = []
    singleton = MailOnRails::Boot.singleton_class
    original = MailOnRails::Boot.method(:kick_connections)
    singleton.define_method(:kick_connections) { |&matcher| matchers << matcher; result }
    yield matchers
  ensure
    singleton.define_method(:kick_connections, original)
  end

  test "requires a signed-in user" do
    reset!
    post banned_ips_path, params: { banned_ip: { cidr: "203.0.113.0/24" } }
    assert_redirected_to new_session_path
    assert_equal 0, BannedIp.count
  end

  test "bans a range and returns to the index, keeping the window" do
    post banned_ips_path, params: { banned_ip: { cidr: "203.0.113.0/24", note: "spray" }, window: "24h" }

    assert_redirected_to auth_attempts_path(window: "24h")
    ban = BannedIp.sole
    assert_equal "203.0.113.0/24", ban.cidr
    assert_equal "spray", ban.note
    assert_equal "manual", ban.source
  end

  test "returns to the range drill-down it was clicked on" do
    post banned_ips_path, params: { banned_ip: { cidr: "203.0.113.9" }, range: "203.0.113.0/24", window: "7d" }

    assert_redirected_to range_auth_attempts_path(cidr: "203.0.113.0/24", window: "7d")
    assert_equal "203.0.113.9", BannedIp.sole.cidr
  end

  test "rejects garbage with the validation message" do
    post banned_ips_path, params: { banned_ip: { cidr: "not-an-ip" } }

    assert_redirected_to auth_attempts_path(window: nil)
    assert_equal 0, BannedIp.count
    assert_match(/Ban not added/, flash[:alert])
  end

  # With the web login also enforcing bans, banning yourself is a lockout.
  # Tests run from 127.0.0.1, so a loopback-covering range must be refused.
  test "refuses a ban covering the admin's own address" do
    post banned_ips_path, params: { banned_ip: { cidr: "127.0.0.0/24" } }

    assert_equal 0, BannedIp.count
    assert_match(/covers your own address/, flash[:alert])
  end

  test "returns to the live connections page it was clicked on" do
    post banned_ips_path, params: { banned_ip: { cidr: "203.0.113.9" }, origin: "imap" }

    assert_redirected_to imap_path
    assert_equal "203.0.113.9", BannedIp.sole.cidr
  end

  test "drops the banned address's live connections and says so" do
    with_kick(2) do |matchers|
      post banned_ips_path, params: { banned_ip: { cidr: "203.0.113.0/24" }, origin: "smtp" }

      assert_redirected_to smtp_path
      assert_match(/Dropped 2 live connections/, flash[:notice])
      # the matcher handed to the servers must cover exactly the ban
      matcher = matchers.sole
      assert matcher.call("203.0.113.9")
      refute matcher.call("198.51.100.1")
      refute matcher.call("not-an-ip")
    end
  end

  test "unbans" do
    ban = BannedIp.create!(cidr: "203.0.113.0/24")

    delete banned_ip_path(ban, window: "30d")

    assert_redirected_to auth_attempts_path(window: "30d")
    assert_equal 0, BannedIp.count
    assert_match(/Unbanned 203.0.113.0\/24/, flash[:notice])
  end
end
