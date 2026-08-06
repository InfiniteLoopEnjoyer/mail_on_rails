require "test_helper"
require "mail_on_rails/boot"

class LiveConnectionsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as users(:one)
  end

  # What MailOnRails::Boot.server returns when the in-process servers run;
  # the test process never boots them, so the pages get this stand-in.
  class FakeServer
    MAX_CONNECTIONS = 100

    def initialize(connections)
      @connections = connections
    end

    attr_reader :connections
  end

  # Swaps Boot.server for the block's duration (the repo's hand-rolled
  # stubbing convention - minitest/mock is a separate gem under
  # Minitest 6).
  def with_server(server)
    singleton = MailOnRails::Boot.singleton_class
    original = MailOnRails::Boot.method(:server)
    singleton.define_method(:server) { |_protocol| server }
    yield
  ensure
    singleton.define_method(:server, original)
  end

  test "requires a signed-in user" do
    reset!
    get smtp_path
    assert_redirected_to new_session_path
  end

  test "smtp page explains when the server is not running in this process" do
    get smtp_path
    assert_response :success
    assert_select "h1", "SMTP"
    assert_match "not running in this process", response.body
  end

  test "imap page explains when the server is not running in this process" do
    get imap_path
    assert_response :success
    assert_select "h1", "IMAP"
    assert_match "not running in this process", response.body
  end

  test "smtp page lists live connections with ban buttons" do
    server = FakeServer.new([
      { protocol: "SMTP", peer_ip: "203.0.113.9", port: 1587, role: :submission,
        connected_at: 2.minutes.ago, user: "carol@example.com", helo: "laptop.lan",
        messages: 3, tls: true }
    ])
    with_server(server) { get smtp_path }

    assert_response :success
    assert_match "203.0.113.9", response.body
    assert_match "laptop.lan", response.body
    assert_match "carol@example.com", response.body
    assert_select "form[action=?]", banned_ips_path
    # the ban must come back to this page, not the auth attempts index
    assert_select "input[name=origin][value=smtp]"
  end

  test "imap page lists live connections and their protocol state" do
    server = FakeServer.new([
      { protocol: "IMAP", peer_ip: "203.0.113.9", port: 1993, role: nil,
        connected_at: 2.minutes.ago, user: "carol@example.com",
        state: "IDLE INBOX", tls: true }
    ])
    with_server(server) { get imap_path }

    assert_response :success
    assert_match "IDLE INBOX", response.body
    assert_select "input[name=origin][value=imap]"
  end

  test "a connection covered by an existing ban shows the badge instead of a button" do
    BannedIp.create!(cidr: "203.0.113.0/24", note: "test")
    server = FakeServer.new([
      { protocol: "IMAP", peer_ip: "203.0.113.9", port: 1143, role: nil,
        connected_at: 1.minute.ago, user: nil, state: "pre-auth", tls: false }
    ])
    with_server(server) { get imap_path }

    assert_response :success
    assert_match "banned", response.body
    assert_select "input[name=origin]", count: 0
  end
end
