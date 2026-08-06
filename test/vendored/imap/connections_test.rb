# frozen_string_literal: true

require "test_helper"
require "socket"
require "mail_on_rails/imap_server"
require "mail_on_rails/imap/store/memory"

# The live-connections registry behind the Rails UI's IMAP page:
# Server#connections snapshots each connection as plain values (no socket
# or thread escapes), Session#live_info tracks login/SELECT/IDLE, and
# Server#kick force-closes a banned address's live sessions.
class ImapConnectionsTest < Minitest::Test
  EMAIL = "user@example.test"
  PASSWORD = "pw-123456"

  def setup
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def build_server
    store = MailOnRails::Imap::Store::Memory.new
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = TCPServer.new("127.0.0.1", 0)
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :none, tcp_server: listener }
    server = MailOnRails::ImapServer.new(store, [ spec ], nil)
    thread = Thread.new { server.run }
    @cleanup << -> { thread.kill }
    server.wait_ready(5)
    [ server, spec ]
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  def eventually(timeout = 5, message = "condition not met")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      flunk "#{message} within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
  end

  def test_connections_snapshots_registry_and_preauth_state
    server, spec = build_server

    assert_empty server.connections

    client = connect(spec)

    assert_match(/\A\* OK /, client.gets("\r\n"))
    eventually(5, "connection not registered") { server.connections.size == 1 }

    conn = server.connections.first

    assert_equal "IMAP", conn[:protocol]
    assert_equal "127.0.0.1", conn[:peer_ip]
    assert_equal spec[:port], conn[:port]
    assert_nil conn[:role]
    assert_kind_of Time, conn[:connected_at]
    assert_equal "pre-auth", conn[:state]
    assert_nil conn[:user]

    client.write("a1 LOGOUT\r\n")
    eventually(5, "connection not deregistered") { server.connections.empty? }
  end

  def test_kick_closes_only_matching_connections
    server, spec = build_server
    client = connect(spec)

    assert_match(/\A\* OK /, client.gets("\r\n"))
    eventually(5, "connection not registered") { server.connections.size == 1 }

    assert_equal 0, server.kick { |ip| ip == "198.51.100.1" }
    assert_equal 1, server.kick { |ip| ip == "127.0.0.1" }

    assert_nil client.gets("\r\n"), "kicked client must see EOF"
    eventually(5, "kicked connection not deregistered") { server.connections.empty? }
  end

  # Session-level live_info, driven over a real wire but with the session
  # built directly (tls: :implicit so LOGIN is permitted without a
  # handshake, the wire-test convention).
  def test_live_info_tracks_login_select_and_idle
    store = MailOnRails::Imap::Store::Memory.new
    store.add_account(email: EMAIL, password: PASSWORD)
    listener = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    @cleanup << -> { listener.close rescue nil }
    session = MailOnRails::ImapServer::Session.new(listener.accept, store, { tls: :implicit }, nil)
    thread = Thread.new { session.run }
    @cleanup << -> { thread.kill }

    assert_match(/\A\* OK /, client.gets("\r\n"))
    assert_equal({ user: nil, state: "pre-auth", tls: true }, session.live_info)

    client.write("a1 LOGIN #{EMAIL} #{PASSWORD}\r\n")
    client.gets("\r\n")

    assert_equal EMAIL, session.live_info[:user]
    assert_equal "authenticated", session.live_info[:state]

    client.write("a2 SELECT INBOX\r\n")
    until (line = client.gets("\r\n")).nil? || line.start_with?("a2 "); end

    assert_equal "SELECT INBOX", session.live_info[:state]

    client.write("a3 IDLE\r\n")

    assert_match(/\A\+ /, client.gets("\r\n"))
    assert_equal "IDLE INBOX", session.live_info[:state]

    client.write("DONE\r\n")

    assert_match(/\Aa3 OK/, client.gets("\r\n"))
    assert_equal "SELECT INBOX", session.live_info[:state]
  end
end
