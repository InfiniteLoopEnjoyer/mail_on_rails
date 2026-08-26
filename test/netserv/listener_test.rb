# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/netserv/server"

# The listener socket and the accept-time peer address: a "::" bind is
# dual-stack, IPv4 peers off it read as plain IPv4 (not v4-mapped), and a
# host without IPv6 gets an IPv4 listener plus a warning instead of a
# dead accept loop.
class ListenerTest < Minitest::Test
  class FakeStore
    attr_reader :logged

    def initialize = @logged = []
    def log(level, message) = @logged << [ level, message ]
    def banned_cidrs = []
  end

  class Server < MailOnRails::Netserv::Server
    def protocol_name = "TEST"
  end

  def setup
    @store = FakeStore.new
    @server = Server.new(@store, [], nil)
    @cleanup = []
  end

  def teardown
    @cleanup.each { |c| c.call rescue nil }
  end

  def listener(host)
    socket = @server.send(:build_listener, host, 0)
    @cleanup << -> { socket.close }
    socket
  end

  # Connects to +listener+ from +client_host+, accepts, and returns the
  # peer address the server would key on.
  def accepted_peer_ip(listener, client_host)
    port = listener.local_address.ip_port
    client = TCPSocket.new(client_host, port)
    @cleanup << -> { client.close }
    socket, addr = listener.accept
    @cleanup << -> { socket.close }
    @server.send(:peer_ip, socket, addr)
  end

  def ipv6_available?
    Socket.new(:INET6, :STREAM).close
    true
  rescue Errno::EAFNOSUPPORT
    false
  end

  test "a :: listener reports IPv4 peers as plain IPv4" do
    skip "no IPv6 stack" unless ipv6_available?
    socket = listener("::")

    assert_equal "127.0.0.1", accepted_peer_ip(socket, "127.0.0.1")
    assert_empty @store.logged
  end

  test "a :: listener reports IPv6 peers canonically" do
    skip "no IPv6 stack" unless ipv6_available?
    socket = listener("::")

    assert_equal "::1", accepted_peer_ip(socket, "::1")
  end

  test "an IPv4 listener is unchanged" do
    socket = listener("127.0.0.1")

    assert_equal "127.0.0.1", accepted_peer_ip(socket, "127.0.0.1")
  end

  test "a :: bind on a host without IPv6 falls back to 0.0.0.0 with a warning" do
    original = @server.method(:bind_listener)
    @server.define_singleton_method(:bind_listener) do |addr|
      raise Errno::EADDRNOTAVAIL, "bind" if addr.ipv6?

      original.call(addr)
    end
    socket = listener("::")

    assert socket.local_address.ipv4?
    assert_equal "0.0.0.0", socket.local_address.ip_address
    assert_equal "127.0.0.1", accepted_peer_ip(socket, "127.0.0.1")
    warning = @store.logged.find { |level, _| level == :warn }&.last
    assert_match(/cannot bind ::.*IPv6 unavailable.*0\.0\.0\.0/, warning.to_s)
  end

  test "a bind failure on a specific IPv6 address is not papered over" do
    original = @server.method(:bind_listener)
    @server.define_singleton_method(:bind_listener) do |addr|
      raise Errno::EADDRNOTAVAIL, "bind" if addr.ipv6?

      original.call(addr)
    end

    assert_raises(Errno::EADDRNOTAVAIL) { @server.send(:build_listener, "2001:db8::1", 0) }
  end
end
