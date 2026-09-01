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

# The accept loop under resource exhaustion: accept(2) failing with
# EMFILE (the process is out of descriptors - a flood, or a leak) must not
# end the accept thread, which would leave the port bound and deaf until
# the Runtime monitor restarts the server. It backs off, logs once per
# burst, and serves the next connection normally.
class AcceptLoopTest < Minitest::Test
  class FakeStore
    attr_reader :logged

    def initialize = @logged = []
    def log(level, message) = @logged << [ level, message ]
    def banned_cidrs = []
  end

  # The smallest session the scaffolding will run: greets and hangs up.
  class HelloSession
    def initialize(socket, _store, _spec, _ctx)
      @socket = socket
    end

    def run
      @socket.write("220 hello\r\n")
    end

    def live_info = {}
  end

  class Server < MailOnRails::Netserv::Server
    MAX_CONNECTIONS = 4
    OPS_SYNC_INTERVAL = 60

    def protocol_name = "TEST"
    def busy_line = "421 busy"
    def listener_label(spec) = "test:#{spec[:port]}"
    def session_class = HelloSession
  end

  # A listener whose accept fails with the scripted errors first, then
  # behaves like the real socket underneath.
  class FlakyListener
    def initialize(real, failures)
      @real = real
      @failures = failures
    end

    def accept
      raise @failures.shift if @failures.any?

      @real.accept
    end

    def close = @real.close
    def closed? = @real.closed?
    def local_address = @real.local_address
  end

  def setup
    @store = FakeStore.new
    @real = Socket.new(:INET, :STREAM)
    @real.setsockopt(:SOCKET, :REUSEADDR, true)
    @real.bind(Addrinfo.tcp("127.0.0.1", 0))
    @real.listen(5)
    @port = @real.local_address.ip_port
  end

  def teardown
    @server&.shutdown(drain: 1)
    @thread&.join(2)
    @real.close unless @real.closed?
  end

  def run_server(failures)
    listener = FlakyListener.new(@real, failures)
    @server = Server.new(@store, [ { tcp_server: listener, port: @port, host: "127.0.0.1" } ], nil)
    @thread = Thread.new { @server.run }
    assert @server.wait_ready(5), "the listener must come up"
  end

  def greeting
    client = TCPSocket.new("127.0.0.1", @port)
    client.timeout = 5
    client.gets
  ensure
    client&.close
  end

  test "EMFILE on accept is retried, logged once, and the next connection is served" do
    run_server([ Errno::EMFILE.new("accept"), Errno::EMFILE.new("accept") ])

    assert_equal "220 hello\r\n", greeting
    assert @server.healthy?, "the accept thread must survive resource exhaustion"
    starvation = @store.logged.select { |_level, message| message.include?("cannot accept") }
    assert_equal 1, starvation.size, "one log line per burst, not per failed accept"
    assert_match(/EMFILE/, starvation.first.last)
  end

  test "an aborted connection is skipped silently" do
    run_server([ Errno::ECONNABORTED.new("accept") ])

    assert_equal "220 hello\r\n", greeting
    assert_empty @store.logged.select { |level, _| level == :error }
  end
end
