# frozen_string_literal: true

require "test_helper"
require "socket"
require "tmpdir"
require "fileutils"
require "mail_on_rails/smtp_server"
require "mail_on_rails/smtp/store/memory"

# The denylist as a client experiences it: the full server stack booted on
# loopback (the spec[:tcp_server] seam), with SMTP_DENYLIST_FILE pointing
# at a scratch file. A banned peer gets a bare close before any banner;
# everyone else gets the normal 220 greeting.
class DenylistWireTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @path = File.join(@dir, "banned_ips")
    ENV["SMTP_DENYLIST_FILE"] = @path
    @cleanup = []
  end

  def teardown
    ENV.delete("SMTP_DENYLIST_FILE")
    @cleanup.each { |c| c.call rescue nil }
    FileUtils.remove_entry(@dir)
  end

  def start_server
    store = MailOnRails::Smtp::Store::Memory.new
    listener = TCPServer.new("127.0.0.1", 0)
    @cleanup << -> { listener.close }
    spec = { host: "127.0.0.1", port: listener.addr[1], tls: :starttls, role: :mx,
             hostname: "mx.test", tcp_server: listener }
    thread = Thread.new { MailOnRails::SmtpServer.run(store, [ spec ], nil) }
    @cleanup << -> { thread.kill }
    spec
  end

  def connect(spec)
    client = TCPSocket.new("127.0.0.1", spec[:port])
    client.timeout = 5
    @cleanup << -> { client.close rescue nil }
    client
  end

  test "a banned peer is closed without a banner" do
    File.write(@path, "127.0.0.1\n")
    spec = start_server

    assert_nil connect(spec).gets("\r\n"), "expected EOF before any banner"
  end

  test "a banned range covering the peer is enough" do
    File.write(@path, "127.0.0.0/8\n")
    spec = start_server

    assert_nil connect(spec).gets("\r\n")
  end

  test "an empty denylist serves the normal banner" do
    File.write(@path, "")
    spec = start_server

    assert_match(/\A220 /, connect(spec).gets("\r\n"))
  end
end
