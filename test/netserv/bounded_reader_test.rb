# frozen_string_literal: true

require "test_helper"
require "socket"
require "timeout"
require "mail_on_rails/netserv/tls"
require "mail_on_rails/netserv/bounded_reader"

# Netserv::BoundedReader: the line limit both protocol servers read with
# has to hold on TLS, where OpenSSL::Buffering#gets ignores it until the
# terminator shows up.
class BoundedReaderTest < Minitest::Test
  Reader = MailOnRails::Netserv::BoundedReader
  PEMS = MailOnRails::Netserv::Tls.generate_self_signed([ "localhost" ])
  LIMIT = 4096

  def teardown
    [ @client, @server, @listener ].compact.each do |io|
      io.close
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil
    end
  end

  def tls_pair
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = OpenSSL::X509::Certificate.new(PEMS[:cert])
    ctx.key = OpenSSL::PKey.read(PEMS[:key])
    @listener = TCPServer.new("127.0.0.1", 0)
    connector = Thread.new do
      client = OpenSSL::SSL::SSLSocket.new(TCPSocket.new("127.0.0.1", @listener.addr[1]))
      client.sync_close = true
      client.connect
      client
    end
    @server = OpenSSL::SSL::SSLSocket.new(@listener.accept, ctx)
    @server.sync_close = true
    @server.accept
    @client = connector.value
    [ @client, @server ]
  end

  def plain_pair
    @client, @server = UNIXSocket.pair
    [ @client, @server ]
  end

  def buffer_bytes(reader) = reader.instance_variable_get(:@buffer).bytesize

  test "TLS: a stream with no terminator comes back limit bytes at a time" do
    client, server = tls_pair
    writer = Thread.new { client.write("A" * 2_000_000) }
    reader = Reader.new(server)

    3.times do
      chunk = Timeout.timeout(5) { reader.gets("\r\n", LIMIT) }
      assert_equal LIMIT, chunk.bytesize
      assert_operator buffer_bytes(reader), :<=, LIMIT + Reader::BLOCK
    end
    assert_equal 0, server.instance_variable_get(:@rbuffer).bytesize,
                 "nothing may pile up in OpenSSL's own buffer"
  ensure
    client&.close
    writer&.join(2)
  end

  test "TLS: lines, a terminator split across reads, and pipelined lines" do
    client, server = tls_pair
    reader = Reader.new(server)

    client.write("EHLO a\r\nMAIL FROM:<x>\r\nRCPT")
    assert_equal "EHLO a\r\n", reader.gets("\r\n", LIMIT)
    assert_equal "MAIL FROM:<x>\r\n", reader.gets("\r\n", LIMIT)
    assert reader.buffered?, "the partial third line is held"

    Thread.new { sleep 0.05; client.write(" TO:<y>\r"); sleep 0.05; client.write("\nQUIT\r\n") }
    assert_equal "RCPT TO:<y>\r\n", reader.gets("\r\n", LIMIT)
    assert_equal "QUIT\r\n", reader.gets("\r\n", LIMIT)
    assert_not reader.buffered?
  end

  # The reader must cut exactly where a plain socket's gets cuts, or the
  # two transports would frame the same bytes differently.
  test "TLS: a terminator straddling the limit splits as a plain socket splits it" do
    bytes = "B" * (LIMIT - 1) + "\r\nnext\r\n"
    client, server = tls_pair
    reader = Reader.new(server)
    client.write(bytes)
    plain_client, plain_server = UNIXSocket.pair
    plain_client.write(bytes)

    first = reader.gets("\r\n", LIMIT)
    assert_equal LIMIT, first.bytesize
    assert first.end_with?("\r")
    assert_equal plain_server.gets("\r\n", LIMIT), first
    assert_equal plain_server.gets("\r\n", LIMIT), reader.gets("\r\n", LIMIT)
  ensure
    plain_client&.close
    plain_server&.close
  end

  test "TLS: read returns exactly the bytes asked for and leaves the rest" do
    client, server = tls_pair
    reader = Reader.new(server)
    client.write("BDAT 10 LAST\r\n0123456789NOOP\r\n")

    assert_equal "BDAT 10 LAST\r\n", reader.gets("\r\n", LIMIT)
    assert_equal "0123456789", reader.read(10)
    assert_equal "NOOP\r\n", reader.gets("\r\n", LIMIT)
  end

  test "TLS: read spans records larger than one block" do
    client, server = tls_pair
    reader = Reader.new(server)
    payload = Random.bytes(70_000)
    writer = Thread.new { client.write(payload + "x\r\n") }

    assert_equal payload, reader.read(70_000)
    assert_equal "x\r\n", reader.gets("\r\n", LIMIT)
  ensure
    writer&.join(2)
  end

  test "TLS: EOF returns the unterminated remainder, then nil" do
    client, server = tls_pair
    reader = Reader.new(server)
    client.write("half a line")
    client.close

    assert_equal "half a line", reader.gets("\r\n", LIMIT)
    assert_nil reader.gets("\r\n", LIMIT)
    assert_nil reader.read(5)
  end

  test "TLS: read at EOF returns what there was" do
    client, server = tls_pair
    reader = Reader.new(server)
    client.write("abc")
    client.close

    assert_equal "abc", reader.read(10)
    assert_nil reader.read(10)
  end

  test "TLS: lines are binary" do
    client, server = tls_pair
    reader = Reader.new(server)
    client.write("caf\xC3\xA9 \xFF\r\n".b)

    line = reader.gets("\r\n", LIMIT)
    assert_equal Encoding::BINARY, line.encoding
    assert_equal "caf\xC3\xA9 \xFF\r\n".b, line
  end

  test "TLS: the socket's read timeout still applies" do
    _client, server = tls_pair
    server.to_io.timeout = 0.2
    reader = Reader.new(server)

    assert_raises(IO::TimeoutError) { reader.gets("\r\n", LIMIT) }
  end

  test "plain: passes through to the socket, limit included" do
    client, server = plain_pair
    reader = Reader.new(server)
    client.write("NOOP\r\n" + "C" * 10_000)

    assert_equal "NOOP\r\n", reader.gets("\r\n", LIMIT)
    assert_equal LIMIT, reader.gets("\r\n", LIMIT).bytesize
    assert_equal "CC", reader.read(2)
    assert_not reader.buffered?, "a plain socket never fills the reader's own buffer"
  end
end
