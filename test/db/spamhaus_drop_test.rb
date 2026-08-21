# frozen_string_literal: true

require_relative "test_helper"
require "socket"

class SpamhausDropTest < DbSuite::TestCase
  def fetch_returning(v4_cidrs)
    lambda do |url|
      if url.include?("v4")
        v4_cidrs.map { |cidr| %({"cidr":"#{cidr}"}) }.push(%({"type":"metadata"})).join("\n")
      else
        %({"cidr":"2001:db8::/32"})
      end
    end
  end

  test "imports the DROP list and a manual row keeps its note across refreshes" do
    MailOnRails::BannedIp.create!(cidr: "198.51.100.0/24", note: "manual ban", source: "manual")

    count = MailOnRails::SpamhausDrop.refresh!(fetch: fetch_returning([ "192.0.2.0/24", "198.51.100.0/24" ]))

    assert_equal 3, count
    manual = MailOnRails::BannedIp.find_by!(cidr: "198.51.100.0/24")
    assert_equal "manual", manual.source
    assert_equal "manual ban", manual.note
    assert_equal 2, MailOnRails::BannedIp.where(source: "spamhaus_drop").count

    # A later list without 192.0.2.0/24 drops that import; the manual row
    # is never spamhaus's to remove.
    MailOnRails::SpamhausDrop.refresh!(fetch: fetch_returning([ "203.0.113.0/24" ]))
    remaining = MailOnRails::BannedIp.order(:cidr).pluck(:cidr, :source)
    assert_includes remaining, [ "198.51.100.0/24", "manual" ]
    assert_includes remaining, [ "203.0.113.0/24", "spamhaus_drop" ]
    assert_not MailOnRails::BannedIp.exists?(cidr: "192.0.2.0/24")
  end

  # Serves one HTTP response with the given body over a background thread,
  # yielding "http://127.0.0.1:<port>/". Chunked so the reader sees bytes
  # before the whole body is (never) finished.
  def with_http_server(body_bytes)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      socket = server.accept
      socket.gets("\r\n\r\n") # drain the request headers
      socket.write("HTTP/1.1 200 OK\r\nContent-Length: #{body_bytes.bytesize}\r\n\r\n")
      socket.write(body_bytes)
      socket.close
    rescue IOError, Errno::EPIPE
      nil # the client hung up when the cap tripped - expected
    end
    yield "http://127.0.0.1:#{server.addr[1]}/drop_v4.json"
  ensure
    thread&.kill
    server&.close
  end

  test "the capped fetch aborts a body past the byte limit" do
    with_http_server("x" * 2048) do |url|
      error = assert_raises(MailOnRails::SpamhausDrop::FetchError) do
        MailOnRails::SpamhausDrop.fetch_capped(url, limit: 1024)
      end
      assert_match(/exceeded 1024 bytes/, error.message)
    end
  end

  test "the capped fetch returns a body within the limit" do
    with_http_server(%({"cidr":"192.0.2.0/24"})) do |url|
      assert_equal %({"cidr":"192.0.2.0/24"}), MailOnRails::SpamhausDrop.fetch_capped(url, limit: 1024)
    end
  end

  test "the capped fetch raises on a non-success status" do
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      socket = server.accept
      socket.gets("\r\n\r\n")
      socket.write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
      socket.close
    rescue IOError, Errno::EPIPE
      nil
    end
    url = "http://127.0.0.1:#{server.addr[1]}/drop_v4.json"

    error = assert_raises(MailOnRails::SpamhausDrop::FetchError) { MailOnRails::SpamhausDrop.fetch_capped(url) }
    assert_match(/returned 503/, error.message)
  ensure
    thread&.kill
    server&.close
  end
end
