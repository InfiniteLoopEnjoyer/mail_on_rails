# frozen_string_literal: true

require "socket"
require "json"

# Scripted rspamd stand-in for the /checkv2 HTTP endpoint: reads the request
# (capturing the headers the analyzer sends - IP/Helo/From/...), then answers
# per script. Real-engine verification is a manual check against an
# rspamd/rspamd container - never part of the automated suites.
#
# Yields the "host:port" address and a Hash that fills in with the captured
# request headers (downcased keys) once a request has been served.
class FakeRspamd
  # `body` is a Hash serialized to JSON (or a raw String for the garbage
  # case). `status` sets the HTTP status; `hang: true` never answers.
  def self.serving(body, status: 200, hang: false)
    server = TCPServer.new("127.0.0.1", 0)
    captured = {}
    thread = Thread.new do
      loop do
        conn = server.accept
        captured.replace(read_request(conn))
        if hang
          sleep
        else
          payload = body.is_a?(String) ? body : JSON.generate(body)
          conn.write("HTTP/1.1 #{status} X\r\n" \
                     "Content-Type: application/json\r\n" \
                     "Content-Length: #{payload.bytesize}\r\n" \
                     "Connection: close\r\n\r\n")
          conn.write(payload)
        end
        conn.close
      end
    rescue IOError, Errno::EBADF
      nil # server closed - test is done
    end
    yield "127.0.0.1:#{server.addr[1]}", captured
  ensure
    thread&.kill
    server&.close
  end

  # Reads the request line + headers and consumes the Content-Length body,
  # returning the headers as a downcased-key Hash.
  def self.read_request(conn)
    headers = {}
    conn.gets # request line
    while (line = conn.gets) && line != "\r\n"
      key, value = line.split(":", 2)
      headers[key.strip.downcase] = value.to_s.strip if key
    end
    length = headers["content-length"].to_i
    conn.read(length) if length.positive?
    headers
  end
end
