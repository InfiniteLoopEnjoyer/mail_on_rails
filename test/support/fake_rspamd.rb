# frozen_string_literal: true

require "socket"
require "json"

# Scripted rspamd stand-in: reads one POST per connection, answers
# /checkv2 with the given action and the controller's /learnspam,/learnham
# with success (or, with learn_status: 404, rspamd's "already learned"
# refusal), and keeps the requests so tests can assert what the client
# sent (and whether it called at all). Modeled on FakeClamd.
#
#   FakeRspamd.serving("reject") { |addr, fake| ... }   # "127.0.0.1:<port>"
class FakeRspamd
  attr_reader :requests # one {line:, headers:, body:} per handled request

  def initialize(action, score: 15.0, required_score: 15.0, learn_status: 200)
    @action = action
    @score = score
    @required_score = required_score
    @learn_status = learn_status
    @requests = []
  end

  def self.serving(action, **options)
    fake = new(action, **options)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        conn = server.accept
        fake.handle(conn)
        conn.close
      end
    rescue IOError, Errno::EBADF
      nil # server closed - test is done
    end
    yield "127.0.0.1:#{server.addr[1]}", fake
  ensure
    thread&.kill
    server&.close
  end

  def handle(conn)
    request_line = conn.gets("\r\n")
    headers = {}
    while (line = conn.gets("\r\n")) && line != "\r\n"
      key, value = line.chomp.split(":", 2)
      headers[key.downcase] = value.to_s.strip
    end
    body = conn.read(headers["content-length"].to_i)
    @requests << { line: request_line, headers: headers, body: body }

    if request_line.to_s.start_with?("POST /learn")
      respond(conn, *learn_reply(request_line))
    else
      payload = JSON.generate({ "action" => @action, "score" => @score,
                                "required_score" => @required_score, "symbols" => {} })
      respond(conn, "200 OK", payload)
    end
  end

  private

  def learn_reply(request_line)
    case @learn_status
    when 200 then [ "200 OK", JSON.generate({ "success" => true }) ]
    when 404
      klass = request_line.include?("/learnham") ? "ham" : "spam"
      [ "404 Not Found", JSON.generate({ "error" => "<abc123> has been already learned as #{klass}, ignore it" }) ]
    else [ "#{@learn_status} Error", JSON.generate({ "error" => "scripted failure" }) ]
    end
  end

  def respond(conn, status, payload)
    conn.write("HTTP/1.1 #{status}\r\nContent-Type: application/json\r\n" \
               "Content-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
  end
end
