# frozen_string_literal: true

require "socket"

# Scripted clamd stand-in for the INSTREAM protocol (twin of the one in the
# mail_on_rails_smtp gem's suite): reads whatever the client streams, then
# answers per mode. Real-engine verification is the manual EICAR smoke
# against a clamav/clamav container - never part of the automated suites.
#
# Modes: :clean, :infected, :garbage (unparseable), :hang (never answers).
class FakeClamd
  REPLIES = {
    clean: "stream: OK\0",
    infected: "stream: Eicar-Test-Signature FOUND\0",
    garbage: "INSTREAM size limit exceeded. ERROR\0"
  }.freeze

  def self.serving(mode)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        conn = server.accept
        conn.read # everything up to the client's close_write
        if mode == :hang
          sleep
        else
          conn.write(REPLIES.fetch(mode))
        end
        conn.close
      end
    rescue IOError, Errno::EBADF
      nil # server closed - test is done
    end
    yield "127.0.0.1:#{server.addr[1]}"
  ensure
    thread&.kill
    server&.close
  end
end
