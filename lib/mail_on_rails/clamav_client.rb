# frozen_string_literal: true

require "socket"
require "timeout"
require_relative "settings"

module MailOnRails
  # Streams a raw RFC822 message to a clamd daemon over its INSTREAM
  # protocol and reports a three-way verdict: :clean, :infected (with the
  # signature name), or :unavailable (clamd unreachable, timed out, or
  # answered something unparseable - including its own size-limit error).
  # The session decides policy; this client never raises.
  #
  # clamd decodes MIME itself, so the whole message is streamed as one
  # chunk - no attachment splitting (same approach as Postal).
  class ClamavClient
    Result = Struct.new(:status, :virus) do
      def clean? = status == :clean
      def infected? = status == :infected
      def unavailable? = status == :unavailable
    end

    DEFAULT_PORT = 3310

    # Address/timeout read through the settings schema per scan (the
    # client is constructed per message), so scanning can be pointed
    # elsewhere or disabled without a restart; per-listener
    # spec[:clamav_addr]/[:clamav_timeout] override them (the test
    # seam). An empty addr disables scanning.
    def self.enabled? = !Settings[:smtp_clamav_addr].to_s.empty?

    def initialize(addr: Settings[:smtp_clamav_addr], timeout: Settings[:smtp_clamav_timeout])
      host, port = addr.to_s.split(":", 2)
      @host = host
      @port = (port || DEFAULT_PORT).to_i
      @timeout = timeout
    end

    def scan(raw)
      reply = nil
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@host, @port)
        begin
          socket.write("zINSTREAM\0")
          socket.write([ raw.bytesize ].pack("N"))
          socket.write(raw)
          socket.write([ 0 ].pack("N"))
          socket.close_write
          reply = socket.read
        ensure
          begin
            socket.close
          rescue IOError
            nil
          end
        end
      end
      parse(reply)
    rescue Timeout::Error, SystemCallError, IOError, SocketError
      Result.new(:unavailable, nil)
    end

    private

    # clamd answers "stream: OK" or "stream: <Signature> FOUND" (NUL/LF
    # terminated); anything else (error line, truncated reply) counts as
    # unavailable rather than clean.
    def parse(reply)
      case reply.to_s
      when /\Astream: OK[\s\0]*\z/i then Result.new(:clean, nil)
      when /\Astream: (.+?) FOUND[\s\0]*\z/i then Result.new(:infected, Regexp.last_match(1).strip)
      else Result.new(:unavailable, nil)
      end
    end
  end
end
