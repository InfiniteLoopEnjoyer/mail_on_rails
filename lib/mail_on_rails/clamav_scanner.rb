# frozen_string_literal: true

require "socket"
require "timeout"

module MailOnRails
  # Streams a raw RFC822 message to clamd over its INSTREAM protocol
  # (clamd decodes MIME itself, so attachments are covered). App-side
  # callers are the mailroom (all inbound mail - the exim edge does no
  # scanning of its own) and the IMAP APPEND path.
  #
  # Verdicts: :clean, :infected (with signature name), :unavailable (clamd
  # unreachable/timeout/unparseable answer). Never raises - callers decide
  # policy. Disabled unless SMTP_CLAMAV_ADDR is set (read per call:
  # no Ractors here, and tests can toggle it).
  module ClamavScanner
    Result = Struct.new(:status, :virus) do
      def clean? = status == :clean
      def infected? = status == :infected
      def unavailable? = status == :unavailable
    end

    DEFAULT_PORT = 3310
    DEFAULT_TIMEOUT = 10

    module_function

    def enabled?
      !addr.empty?
    end

    def addr
      ENV["SMTP_CLAMAV_ADDR"].to_s.strip
    end

    def timeout
      Integer(ENV.fetch("SMTP_CLAMAV_TIMEOUT", DEFAULT_TIMEOUT))
    end

    def scan(raw)
      host, port = addr.split(":", 2)
      reply = nil
      Timeout.timeout(timeout) do
        socket = TCPSocket.new(host, (port || DEFAULT_PORT).to_i)
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

    def parse(reply)
      case reply.to_s
      when /\Astream: OK[\s\0]*\z/i then Result.new(:clean, nil)
      when /\Astream: (.+?) FOUND[\s\0]*\z/i then Result.new(:infected, Regexp.last_match(1).strip)
      else Result.new(:unavailable, nil)
      end
    end
  end
end
