# frozen_string_literal: true

require "openssl"

module MailOnRails
  module Netserv
    # The session's read side: gets with a line limit that holds on TLS.
    #
    # IO#gets(eol, limit) on a TCPSocket stops at +limit+ bytes whether or
    # not the terminator has arrived. OpenSSL::Buffering#gets does not: it
    # reads until it finds the terminator and applies +limit+ only to what
    # it returns, re-scanning its whole buffer after every record. A TLS
    # peer that streams bytes and never sends the terminator therefore
    # grows the buffer without bound, at quadratic CPU, inside one gets
    # call that no between-lines check ever sees.
    #
    # On a TLS socket this reader does its own buffering instead: it pulls
    # at most BLOCK bytes at a time and never holds more than the caller's
    # limit plus one block. A plain socket is passed straight through to
    # the C implementation, which already honours the limit.
    #
    # One reader per socket: after STARTTLS the session builds a new one
    # around the SSLSocket (a plain socket never fills this buffer, so
    # there is nothing of the cleartext side to carry over or discard).
    class BoundedReader
      BLOCK = 16_384

      def initialize(socket)
        @socket = socket
        @tls = socket.is_a?(OpenSSL::SSL::SSLSocket)
        @buffer = +"".b
        @eof = false
      end

      # IO#gets(eol, limit): the next line through +eol+, or the next
      # +limit+ bytes when no terminator ends inside them, or what is left
      # at EOF; nil at EOF with nothing buffered.
      def gets(eol, limit)
        return @socket.gets(eol, limit) unless @tls

        scanned = 0
        loop do
          # Resume the search where the last one stopped, backed up far
          # enough to catch a terminator split across two reads.
          from = [ scanned - eol.bytesize + 1, 0 ].max
          index = @buffer.byteindex(eol, from)
          return take(index + eol.bytesize) if index && index + eol.bytesize <= limit
          return take(limit) if @buffer.bytesize >= limit
          return take(@buffer.bytesize) if @eof

          scanned = @buffer.bytesize
          fill
        end
      end

      # IO#read(length): exactly +length+ bytes, fewer at EOF, nil at EOF
      # with nothing buffered.
      def read(length)
        return @socket.read(length) unless @tls

        fill while @buffer.bytesize < length && !@eof
        take(length)
      end

      # Bytes already received and waiting here - a caller about to sleep
      # on the socket's readability must look first, or it sleeps on data
      # it already has.
      def buffered?
        !@buffer.empty?
      end

      private

      def take(length)
        return nil if @buffer.empty?

        @buffer.slice!(0, length)
      end

      def fill
        @buffer << @socket.readpartial(BLOCK)
      rescue EOFError
        @eof = true
      end
    end
  end
end
