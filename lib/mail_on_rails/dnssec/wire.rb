# frozen_string_literal: true

module MailOnRails
  module Dnssec
    # The little of the wire format Transport reads for itself, before
    # (or instead of) handing a datagram to dnsruby's Message codec.
    #
    # Two reasons it exists. Whether a datagram is the reply to our
    # query at all is a question about its fixed header, and is better
    # asked before any attacker-shaped RDATA is parsed. And dnsruby
    # decodes a message whole or not at all: its record classes validate
    # as they parse and raise whatever comes to hand (ArgumentError for
    # a TLSA whose digest has the wrong length, NoMethodError for a
    # clipped NSEC bitmap), so one bad record anywhere takes the message
    # with it. For most records "undecodable" is the right verdict. For
    # TLSA it is not: RFC 7671 section 4.1 has a client set unusable
    # records aside and judge the RRset by the rest, and that needs the
    # record decoded as published - not least because the RRSIG covers
    # its RDATA byte for byte.
    module Wire
      HEADER_BYTES = 12
      QR = 0x80
      TC = 0x02
      TLSA = 52
      IN = 1
      # RFC 6698 section 2.1.3 private-use matching type: dnsruby checks
      # neither the length nor the contents of the association data
      # under it.
      UNCHECKED_MATCHING_TYPE = 255

      # A TLSA record exactly as published, for the ones dnsruby's own
      # class refuses to hold: same fields, same RDATA encoding. Only
      # copying differs - RR#clone goes back through the validating
      # decoder, and RRSet clones every record it is given.
      class PublishedTlsa < Dnsruby::RR::IN::TLSA
        # +decoded+ is the record as dnsruby would take it, i.e. under
        # UNCHECKED_MATCHING_TYPE; +matching_type+ is the real one.
        def self.from(decoded, matching_type)
          record = allocate
          decoded.instance_variables.each do |field|
            record.instance_variable_set(field, decoded.instance_variable_get(field))
          end
          record.matching_type = matching_type
          record
        end

        def clone
          dup
        end
      end

      module_function

      # The header says this is a response carrying +id+.
      def response_to?(data, id)
        data.bytesize >= HEADER_BYTES && data.unpack1("n") == id && data.getbyte(2).anybits?(QR)
      end

      def truncated?(data)
        data.bytesize >= HEADER_BYTES && data.getbyte(2).anybits?(TC)
      end

      # A Dnsruby::Message, or nil for bytes dnsruby cannot represent -
      # whatever it raised on the way. TLSA records that only dnsruby's
      # own validation objects to are kept, exactly as published.
      def decode(data)
        Dnsruby::Message.decode(data)
      rescue StandardError
        decode_keeping_unusable_tlsa(data)
      end

      # Second attempt for a message dnsruby refused: every TLSA record
      # its constructor rejects is decoded under a matching type dnsruby
      # does not check, then swapped for a PublishedTlsa carrying the
      # real one. The record encodes to the published RDATA again (so
      # signatures over the RRset verify), and reaches
      # Dane.usable_records for what it is. Anything else wrong with the
      # message still makes it nil.
      def decode_keeping_unusable_tlsa(data)
        rejected = rejected_tlsa(data)
        return nil if rejected.empty?

        patched = data.b
        rejected.each { |record| patched.setbyte(record[:offset] + 2, UNCHECKED_MATCHING_TYPE) }
        msg = Dnsruby::Message.decode(patched)
        rejected.each do |record|
          section = msg.public_send(record[:section])
          rr = section[record[:index]]
          return nil unless rr.is_a?(Dnsruby::RR::IN::TLSA) && rr.matching_type == UNCHECKED_MATCHING_TYPE

          section[record[:index]] = PublishedTlsa.from(rr, record[:matching_type])
        end
        msg
      rescue StandardError
        nil
      end

      # Where the TLSA records dnsruby would refuse sit: section, index
      # within it, RDATA offset and the published matching type. Empty
      # when there are none or the message does not parse this far.
      def rejected_tlsa(data)
        found = []
        each_record(data) do |section, index, type, klass, offset, length|
          next unless type == TLSA && klass == IN && length >= 3

          usage, selector, matching_type = data.unpack("@#{offset}CCC")
          next if matching_type == UNCHECKED_MATCHING_TYPE
          next if dnsruby_accepts_tlsa?(usage, selector, matching_type, data.byteslice(offset + 3, length - 3))

          found << { section: section, index: index, offset: offset, matching_type: matching_type }
        end
        found
      rescue ArgumentError, TypeError # ran off the end of the message
        []
      end

      def dnsruby_accepts_tlsa?(usage, selector, matching_type, association)
        Dnsruby::RR::IN::TLSA.new([ usage, selector, matching_type, association ])
        true
      rescue StandardError
        false
      end

      # Walks the three record sections, yielding section, index, type,
      # class, RDATA offset and RDATA length per record. Raises
      # ArgumentError when the message ends early.
      def each_record(data)
        raise ArgumentError, "short message" if data.bytesize < HEADER_BYTES

        questions, *counts = data.unpack("@4n4")
        position = HEADER_BYTES
        questions.times { position = skip_name(data, position) + 4 }
        %i[answer authority additional].zip(counts) do |section, count|
          count.times do |index|
            position = skip_name(data, position)
            raise ArgumentError, "short record" if position + 10 > data.bytesize

            type, klass, _ttl, length = data.unpack("@#{position}nnNn")
            position += 10
            raise ArgumentError, "short RDATA" if position + length > data.bytesize

            yield section, index, type, klass, position, length
            position += length
          end
        end
      end

      # The offset just past the (possibly compressed) name at +position+.
      def skip_name(data, position)
        loop do
          length = data.getbyte(position)
          raise ArgumentError, "short name" if length.nil?
          return position + 2 if length >= 0xC0 # compression pointer ends the name
          raise ArgumentError, "reserved label type" if length > 63

          position += 1 + length
          return position if length.zero?
        end
      end
    end
  end
end
