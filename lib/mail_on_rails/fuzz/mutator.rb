# frozen_string_literal: true

module MailOnRails
  module Fuzz
    # Byte- and token-level mutations shared by the SMTP and IMAP harnesses.
    class Mutator
      SMTP_VERBS = %w[EHLO HELO MAIL RCPT DATA AUTH RSET NOOP VRFY STARTTLS QUIT].freeze
      IMAP_VERBS = %w[CAPABILITY NOOP LOGIN AUTHENTICATE SELECT EXAMINE LIST FETCH SEARCH
                      STORE COPY MOVE APPEND CREATE DELETE RENAME STATUS IDLE LOGOUT].freeze
      EICAR = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

      def initialize(rng)
        @rng = rng
      end

      def email(local: "user", domain: "example.test")
        mutate("#{local}@#{domain}")
      end

      def mutate(str)
        return garbage_line if str.nil? || str.empty?

        case @rng.rand(8)
        when 0 then str + @rng.bytes(@rng.rand(1..16)).force_encoding(Encoding::BINARY)
        when 1 then str.tr("@.", @rng.rand(2).zero? ? ".." : "@@")
        when 2 then str[0, @rng.rand(0..str.bytesize)]
        when 3 then garbage_line
        when 4 then str * @rng.rand(2..4)
        when 5 then str.gsub(/[a-z]/) { |c| (c.ord + @rng.rand(-1..1)).chr }
        when 6 then "\x00#{str}\x00"
        else str
        end
      end

      def maybe(value, chance: 0.35)
        @rng.rand < chance ? mutate(value) : value
      end

      def garbage_line(verbs: SMTP_VERBS)
        case @rng.rand(7)
        when 0 then @rng.bytes(@rng.rand(1..120)).delete("\r\n")
        when 1 then (1..31).map(&:chr).shuffle(random: @rng).take(@rng.rand(1..12)).join.delete("\r\n")
        when 2 then "\xC3\x28\xA0\xFF\xFE".b + @rng.bytes(@rng.rand(1..40))
        when 3 then "#{verbs.sample(random: @rng)} #{@rng.bytes(@rng.rand(0..40)).delete("\r\n")}"
        when 4 then "A" * @rng.rand(1..9000)
        when 5 then "#{verbs.sample(random: @rng)} FROM:<#{@rng.bytes(12).delete("\r\n")}>"
        when 6 then EICAR
        end
      end

      def malicious_body
        case @rng.rand(5)
        when 0 then "From: attacker@evil.test\r\nTo: user@example.test\r\nSubject: fuzz\r\n\r\n#{EICAR}\r\n"
        when 1 then "Received: #{@rng.rand(10)} hops\r\n" * @rng.rand(3..8) + "\r\nbody\r\n"
        when 2 then "Subject: inject\r\n\r\n.\r\nMAIL FROM:<a@b.test>\r\n"
        when 3 then "A" * @rng.rand(500..5000) + "\r\n"
        else "From: fuzz@example.test\r\n\r\n#{garbage_line}\r\n"
        end
      end

      def tag = "a#{@rng.rand(1000)}"
    end
  end
end
