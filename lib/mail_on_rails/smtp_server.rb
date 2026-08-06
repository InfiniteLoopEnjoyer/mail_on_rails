# frozen_string_literal: true

require "time"
require "mail_on_rails/smtp/config"
require "mail_on_rails/smtp/server"
require "mail_on_rails/smtp/session_helpers"
require "mail_on_rails/smtp/sender_auth"
require "mail_on_rails/smtp/dnsbl"
require "mail_on_rails/smtp/clamav_client"

module MailOnRails
  # SMTP server (RFC 5321 subset), run on a thread by Smtp::Daemon -
  # standalone in this repo's container via bin/server, or embedded in a
  # host process in development. Listens on several ports with
  # production-style roles:
  #
  #   :mx          - inbound receiving (like port 25). No auth required, but
  #                  accepts only for existing local recipients. Offers AUTH
  #                  and STARTTLS opportunistically; unauthenticated mail is
  #                  stored untrusted (authenticated_as = nil).
  #   :submission  - outgoing submission (like ports 587/465). AUTH required
  #                  before MAIL FROM, over TLS only, and MAIL FROM must match
  #                  the authenticated account. Stored trusted.
  #
  # Accepted messages are persisted through the store's SMTP interface -
  # the ActiveRecord-backed Store::SmtpBackend in the app, Store::Memory in
  # tests.
  class SmtpServer < Smtp::Server
    # 1 MB under clamd's 25 MB StreamMaxLength: the app-side rescan streams
    # the message with our added headers, and a max-size message must not
    # blow the scanner's cap (which fails closed as a 451, forever).
    MAX_MESSAGE_BYTES = 24 * 1024 * 1024
    MAX_LINE = 4096
    MAX_RECEIVED_HOPS = 4
    MAX_RECIPIENTS = 100
    MAX_MESSAGES_PER_SESSION = 100
    MAX_AUTH_ATTEMPTS = 3
    # Per-session budget for 5xx syntax/state errors: a legitimate client
    # never accumulates these, a fuzzer or spam cannon does.
    MAX_PROTOCOL_ERRORS = 8
    MAX_CONNECTIONS = Smtp::Config.int("SMTP_MAX_CONN", 100, min: 1)
    # Per-IP anti-abuse, enforced on the accept side (ConnLimiter /
    # AuthThrottle): concurrent-connection cap per peer IP, and a lockout
    # after repeated failed AUTHs (which otherwise cost the host app an HTTP
    # credential check each, MAX_AUTH_ATTEMPTS per connection, fresh on
    # every reconnect). 0 disables either.
    MAX_CONNECTIONS_PER_IP = Smtp::Config.int("SMTP_MAX_CONN_PER_IP", 10)
    AUTH_LOCKOUT_FAILURES = Smtp::Config.int("SMTP_AUTH_LOCKOUT_FAILURES", 10)
    AUTH_LOCKOUT_SECONDS = Smtp::Config.int("SMTP_AUTH_LOCKOUT_SECONDS", 900, min: 1)
    # Sliding-window connection rate per peer IP; connections over the
    # budget are tarpitted with an escalating pre-banner delay (see
    # Smtp::RateLimiter). 0 disables.
    CONN_RATE_LIMIT = Smtp::Config.int("SMTP_CONN_RATE", 60)
    CONN_RATE_WINDOW = Smtp::Config.int("SMTP_CONN_RATE_WINDOW", 60, min: 1)
    # Protocol tracing default; per-listener spec[:trace] overrides. Read
    # at load time - in the app these files load from the Puma plugin, with
    # the environment already set.
    TRACE_DEFAULT = ENV["SMTP_TRACE"] == "1"
    LOG_REDACTION = "[redacted]"

    private

    def protocol_name = "SMTP"

    def busy_line = "421 Too many connections, try later"

    def locked_line = "421 Too many failed authentication attempts, try later"

    def listener_label(spec) = "#{spec[:port]}/#{spec[:tls]}/#{spec[:role]}"

    def session_class = Session

    class Session
      include Smtp::SessionHelpers

      # Set by Server when per-IP auth throttling is active: a no-arg
      # callable invoked once per failed authentication attempt.
      attr_writer :on_auth_failure

      def initialize(socket, store, spec, tls_ctx)
        @socket = socket
        @store = store
        @spec = spec
        @tls_ctx = tls_ctx
        @tls = spec[:tls] == :implicit
        @trace = spec.fetch(:trace, TRACE_DEFAULT)
        @helo_name = nil
        @authenticated_as = nil
        @auth_attempts = 0
        @protocol_errors = 0
        @on_auth_failure = nil
        @message_count = 0
        @continuation = nil
        reset
      end

      # Live-state snapshot for the ops UI (Server#connections). Read from
      # the web thread while the session thread runs, so plain values
      # only; a stale read costs nothing worse than a momentarily
      # out-of-date dashboard row.
      def live_info
        { user: @authenticated_as, helo: @helo_name,
          messages: @message_count, tls: @tls }
      end

      def run
        set_timeout(read_timeout)
        reply 220, "#{server_name} ESMTP service ready"
        while (chunk = @socket.gets("\r\n", MAX_LINE))
          break if handle_chunk(chunk) == :quit
        end
        # EOF with a continuation active means the peer vanished mid-DATA
        # or mid-AUTH; nothing has been stored, so ending here aborts it.
      rescue IO::TimeoutError
        # An idle peer is told why before the close (best effort - it may
        # already be gone).
        begin
          reply 421, "SMTP command timeout - closing connection"
        rescue StandardError
          nil
        end
      rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
        # client went away
      rescue StandardError => e
        @store.log(:error, "SMTP session error: #{e.class}: #{e.message}")
      ensure
        close_socket
      end

      private

      def reset
        @mail_from = nil
        @rcpt_to = []
      end

      def close_socket
        @socket.close
      rescue StandardError
        nil
      end

      # -- input handling ----------------------------------------------------
      #
      # The run loop above is the only read site. Each chunk is one
      # MAX_LINE-capped gets("\r\n") result: normally a full CRLF line, but
      # an overlong line arrives split with no terminator. Multi-line states
      # (DATA payload, AUTH challenge/response) install @continuation, which
      # then receives the raw chunks instead of the command dispatch and
      # clears itself when its exchange completes - Postal's @proc pattern.

      def handle_chunk(chunk)
        return @continuation.call(chunk) if @continuation

        line = line_from(chunk)
        trace "<= #{redact_for_trace(line)}"
        handle_command(line)
      end

      # A chunk without its CRLF is an overlong command line; normalize to
      # "" so dispatch rejects it rather than acting on a truncated command.
      def line_from(chunk)
        chunk.end_with?("\r\n") ? chunk.delete_suffix("\r\n") : ""
      end

      # -- protocol tracing --------------------------------------------------
      #
      # Debug-level log of the command/reply exchange, for diagnosing broken
      # peers. Credentials never reach the log: AUTH arguments are redacted
      # here, AUTH challenge responses are logged as a placeholder at the
      # challenge chokepoint, and DATA payloads bypass tracing entirely
      # (continuation chunks are never traced).

      def trace(message)
        @store.log(:debug, "SMTP #{message} (#{peer_ip})") if @trace
      end

      # An AUTH argument is an initial response - PLAIN's carries the
      # password, LOGIN's the username - so drop everything after the
      # mechanism (Postal's sanitize_input_for_log).
      def redact_for_trace(line)
        line.sub(/\A(AUTH[ \t]+\S+)[ \t].*/i) { "#{Regexp.last_match(1)} #{LOG_REDACTION}" }
      end

      # -- command dispatch --------------------------------------------------

      def handle_command(line)
        verb, arg = line.split(" ", 2)
        case verb&.upcase
        when "HELO", "EHLO" then helo(verb, arg)
        when "STARTTLS" then starttls(arg)
        when "AUTH" then auth(arg)
        when "MAIL" then mail_from(arg)
        when "RCPT" then rcpt_to(arg)
        when "DATA" then data
        when "RSET" then reset; reply 250, "OK"
        when "NOOP" then reply 250, "OK"
        when "VRFY" then reply 252, "Cannot verify, but will accept and try"
        when "QUIT" then reply 221, "Bye"; return :quit
        else error_reply 502, "Command not implemented"
        end
        nil
      end

      # RFC 5321 wants a domain or address literal as the argument;
      # validating it also keeps raw junk bytes out of the echoed
      # greeting. A repeated HELO/EHLO is legal and aborts any transaction
      # in progress (RFC 5321 4.1.4).
      def helo(verb, arg)
        name = arg.to_s.strip
        unless name.match?(/\A[A-Za-z0-9\[\].:_-]+\z/)
          return error_reply 501, "Syntactically invalid #{verb.upcase} argument"
        end

        @helo_name = name
        reset
        verb.casecmp?("HELO") ? reply(250, "#{server_name} greets #{name}") : ehlo(name)
      end

      # Counts toward the session's error budget; past it the peer gets one
      # final reply and the connection drops (the run loop's rescue).
      def error_reply(code, message)
        @protocol_errors += 1
        if @protocol_errors >= MAX_PROTOCOL_ERRORS
          reply code, "Too many syntax or protocol errors"
          raise IOError, "protocol error abuse"
        end
        reply code, message
      end

      # spec[:hostname] may be a callable (the Rails host passes one so a
      # Settings-page change reaches new connections without a restart);
      # resolved once per session, before the banner.
      def server_name
        return @server_name if defined?(@server_name)

        name = @spec[:hostname]
        name = name.call if name.respond_to?(:call)
        @server_name = name || "mail_on_rails"
      end

      # Overridable via spec so tests can exercise size handling without
      # shoveling 25 MB through a loopback socket.
      def max_message_bytes
        @spec[:max_message_bytes] || MAX_MESSAGE_BYTES
      end

      # Same seam for the per-session message cap.
      def max_messages_per_session
        @spec[:max_messages] || MAX_MESSAGES_PER_SESSION
      end

      # And for the command-read timeout.
      def read_timeout
        @spec[:timeout] || 300
      end

      def ehlo(arg)
        extensions = [ "#{server_name} greets #{arg}", "SIZE #{max_message_bytes}", "8BITMIME", "PIPELINING" ]
        extensions << "STARTTLS" if @tls_ctx && !@tls
        extensions << "AUTH PLAIN LOGIN" if auth_offered?
        multi 250, extensions
      end

      # AUTH is only offered over an encrypted channel - never send
      # credentials in the clear.
      def auth_offered?
        @tls
      end

      def starttls(arg)
        # RFC 3207: STARTTLS takes no parameter.
        return error_reply 501, "Syntax error (no parameters allowed)" if arg
        return error_reply 503, "TLS already active" if @tls
        return reply 454, "TLS not available" unless @tls_ctx

        reply 220, "Ready to start TLS"
        @socket = Smtp::TLS.accept(io_for(@socket), @tls_ctx)
        @tls = true
        set_timeout(read_timeout)
        # RFC 3207: discard all state learned before STARTTLS, the
        # pre-handshake HELO included.
        @helo_name = nil
        reset
      rescue OpenSSL::SSL::SSLError => e
        @store.log(:error, "SMTP STARTTLS failed: #{e.message}")
        raise IOError, "TLS handshake failed"
      end

      # -- authentication ----------------------------------------------------

      def auth(arg)
        return reply 538, "Encryption required for authentication" unless @tls
        return error_reply 503, "Already authenticated" if @authenticated_as
        # RFC 4954: AUTH is illegal once a mail transaction is open.
        return error_reply 503, "AUTH not permitted in mail transaction" if @mail_from

        mechanism, initial = arg.to_s.split(" ", 2)
        case mechanism&.upcase
        when "PLAIN"
          initial ? auth_plain(initial) : challenge("") { |response| auth_plain(response) }
        when "LOGIN"
          if initial
            challenge("UGFzc3dvcmQ6") { |pass| verify_credentials(decode64(initial), decode64(pass)) }
          else
            challenge("VXNlcm5hbWU6") do |user|
              challenge("UGFzc3dvcmQ6") { |pass| verify_credentials(decode64(user), decode64(pass)) }
            end
          end
        else
          error_reply 504, "Unrecognized authentication type"
        end
      end

      def auth_plain(response)
        _authzid, user, pass = (decode_sasl_plain(response) rescue [])
        verify_credentials(user, pass)
      end

      # RFC 4954 challenge: send 334 and hand the client's next line to the
      # block. A lone "*" cancels the exchange (uniformly, for every prompt).
      # The response is a credential, so the trace gets a placeholder.
      def challenge(prompt, &handler)
        reply 334, prompt
        @continuation = proc do |chunk|
          @continuation = nil
          line = line_from(chunk)
          trace "<= #{line == "*" ? line : LOG_REDACTION}"
          line == "*" ? reply(501, "Cancelled") : handler.call(line)
        end
        nil
      end

      def decode64(str)
        str.to_s.unpack1("m0").to_s
      rescue ArgumentError
        ""
      end

      def verify_credentials(user, pass)
        result = @store.authenticate(user.to_s, pass.to_s, ip: peer_ip)
        if result[:account_id]
          @authenticated_as = result[:email]
          @store.log(:info, "SMTP auth success for #{@authenticated_as} (#{peer_ip})")
          reply 235, "Authentication successful"
        elsif result[:throttled]
          # The store refused to adjudicate (brute-force throttle): RFC
          # 4954's 454, so a legitimate client with a stale password backs
          # off and retries instead of treating its password as wrong. Not
          # counted as a failure anywhere - the throttle already has this
          # peer blocked.
          @store.log(:warn, "SMTP auth throttled for #{user.to_s.empty? ? "(empty)" : user} (#{peer_ip})")
          reply 454, "Temporary authentication failure, try again later"
        else
          @auth_attempts += 1
          @on_auth_failure&.call # recorded before the reply so the throttle can't lag the client
          @store.log(:warn, "SMTP auth failed for #{user.to_s.empty? ? "(empty)" : user} (#{peer_ip}, attempt #{@auth_attempts}/#{MAX_AUTH_ATTEMPTS})")
          if @auth_attempts >= MAX_AUTH_ATTEMPTS
            reply 421, "Too many failed authentication attempts"
            raise IOError, "auth abuse"
          end
          reply 535, "Authentication credentials invalid"
        end
      end

      # -- envelope ----------------------------------------------------------

      def mail_from(arg)
        return error_reply 503, "Sender already given" if @mail_from
        if @spec[:role] == :submission && !@authenticated_as
          return reply 530, "Authentication required"
        end

        unless arg =~ /\AFROM:\s*<([^>]*)>\s*(.*)\z/im
          return error_reply 501, "Syntax: MAIL FROM:<address>"
        end

        from = Regexp.last_match(1)
        return unless accept_mail_parameters(Regexp.last_match(2))

        if (zone = rbl_listing)
          @store.log(:info, "SMTP rejected MAIL FROM:<#{from}> from #{peer_ip}: listed by DNSBL #{zone}")
          return reply 554, "5.7.1 Service unavailable; #{peer_ip} is listed by #{zone}"
        end

        if @authenticated_as && !from.strip.casecmp?(@authenticated_as)
          return reply 550, "Sender address must match authenticated account"
        end

        @mail_from = from
        @rcpt_to = []
        reply 250, "OK"
      end

      # ESMTP MAIL parameters (RFC 5321 4.1.1.2). We advertise SIZE and
      # 8BITMIME, so honor them: an oversize SIZE declaration is refused
      # before the client wastes the transfer (RFC 1870), BODY must be a
      # value we advertised, and AUTH= (RFC 4954) is accepted and ignored -
      # the session's own AUTH is the only identity we trust. Anything
      # else was never advertised, so it earns RFC 5321's 555. Replies and
      # returns false on rejection.
      def accept_mail_parameters(params)
        params.to_s.split(/\s+/).each do |param|
          key, value = param.split("=", 2)
          case key.upcase
          when "SIZE"
            unless value.to_s.match?(/\A\d+\z/)
              error_reply 501, "Invalid SIZE value"
              return false
            end
            if value.to_i > max_message_bytes
              reply 552, "Message size exceeds maximum permitted"
              return false
            end
          when "BODY"
            unless value.to_s.match?(/\A(7BIT|8BITMIME)\z/i)
              error_reply 501, "Invalid BODY value"
              return false
            end
          when "AUTH" # accepted, ignored
          else
            error_reply 555, "MAIL parameter not recognized"
            return false
          end
        end
        true
      end

      def rcpt_to(arg)
        return error_reply 503, "Need MAIL command first" unless @mail_from
        return reply 452, "Too many recipients" if @rcpt_to.size >= MAX_RECIPIENTS

        unless arg =~ /\ATO:\s*<([^>]+)>\s*(.*)\z/im
          return error_reply 501, "Syntax: RCPT TO:<address>"
        end

        # No RCPT extension (DSN etc.) is advertised, so no parameter is
        # legal here.
        unless Regexp.last_match(2).to_s.strip.empty?
          return error_reply 555, "RCPT parameter not recognized"
        end

        recipient = Regexp.last_match(1)
        # Local recipients (accounts and aliases) are accepted everywhere.
        # Remote recipients are accepted only from authenticated submission
        # (queued for outbound delivery) - the MX port stays local-only, so
        # we never open relay. A miss splits two ways: an unknown user in
        # a domain we host is a 5.1.1, anything else is refused as
        # relaying.
        lookup = @store.local_rcpts([ recipient ])
        unless Array(lookup[:local]).any? || relay_allowed?(recipient)
          @store.log(:info, "SMTP rejected recipient <#{recipient}> from <#{@mail_from}> (#{@spec[:role]}, #{peer_ip})")
          if Array(lookup[:unknown_in_local_domain]).any?
            return reply 550, "5.1.1 No such user here"
          end

          return reply 550, "5.7.1 Relaying denied"
        end

        @rcpt_to << recipient
        reply 250, "OK"
      end

      def relay_allowed?(address)
        @spec[:role] == :submission && @authenticated_as &&
          address.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
      end

      # -- data --------------------------------------------------------------

      def data
        return error_reply 503, "Need RCPT command first" if @rcpt_to.empty?
        if @message_count >= max_messages_per_session
          return reply 421, "Too many messages this session"
        end

        reply 354, "End data with <CR><LF>.<CR><LF>"
        @continuation = data_continuation
      end

      # Consumes the DATA payload one chunk at a time through the
      # terminating <CRLF>.<CRLF>. Chunks are MAX_LINE-capped, so a peer
      # that never sends CRLF cannot grow a single read without bound, and
      # line boundaries are tracked across chunk splits so the terminator
      # and dot-unstuffing apply only at true line starts - a bare-LF "."
      # line never ends DATA (SMTP smuggling).
      #
      # Over max_message_bytes the payload is discarded but still consumed
      # to stay in sync, then answered 552 at the terminator; past twice
      # the limit we stop reading mid-message, so the connection must drop
      # (:quit). A disconnect mid-payload just ends the run loop with the
      # continuation still installed - the partial body is never stored.
      def data_continuation
        body = +"".b
        consumed = 0
        line_start = true    # next chunk begins a fresh line
        dangling_cr = false  # previous chunk was cut just after a "\r"
        proc do |chunk|
          if dangling_cr && chunk.start_with?("\n")
            # A CRLF split across the chunk cap: this LF completes the line.
            consumed += 1
            body << "\n" if consumed <= max_message_bytes
            chunk = chunk[1..]
            line_start = true
            dangling_cr = false
            next if chunk.empty?
          end
          if line_start
            if chunk == ".\r\n"
              @continuation = nil
              next finish_data(consumed > max_message_bytes ? :overflow : body)
            end
            chunk = chunk[1..] if chunk.start_with?(".") # undo dot-stuffing
          end
          line_start = chunk.end_with?("\r\n")
          dangling_cr = !line_start && chunk.end_with?("\r")
          consumed += chunk.bytesize
          if consumed > max_message_bytes * 2
            @store.log(:warn, "SMTP message from <#{@mail_from}> refused: exceeds #{max_message_bytes} bytes (#{peer_ip})")
            reply 552, "Message exceeds maximum size"
            next :quit # peer kept flooding past the size limit
          end
          body << chunk if consumed <= max_message_bytes
          nil
        end
      end

      def finish_data(body)
        unless body.is_a?(String) # :overflow
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: exceeds #{max_message_bytes} bytes (#{peer_ip})")
          reply 552, "Message exceeds maximum size"
          reset
          return
        end

        if received_loop?(body)
          @store.log(:warn, "SMTP rejected message from <#{@mail_from}>: mail loop detected (#{peer_ip})")
          reply 550, "Loop detected"
          reset
          return
        end

        auth_results = nil
        if @spec[:role] == :mx && !@authenticated_as && sender_auth?
          verdict = verify_sender(body)
          auth_results = verdict&.summary
          if verdict&.dmarc_reject?
            if Smtp::SenderAuth.enforce_dmarc?
              @store.log(:info, "SMTP rejected message from <#{@mail_from}>: DMARC policy (#{auth_results}, #{peer_ip})")
              reply 550, "5.7.1 Rejected per DMARC policy of #{verdict.from_domain}"
              reset
              return
            end
            @store.log(:info, "SMTP would reject message from <#{@mail_from}> under DMARC enforcement (#{auth_results}, #{peer_ip})")
          end
        end

        # Our own trace header, prepended after the loop check (so we count
        # only prior hops) and before storage - RFC 5321 wants every
        # receiving host to stamp one, and it's what makes the loop guard
        # meaningful for the next hop.
        body = received_header + body

        # Virus scan after the cheap rejects (loop/DMARC) so refused mail
        # never costs a clamd round-trip. Policy: infected -> hard 550 plus a
        # stamped review copy quarantined app-side; scanner unreachable ->
        # 451 so the sending MTA retries (nothing skips scanning), also
        # quarantining an "unscanned" copy for review (deduped app-side by
        # Message-ID across those retries). The quarantine store result never
        # changes the reply - the verdict alone decided it.
        scan = scan_message(body)
        if scan&.infected?
          @store.log(:warn, "SMTP rejected message from <#{@mail_from}>: virus #{scan.virus} (#{peer_ip})")
          @store.quarantine(@mail_from, @rcpt_to, body, @authenticated_as,
                            client_ip: peer_ip, helo: @helo_name,
                            auth_results: auth_results, scan_status: "infected", virus: scan.virus)
          reply 550, "5.7.1 Message rejected: virus detected (#{scan.virus})"
          reset
          return
        elsif scan&.unavailable?
          @store.log(:error, "SMTP tempfail for message from <#{@mail_from}>: virus scanner unavailable (#{peer_ip})")
          @store.quarantine(@mail_from, @rcpt_to, body, @authenticated_as,
                            client_ip: peer_ip, helo: @helo_name,
                            auth_results: auth_results, scan_status: "unscanned")
          reply 451, "4.7.1 Virus scanner unavailable, try again later"
          reset
          return
        end

        result = @store.smtp_store(@mail_from, @rcpt_to, body, @authenticated_as,
                                   client_ip: peer_ip, helo: @helo_name,
                                   auth_results: auth_results, scan_status: scan && "clean")
        if result[:code] == :insufficient_storage
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: insufficient storage (#{peer_ip})")
          reply 452, "Insufficient system storage, try later"
        elsif result[:code] == :relay_denied
          @store.log(:warn, "SMTP message from <#{@mail_from}> refused: relay denied (#{peer_ip})")
          reply 550, "Relaying denied"
        elsif result[:error]
          reply 451, "Requested action aborted: local error"
        else
          @message_count += 1
          auth_note = @authenticated_as ? ", auth #{@authenticated_as}" : ""
          @store.log(:info, "SMTP accepted message #{result[:id]} from <#{@mail_from}> to #{recipient_summary} " \
                            "(#{body.bytesize} bytes, #{@spec[:role]}#{auth_note}, #{peer_ip})")
          reply 250, "OK: queued as #{result[:id]}"
        end
        reset
      end

      # SPF/DKIM/DMARC switch: per-listener spec[:sender_auth] wins (the
      # test seam - worker Ractors cannot read ENV at runtime), else the
      # load-time SMTP_SENDER_AUTH default.
      def sender_auth?
        @spec.fetch(:sender_auth) { Smtp::SenderAuth.enabled? }
      end

      # SPF/DKIM/DMARC for unauthenticated MX mail. DNS-heavy but bounded
      # (per-query timeouts, SPF lookup limits, capped DKIM signatures);
      # runs on this session's thread. Never lets a verifier bug take the
      # session down - verification failure just means no verdict.
      def verify_sender(body)
        Smtp::SenderAuth.verify(ip: peer_ip, helo: @helo_name, mail_from: @mail_from, data: body)
      rescue StandardError => e
        @store.log(:error, "SMTP sender verification error: #{e.class}: #{e.message}")
        nil
      end

      # DNSBL verdict for this peer: the configured zone that lists it, or
      # nil. Checked only for unauthenticated MX traffic - authenticated
      # clients vouch for themselves - and at MAIL FROM rather than at
      # connect, so a legitimate sender stuck on a listed IP can still
      # STARTTLS + AUTH its way in. spec[:dnsbl] is the test seam (worker
      # Ractors cannot read ENV at runtime; the default checker's zones are
      # parsed at load, its verdict cache shared per worker thread). Never
      # lets a checker bug refuse mail - failure just means no verdict.
      def rbl_listing
        return nil unless @spec[:role] == :mx && !@authenticated_as

        checker = @spec.fetch(:dnsbl) { Smtp::Dnsbl.shared }
        checker&.listed(peer_ip)
      rescue StandardError => e
        @store.log(:error, "SMTP DNSBL check error: #{e.class}: #{e.message}")
        nil
      end

      # ClamAV verdict for the message body, nil when scanning is disabled
      # (no clamd address configured). Per-listener spec keys override the
      # env-derived defaults, mirroring max_message_bytes - and doubling as
      # the test seam, since worker Ractors cannot read ENV at runtime.
      def scan_message(body)
        addr = @spec.fetch(:clamav_addr, Smtp::ClamavClient::ADDR).to_s
        return nil if addr.empty?

        timeout = @spec[:clamav_timeout] || Smtp::ClamavClient::TIMEOUT
        Smtp::ClamavClient.new(addr: addr, timeout: timeout).scan(body)
      end

      def recipient_summary
        shown = @rcpt_to.first(3).map { |r| "<#{r}>" }.join(" ")
        @rcpt_to.size > 3 ? "#{shown} +#{@rcpt_to.size - 3} more" : shown
      end

      # Our RFC 5321 §4.4 trace header. The WITH protocol keyword follows
      # RFC 3848: ESMTP, +S when the channel is TLS, +A when the client
      # authenticated.
      def received_header
        with = +"ESMTP"
        with << "S" if @tls
        with << "A" if @authenticated_as
        helo = @helo_name.to_s.empty? ? "unknown" : sanitize_reply(@helo_name)
        "Received: from #{helo} ([#{peer_ip}])\r\n" \
        "\tby #{server_name} with #{with}; #{Time.now.rfc2822}\r\n"
      end

      # Postal-style mail loop detection: a message whose headers show it
      # already passed through this host more than MAX_RECEIVED_HOPS times
      # is looping between forwarders.
      def received_loop?(body)
        header_section = body.split("\r\n\r\n", 2).first.to_s
        hostname = server_name.downcase
        hops = header_section.split(/\r\n(?![ \t])/).count do |header|
          header.match?(/\AReceived:/i) && header.downcase.include?(hostname)
        end
        hops > MAX_RECEIVED_HOPS
      end

      # -- replies -----------------------------------------------------------
      #
      # Reply text can echo client input (EHLO/HELO arguments); embedded
      # CR/LF or control bytes there would inject raw line breaks into our
      # replies, so everything unprintable is flattened before the wire.

      def reply(code, text)
        text = sanitize_reply(text)
        trace "=> #{code} #{text}"
        @socket.write("#{code} #{text}\r\n")
      end

      def multi(code, lines)
        lines.each_with_index do |text, i|
          text = sanitize_reply(text)
          separator = i == lines.length - 1 ? " " : "-"
          trace "=> #{code}#{separator}#{text}"
          @socket.write("#{code}#{separator}#{text}\r\n")
        end
      end

      def sanitize_reply(text)
        text.to_s.gsub(/[^[:print:]]/, " ")
      end
    end
  end
end
