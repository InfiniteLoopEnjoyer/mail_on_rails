# frozen_string_literal: true

require "mail_on_rails/scram"

module MailOnRails
  module Store
    # Shared plumbing for the Active Record-backed stores. Ops run inline on
    # the calling connection thread, wrapped in the Rails executor (which
    # checks a connection out of the pool for the op's duration and
    # cooperates with code reloading in development).
    #
    # Every result is a plain value (hashes, arrays, strings, integers) -
    # never an ActiveRecord object - so protocol code stays free of Rails
    # specifics. The full interface spec lives in docs/store_contract.md.
    class Base
      def log(level, message)
        MailOnRails.logger.public_send(level, "[mail_on_rails] #{message}")
        nil
      end

      # Longest login name looked up as an account. SASL hands over
      # client-chosen bytes of any length; past this they name no mailbox
      # (RFC 5321 paths stop at 256) and are only ever counted.
      MAX_LOGIN_LENGTH = 320

      # +ip+ is the mail client's address as the edge saw it, used for
      # brute-force throttling (AuthThrottle). It is optional so an edge
      # that cannot supply one still gets per-account throttling.
      #
      # A throttled attempt returns { throttled: true, retry_after: } and
      # never reaches the bcrypt comparison - the point is to make guessing
      # both futile and cheap to refuse.
      #
      # Returning here also means a refused attempt is not counted, in
      # either scope. That is deliberate in both directions: hammering an
      # already-blocked account must not climb the source's counter (it is
      # one target, nearly always a client retrying a stale password, and
      # escalating to an ip block would take out everyone else behind that
      # address), and a blocked source must not be able to push accounts
      # toward blocks (that would make the throttle a lockout tool). The
      # scopes still trip independently across *different* targets: a
      # blocked account is no shield for an attacker working through
      # others, since each fresh address is adjudicated normally and feeds
      # the ip counter. Pinned in test/models/auth_throttle_test.rb.
      #
      # An account block does not refuse a source that logged in to that
      # account lately (AuthThrottle.known_source?): strangers guessing at
      # an address must not be able to lock its owner out.
      #
      # An attempt that is let through is counted as a failure BEFORE the
      # password is looked at (AuthThrottle.reserve) and given back when it
      # proves right. Parallel guesses therefore each see the others, and
      # nothing that goes wrong after the verdict can leave a wrong guess
      # uncounted.
      # +source+ names the auth surface ("imap"/"smtp") for the attempt log;
      # it only affects what gets recorded, never the verdict.
      def authenticate(email, password, ip: nil, source: nil)
        db do
          name, addressable = login_name(email)
          # The cheap refusal first: a blocked caller costs one indexed
          # read, not the reservation's row locks.
          if (blocked = AuthThrottle.check(ip: ip, email: name, exempt_known_source: true))
            next throttled_result(blocked, name, ip, source)
          end

          blocked, holds = AuthThrottle.reserve(ip: ip, email: name, exempt_known_source: true)
          next throttled_result(blocked, name, ip, source) if blocked

          # A name that had to be cleaned up, or a password bcrypt cannot
          # take (it raises on a NUL), matches no account: a wrong guess,
          # not a store error - an error would be answered as a temporary
          # failure and counted nowhere. (A real store error from here on
          # leaves the reservation standing: unadjudicated, but counted.)
          password = password.to_s
          account = if addressable && !password.include?("\0")
            EmailAccount.authenticate_by(email: name, password: password)
          end
          if account
            bookkeeping("auth success") do
              AuthThrottle.refund(holds)
              AuthThrottle.clear_account(account.email)
            end
          else
            count_failure(name, ip, source, password: password, counted: true)
          end
          { account_id: account&.id, email: account&.email, honeypot: account&.honeypot? || false }
        end
      end

      # Counts a failure the store itself did not adjudicate: SCRAM proofs
      # are verified by the daemon against verifier material, so the app
      # only learns of those failures when the daemon reports them.
      # +reservation+ is what a scram_credentials(reserve: true) call handed
      # out: that exchange is already counted, so it is only logged here.
      def record_auth_failure(email, ip: nil, source: nil, reservation: nil)
        db do
          name, = login_name(email)
          count_failure(name, ip, source, counted: !reservation.nil?)
          {}
        end
      end

      # The other end of a reserved SCRAM exchange: the proof verified, so
      # the failure counted up front is given back and the account's
      # counter cleared, as authenticate does for a right password.
      # Optional store method (only a session that reserves calls it).
      def record_auth_success(email, reservation: nil)
        db do
          AuthThrottle.refund(reservation)
          AuthThrottle.clear_account(email)
          {}
        end
      end

      # Every bad-credentials verdict, whoever adjudicated it: the throttle
      # counter, the attempt log, and - when the operator switched
      # auth_auto_ban on - the permanent ban (BannedIp decides, from the
      # count the throttle just reached). +password+ is the rejected
      # plaintext when this store saw one (nil for SCRAM, where it never
      # sees more than a proof); AuthAttempt decides whether to keep it.
      # +counted+ says the throttle already holds this failure (a
      # reservation), so it must not be counted a second time.
      #
      # Each step stands alone: the verdict is already decided when this
      # runs, and a failing counter or log write must not turn "wrong
      # password" into a store error - the session answers that as a
      # temporary failure and counts it nowhere.
      def count_failure(email, ip, source, password: nil, counted: false)
        bookkeeping("auth failure count") { AuthThrottle.record_failure(ip: ip, email: email) } unless counted
        bookkeeping("auth attempt log") { log_attempt(email, ip, source, "bad_credentials", password: password) }
        bookkeeping("auth auto-ban") { BannedIp.auto_ban_after_failure(ip: ip, email: email, source: source) }
      end

      # SCRAM-SHA-256 verifier material for a daemon-side AUTHENTICATE/AUTH
      # exchange (both mail edges speak SCRAM). For an unknown account (or
      # one whose password predates SCRAM derivation - bcrypt digests can't
      # be converted) it returns deterministic *decoy* material rather than
      # a miss, so the exchange is indistinguishable from a real account
      # and cannot be used as a username oracle; the proof against that
      # material never verifies. A throttled caller is refused all material
      # outright: the salt and iteration count are the only things a SCRAM
      # exchange hands out before the proof, and handing them to an
      # attacker mid-block would let them grind offline. +source+ names
      # the auth surface for the attempt log, as in authenticate; only a
      # throttled refusal is logged here (the verdict itself is the
      # daemon's, reported through record_auth_failure).
      #
      # The account-scope exemption for a known source applies here as in
      # authenticate. +reserve+ is the session's opt-in to counting the
      # exchange up front, as authenticate does (the daemon adjudicates,
      # so the store cannot refund on its own): the result then carries
      # reservation:, which the session hands to record_auth_success when
      # the proof verifies and to record_auth_failure when it does not. An
      # exchange the client abandons stays counted.
      def scram_credentials(email, ip: nil, source: nil, reserve: false)
        db do
          name, addressable = login_name(email)
          if (blocked = AuthThrottle.check(ip: ip, email: name, exempt_known_source: true))
            next throttled_result(blocked, name, ip, source)
          end

          holds = nil
          if reserve
            blocked, holds = AuthThrottle.reserve(ip: ip, email: name, exempt_known_source: true)
            next throttled_result(blocked, name, ip, source) if blocked
          end

          key = AuthThrottle.normalize(name)
          account = EmailAccount.find_by(email: key) if addressable
          material = if account&.scram_salt
            {
              account_id: account.id,
              email: account.email,
              salt_base64: account.scram_salt,
              iterations: account.scram_iterations,
              stored_key_base64: account.scram_stored_key,
              server_key_base64: account.scram_server_key,
              honeypot: account.honeypot?
            }
          else
            Scram.decoy_credentials(key, decoy_secret)
          end
          holds ? material.merge(reservation: holds) : material
        end
      end

      # The admin ban list (BannedIp) as plain CIDR strings, polled by the
      # accept-side Netserv::Denylist. On a database problem db returns its
      # error hash instead of an array, which the denylist reads as "keep
      # the last good list".
      def banned_cidrs
        db { BannedIp.pluck(:cidr) }
      end

      # A cheap fingerprint of that list - row count, newest id, newest
      # write - so the denylist's poll can skip re-reading (and re-parsing)
      # a list that has not changed: with an automatic ban setting on,
      # strangers decide how long it is. Optional store method; anything
      # but an array (db's error hash) reads as "no fingerprint".
      def banned_cidrs_stamp
        db { BannedIp.pick(Arel.sql("COUNT(*)"), Arel.sql("MAX(id)"), Arel.sql("MAX(updated_at)")) }
      end

      # Persists one closed connection for the history section of the live
      # connection pages (ClosedConnection). Optional store method: the
      # servers call it behind respond_to?, so stores without it (the
      # vendored memory stores) simply keep no history. +info+ is the
      # plain-values payload Server#report_closed assembles; best-effort
      # end to end - db's rescue plus ClosedConnection.record's own mean a
      # history failure can never disturb a connection teardown.
      #
      # A connection the server marked idle (info[:idle], no mail work
      # done) is also a strike toward the idle_auto_ban setting - counted
      # from the row just written, so the order matters.
      def record_closed_connection(info)
        db do
          info = info.symbolize_keys
          ClosedConnection.record(info)
          BannedIp.idle_strike(ip: info[:ip], protocol: info[:protocol], reason: info[:idle]) if info[:idle].present?
          {}
        end
      end

      # Records one honeypot hit (HoneypotEvent), returning its id so the
      # session can finalize the transcript at teardown. Optional store method,
      # respond_to?-guarded like record_closed_connection; best-effort end to
      # end (db's rescue plus HoneypotEvent.record's own), so an intel-log
      # failure can never disturb the live session. Creating the row also bans
      # the source IP and enqueues enrichment (see HoneypotEvent).
      def record_honeypot_event(info)
        db { { id: HoneypotEvent.record(info)&.id } }
      end

      # Replaces a honeypot event's transcript with the full post-trigger
      # dialogue, called once at session teardown. update_all skips validations
      # and callbacks (the ban and enrichment already fired on create).
      def update_honeypot_transcript(id, transcript:)
        db do
          HoneypotEvent.where(id: id).update_all(transcript: transcript, updated_at: Time.current)
          {}
        end
      end

      # -- ops state (Netserv::OpsSync) ---------------------------------
      #
      # The daemon projects its live picture into the database so the
      # admin UI works across processes: the listener row is heartbeated
      # every tick; connections and lockouts are replaced only when they
      # changed (nil = unchanged, skip). Optional store methods, all
      # respond_to?-guarded on the caller's side and best-effort (db's
      # rescue) - ops state must never disturb a mail session.

      # +listener+ is the plain hash OpsSync builds (listener_id,
      # protocol, pid, hostname, ports, max_connections, ready,
      # started_at); +connections+ the Server#connections rows (each with
      # connection_id); +lockouts+ { ip => locked_until (Time) }.
      def sync_ops_state(listener:, connections: nil, lockouts: nil)
        db do
          Listener.touch!(listener)
          id = listener[:listener_id]
          OpenConnection.replace_for!(id, listener[:protocol], connections) if connections
          AcceptLockout.replace_for!(id, listener[:protocol], lockouts) if lockouts
          {}
        end
      end

      # Unprocessed, unexpired kick commands for a protocol:
      # [ { id:, ip: }, ... ].
      def pending_kicks(protocol)
        db { ConnectionKick.pending_for(protocol) }
      end

      # Marks a kick processed with how many sessions it dropped.
      def ack_kick(id, kicked:, processed_by: nil)
        db do
          ConnectionKick.acknowledge!(id, kicked: kicked, processed_by: processed_by)
          {}
        end
      end

      # Sweeps listeners (and their rows) that stopped heartbeating
      # +stale_after+ seconds ago. Returns { pruned: n }.
      def prune_stale_listeners(stale_after)
        db { { pruned: Listener.prune_stale!(stale_after) } }
      end

      # Clean shutdown: drop this listener's projection right away rather
      # than waiting for it to go stale.
      def remove_listener(listener_id)
        db do
          Listener.remove!(listener_id)
          {}
        end
      end

      private

      def throttled_result(blocked, email, ip, source = nil)
        MailOnRails.logger.warn("[mail_on_rails] auth throttled by #{blocked[:scope]} " \
                          "(#{ip || "no ip"}, #{loggable_login(email)}): #{blocked[:retry_after]}s remaining")
        bookkeeping("auth attempt log") { log_attempt(email, ip, source, "throttled") }
        { account_id: nil, email: nil, throttled: true, retry_after: blocked[:retry_after] }
      end

      # A client's login name as the store will key, look up and record
      # it, and whether it can name an account at all. SASL bytes arrive
      # raw: invalid UTF-8 or a NUL fails the database round trip outright
      # (PostgreSQL), and an unbounded name does not fit the throttle's
      # index - either would surface as a store error, which is counted
      # nowhere. So the name is made storable and bounded here, once, and
      # one that needed changing is never adjudicated: no account is
      # called that, and the cleaned-up spelling must not match one.
      def login_name(raw)
        raw = raw.to_s
        name = raw.dup.force_encoding(Encoding::UTF_8).scrub("?").gsub(/[[:cntrl:]]/, "?")[0, MAX_LOGIN_LENGTH]
        [ name, name.b == raw.b ]
      end

      # A login name as a log line may carry it: client-chosen, so a CR/LF
      # or control byte in one would forge a line of its own. Printable
      # characters only, bounded, "(empty)" for none - the sessions'
      # loggable_user.
      def loggable_login(name)
        text = name.to_s.dup.force_encoding(Encoding::UTF_8).scrub("?").gsub(/[^[:graph:]]/, "?")[0, 80]
        text.empty? ? "(empty)" : text
      end

      # Runs one piece of after-the-verdict accounting on its own: a
      # failure is logged and swallowed, never raised into the verdict.
      def bookkeeping(what)
        yield
      rescue StandardError => e
        MailOnRails.logger.error("[mail_on_rails] #{what} failed: #{e.class}: #{e.message}")
        nil
      end

      # The attempt log is an audit trail, not part of the verdict, so it is
      # skipped rather than guessed at when the caller named no surface -
      # a row labelled with the wrong source is worse than no row.
      def log_attempt(email, ip, source, outcome, password: nil)
        return if source.blank?

        AuthAttempt.record(ip: ip, username: email, source: source, outcome: outcome, password: password)
      end

      # Per-install secret keying the SCRAM decoy material (see
      # scram_credentials). Derived from the host's secret_key_base so it
      # is stable across restarts and never has to be provisioned; a
      # KeyGenerator purpose keeps it distinct from any other use of that
      # base.
      def decoy_secret
        @decoy_secret ||=
          ActiveSupport::KeyGenerator.new(Rails.application.secret_key_base)
                                     .generate_key("mail_on_rails scram decoy", 32)
      end

      def db
        MailOnRails.app_executor.wrap { yield }
      rescue StandardError => e
        MailOnRails.logger.error("[mail_on_rails] store error: #{e.class}: #{e.message}")
        { error: "#{e.class}: #{e.message}", code: :internal }
      end
    end
  end
end
