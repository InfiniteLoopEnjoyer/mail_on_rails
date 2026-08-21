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
      # +source+ names the auth surface ("imap"/"smtp") for the attempt log;
      # it only affects what gets recorded, never the verdict.
      def authenticate(email, password, ip: nil, source: nil)
        db do
          if (blocked = AuthThrottle.check(ip: ip, email: email))
            next throttled_result(blocked, email, ip, source)
          end

          account = EmailAccount.authenticate_by(email: email.to_s, password: password.to_s)
          if account
            AuthThrottle.clear_account(account.email)
          else
            AuthThrottle.record_failure(ip: ip, email: email)
            log_attempt(email, ip, source, "bad_credentials")
          end
          { account_id: account&.id, email: account&.email, honeypot: account&.honeypot? || false }
        end
      end

      # Counts a failure the store itself did not adjudicate: SCRAM proofs
      # are verified by the daemon against verifier material, so the app
      # only learns of those failures when the daemon reports them.
      def record_auth_failure(email, ip: nil, source: nil)
        db do
          AuthThrottle.record_failure(ip: ip, email: email)
          log_attempt(email, ip, source, "bad_credentials")
          {}
        end
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
      # attacker mid-block would let them grind offline.
      def scram_credentials(email, ip: nil)
        db do
          if (blocked = AuthThrottle.check(ip: ip, email: email))
            next throttled_result(blocked, email, ip)
          end

          account = EmailAccount.find_by(email: email.to_s.strip.downcase)
          next Scram.decoy_credentials(email.to_s.strip.downcase, decoy_secret) unless account&.scram_salt

          {
            account_id: account.id,
            email: account.email,
            salt_base64: account.scram_salt,
            iterations: account.scram_iterations,
            stored_key_base64: account.scram_stored_key,
            server_key_base64: account.scram_server_key,
            honeypot: account.honeypot?
          }
        end
      end

      # The admin ban list (BannedIp) as plain CIDR strings, polled by the
      # accept-side Netserv::Denylist. On a database problem db returns its
      # error hash instead of an array, which the denylist reads as "keep
      # the last good list".
      def banned_cidrs
        db { BannedIp.pluck(:cidr) }
      end

      # Persists one closed connection for the history section of the live
      # connection pages (ClosedConnection). Optional store method: the
      # servers call it behind respond_to?, so stores without it (the
      # vendored memory stores) simply keep no history. +info+ is the
      # plain-values payload Server#report_closed assembles; best-effort
      # end to end - db's rescue plus ClosedConnection.record's own mean a
      # history failure can never disturb a connection teardown.
      def record_closed_connection(info)
        db do
          ClosedConnection.record(info)
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
                          "(#{ip || "no ip"}, #{email}): #{blocked[:retry_after]}s remaining")
        log_attempt(email, ip, source, "throttled")
        { account_id: nil, email: nil, throttled: true, retry_after: blocked[:retry_after] }
      end

      # The attempt log is an audit trail, not part of the verdict, so it is
      # skipped rather than guessed at when the caller named no surface -
      # a row labelled with the wrong source is worse than no row.
      def log_attempt(email, ip, source, outcome)
        return if source.blank?

        AuthAttempt.record(ip: ip, username: email, source: source, outcome: outcome)
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
