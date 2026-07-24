# mail_on_rails

A from-scratch mail server built around a Rails app: SMTP (MX + authenticated
submission), IMAP, and a web UI, with mail stored in PostgreSQL.

## Architecture

The mail edges live in sibling repos and deploy as their own Kamal
services:

- **[mail_on_rails_exim](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_exim)**
  — the SMTP edge: an [Exim](https://www.exim.org/) MTA (MX + authenticated
  submission on 25/587/465) with STARTTLS/AUTH and DoS caps. It terminates
  SMTP and hands mail to this app over HTTP — it holds no Rails code, no
  database, and no master key. It does no scanning or SPF/DKIM/DMARC of its
  own; it forwards the connection facts and this app runs those checks.
- **[mail_on_rails_imap](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap)**
  — the IMAP server.

This app is the persistence and UI side. It exposes the Action Mailbox
relay ingress and the private internal API the edges talk to, stores mail
in Postgres, and serves the web UI. The IMAP daemon speaks to a **store**
(interface in `docs/store_contract.md`); the exim edge uses no store and
POSTs straight to the ingress + internal API (its HTTP contract is in the
same doc, authoritative details in the exim repo). Inbound messages carry
verified/unverified badges in the UI.

In development the IMAP daemon is a path dependency (the `:daemons` Gemfile
group) and runs in-process on a background thread via the `:mail_on_rails`
Puma plugin, so `bin/dev` brings up web + IMAP in one process. The SMTP
edge is a Docker/Exim service and runs on its own (see the exim repo).

## Running the test suite

    bin/rails test

The suite includes the IMAP gem's store-contract tests, run against this
app's Active Record and HTTP implementations. When the sibling path gem
isn't installed (e.g. CI sets `BUNDLE_WITHOUT=daemons`), those tests skip
with a note. Each edge repo also carries its own Rails-free suite
(`bin/test`).

Virus-scanning tests run against a scripted fake clamd, so no ClamAV
install is needed; the real-engine EICAR smoke procedure and the scanning
policy live in [docs/virus_scanning.md](docs/virus_scanning.md).

## Roadmap

Planned work, tracked here across the app and the edge repos.

### [mail_on_rails_exim](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_exim)

Edge-level hardening (connection/volume caps, per-IP recipient and AUTH
throttles, TLS floor, RBL/DNSBL) lives in the exim service and is tuned in
its `config/exim4.conf.template` — see that repo's README. Exim replaces
the retired Ruby SMTP daemon, so its own equivalents supersede the DNS /
parser / connection-limiter work that used to be tracked here.

### mail_on_rails (this app)

- [ ] **Spam-action routing** — the mailroom already gets an rspamd spam
  action/score per message (currently logged only); act on it, e.g. file a
  spam verdict into a Junk mailbox instead of INBOX.
- [ ] **DMARC enforcement** — the app computes DMARC via rspamd and badges
  the result; go further and reject or quarantine on failure (behind a
  flag, log-only first) rather than only badging.
- [ ] **Rate limiting beyond auth endpoints** — Rails-native
  `rate_limit` covers login/password-reset only; consider coverage for
  the internal API endpoints the edges call.

Already in place (not TODO): PostgreSQL-backed queuing (Solid Queue plus
the `smtp_outbound_messages` retry/backoff table), app-side SPF/DKIM/DMARC
of inbound mail (rspamd) and virus scanning (ClamAV), and outbound DKIM
signing.
