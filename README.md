# mail_on_rails

A from-scratch mail server built around a Rails app: SMTP (MX + authenticated
submission), IMAP, and a web UI, with mail stored in PostgreSQL.

## Architecture

The protocol daemons live in sibling repos and deploy as their own Kamal
services:

- **[mail_on_rails_smtp](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp)**
  — SMTP listeners (MX, submission, SMTPS) with STARTTLS/AUTH,
  SPF/DKIM/DMARC verification of inbound mail, and DoS caps.
  Sender-verification behavior (DMARC enforcement, DNS fail-open caveats)
  is documented in that repo's README.
- **[mail_on_rails_imap](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap)**
  — the IMAP server.

This app is the persistence and UI side. It exposes the private internal
API and Action Mailbox ingress the daemons talk to (the store contract is
specified in `docs/store_contract.md`), stores mail in Postgres, and
serves the web UI. Inbound messages carry the SMTP daemon's verification
verdict as verified/unverified badges in the UI.

In development the daemons are path dependencies (the `:daemons` Gemfile
group) and run in-process on background threads via the `:mail_on_rails`
Puma plugin, so `bin/dev` brings up the full stack — web, SMTP, and IMAP —
in one process.

## Running the test suite

    bin/rails test

The suite includes the daemon gems' store-contract tests, run against
this app's Active Record and HTTP implementations. When the sibling path
gems aren't installed (e.g. CI sets `BUNDLE_WITHOUT=daemons`), those
tests skip with a note. Each daemon repo also carries its own Rails-free
suite (`bin/test`).

Virus-scanning tests run against a scripted fake clamd, so no ClamAV
install is needed; the real-engine EICAR smoke procedure and the scanning
policy live in [docs/virus_scanning.md](docs/virus_scanning.md).

## Roadmap

Planned work, tracked here across the app and the daemon repos.

### [mail_on_rails_smtp](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp)

- [ ] **RBL/DNSBL checks** — on the MX listener only (not authenticated
  submission), reverse the peer IP and query a configurable zone list
  (`SMTP_RBLS`, e.g. `zen.spamhaus.org`); reject listed IPs with
  `554 5.7.1`. Cache verdicts by IP with a TTL; fail open on DNS timeout.
- [ ] **Per-IP rate limiting** — extend the `ConnLimiter` pattern with a
  per-IP table: concurrent-connection cap, sliding-window connection
  rate, and auth-failure tracking with temporary bans and an escalating
  tarpit delay. Thresholds via env vars like the existing global caps.
- [ ] **Async DNS lookups** — sender-auth DNS is blocking `Resolv::DNS`
  on the session thread. Near-term: a direct-UDP resolver that can
  distinguish NXDOMAIN/SERVFAIL/timeout (today DNS fails open), running
  the independent SPF/DKIM/DMARC lookups concurrently, with a short-TTL
  cache. Long-term: move the server to the Ruby 3 fiber scheduler
  (`async` gem), which makes `Resolv` and socket IO non-blocking.
- [ ] **Allocation-light ("zero-copy") command parser** — replace the
  `gets`/`chomp`/`split`/regex hot path with a reusable binary read
  buffer, byte-offset line tracking, frozen-constant verb dispatch, and
  one-pass DATA dot-unstuffing. Benchmark first; pair with the fiber
  scheduler refactor, which needs a buffer-oriented reader anyway.
- [ ] **DMARC enforcement default** — enforcement exists behind
  `SMTP_DMARC_ENFORCE` but is off by default (log-only); flip
  it on once the verifiers have proven themselves against real traffic.

### mail_on_rails (this app)

- [ ] **Rate limiting beyond auth endpoints** — Rails-native
  `rate_limit` covers login/password-reset only; consider coverage for
  the internal API endpoints the daemons call.

Already in place (not TODO): PostgreSQL-backed queuing (Solid Queue plus
the `smtp_outbound_messages` retry/backoff table), SPF/DKIM/DMARC
verification of inbound mail, and outbound DKIM signing.
