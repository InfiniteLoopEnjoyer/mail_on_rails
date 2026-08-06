# mail_on_rails

A from-scratch mail server built around a Rails app: SMTP (MX + authenticated
submission), IMAP, and a web UI, with mail stored in PostgreSQL.

## Architecture

One container runs everything: Puma serves the web UI and Solid Queue,
and the `:mail_on_rails` Puma plugin boots the SMTP server (MX +
authenticated submission, STARTTLS/implicit TLS, AUTH, DoS caps) and the
IMAP server on background threads in the same process.

The protocol servers are Rails-free and vendored under
`lib/mail_on_rails/smtp*` and `lib/mail_on_rails/imap`; each speaks to a
**store** (interface in `docs/store_contract.md`) whose Active
Record-backed implementations are this app's. Inbound mail is
SPF/DKIM/DMARC-verified and virus-scanned at SMTP DATA time (infected →
550 before acceptance, scanner down → 451, fail closed), then routed
through Action Mailbox; messages carry verified/unverified badges in the
UI. Hosted domains are managed live from the Domains admin UI — no
restart to add or remove one.

In development `bin/dev` brings up web + SMTP + IMAP in one process. A
dev-only Puma plugin (`:clamav_dev`) keeps a local `clamav-dev` docker
container running so virus scanning works too — with no docker it logs a
note and leaves scanning off.

## Running the test suite

    bin/rails test

The suite includes the protocol servers' store-contract tests, run
against this app's Active Record implementations. The vendored servers'
own Rails-free suites run with `bin/rails test:smtp_server` and
`bin/rails test:imap_server` (CI runs both).

Virus-scanning tests run against a scripted fake clamd, so no ClamAV
install is needed; the real-engine EICAR smoke procedure and the scanning
policy live in [docs/virus_scanning.md](docs/virus_scanning.md).

## Roadmap

- [ ] **DMARC enforcement (inbound)** — the app computes DMARC via rspamd
  and badges the result; go further and reject or quarantine on failure
  (behind a flag, log-only first) rather than only badging. (Distinct from
  the outbound-side DMARC *monitoring* already in place — see below.)
- [ ] **Web composer outbound abuse gates** — SMTP submission has a
  per-account send quota (`Smtp::SendQuota`, RCPT-time 452) and an rspamd
  spam gate at DATA, the tripwires for a stolen SMTP password. The web
  composer bypasses both: `ComposedEmail#deliver` queues
  `SmtpOutboundMessage` rows directly, so a stolen *web* password can pump
  outbound mail unmetered. Count composer recipients against the same
  `SendQuota.shared` budget and score the built message with
  `RspamdAnalyzer` before queueing.
- [ ] **Sanitize `<style>` blocks instead of dropping them** —
  `EmailHtmlSanitizer` prunes `<style>` elements entirely, so newsletters
  that rely on stylesheet rules (rather than inline styles) render
  degraded. Parse the stylesheet with Crass (already a transitive
  dependency via Loofah), keep qualified rules whose declarations pass
  `Loofah::HTML5::Scrub.scrub_css`, recurse into `@media`, drop everything
  else (`@import`, `url()`, unknown at-rules), and re-serialize from the
  Crass AST — never from the raw text. The sandboxed iframe stays the
  second layer regardless.
- [ ] **Pin GitHub Actions to commit SHAs** — `actions/checkout@v7` etc.
  are mutable tags (the tj-actions/changed-files compromise worked by
  retargeting tags). Pin to full SHAs with the version in a trailing
  comment, in all three repos' workflows; Dependabot understands and
  updates SHA pins.
- [ ] **Rate limiting beyond auth** — Rails-native `rate_limit` covers
  login, password reset, and the 2FA challenge; the rest of the web UI is
  unthrottled.
- [ ] **If the composer grows rich-text/HTML sending** — it is immune to
  the email-HTML-injection class today only because it sends text/plain
  exclusively. Before adding an HTML part: build it with a templating
  layer or an editor emitting constrained markup (never string
  concatenation), run the result through `EmailHtmlSanitizer` too, and
  keep the Mail gem's header encoding plus the whitespace-rejecting
  recipient validation.

### Feature gaps (capability scan, 2026-08)

Web UI, roughly by value:

- [ ] **Full-text search** — no search box anywhere; the only search is
  IMAP SEARCH from a mail client. Postgres FTS over subject/from/body
  would cover both the web UI and a faster IMAP SEARCH.
- [ ] **Pagination** — a mailbox page renders every message in the folder
  (no limit clause); large mailboxes will hurt.
- [ ] **Attachments in the composer** — outbound mail is text-only; no
  file input. (Attachment *download* with a ClamAV gate already works.)
- [ ] **Per-account server-side filing rules** — inbound filtering is
  global only (rspamd, DMARC); no per-user "file sender X into folder Y"
  (Sieve or a simpler home-grown rule table acted on in the mailroom).
- [ ] **Vacation autoresponder** — nothing exists.
- [ ] **Message threading** — References/In-Reply-To are extracted but
  unused; the list view is flat. (IMAP THREAD is also unimplemented.)
- [ ] **Storage quotas** — no per-account quota, no enforcement at APPEND
  or SMTP DATA, no usage display; one account can fill the disk. Pairs
  with the IMAP QUOTA (RFC 2087) extension.
- [ ] **.eml download / mbox export** — no way to get a message or
  mailbox out of the system from the UI.
- [ ] **Web Push for new mail** — the PWA service worker skeleton exists
  but is unused; clients must poll / IMAP IDLE.

Protocol/delivery:

- [ ] **IMAP THREAD (RFC 5256)** — SORT is done; THREAD returns NIL.
- [ ] **IMAP QUOTA (RFC 2087)** — see storage quotas above.
- [ ] **DANE for outbound (RFC 7672)** — outbound TLS is opportunistic
  and unverified; TLSA validation (and honoring recipient MTA-STS
  policies, which we publish but don't check when sending) would close
  the active-MITM gap on delivery.
- [ ] **TLS-RPT sending** — we ingest reports at `tls-rpt@` but never
  generate reports about our own inbound TLS failures.
- [ ] **ARC sealing (RFC 8617)** — forwarded/relayed mail carries no
  chain of custody.

Operations:

- [ ] **Backups** — no pg_dump tooling, restore procedure, or runbook in
  the deploy config; the mail store is a single Postgres.
- [ ] **Metrics** — no Prometheus endpoint (kamal-proxy already ships
  one); delivery latency, queue depth, and rejection counts are
  log-only.
- [ ] **Audit log** — admin actions (bans, domain/user changes, settings)
  aren't recorded anywhere queryable.

Already in place (not TODO): PostgreSQL-backed queuing (Solid Queue plus
the `smtp_outbound_messages` retry/backoff table), SPF/DKIM/DMARC
verification of inbound mail (rspamd) and virus scanning (ClamAV,
consulted at SMTP DATA time so infected mail is rejected before
acceptance), **spam-action routing** (rspamd-flagged mail is filed into
Junk instead of INBOX, with mark/unmark spam in the web UI), outbound
DKIM signing plus the SMTP-side abuse tripwires (send quota, rspamd DATA
gate, IP/range bans enforced at every edge), **dynamic domain
management** (the Domains admin UI creates/removes hosted domains live: a
DKIM key is generated per domain, the page shows the DNS records to
publish, and `DnsCheck` verifies MX/SPF/DKIM/DMARC live against public
DNS), two-factor auth (passkeys + TOTP), and **DMARC monitoring**
(aggregate reports mailed to each domain's auto-created `dmarc@` account
are virus-scanned, sender-verified, parsed, and summarized into
per-domain alignment stats with advice on when it is safe to tighten the
published policy).
