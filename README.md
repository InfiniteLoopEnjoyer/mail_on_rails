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

Web UI, roughly by value:

- [ ] **Per-account server-side filing rules** — inbound filtering is
  global only (rspamd, DMARC); no per-user "file sender X into folder Y"
  (Sieve or a simpler home-grown rule table acted on in the mailroom).
- [ ] **Attachments on draft autosave** — composer file attachments travel
  with the send only; drafts persist the body (including rich HTML) but
  not the attached files, so a draft opened on another device loses them.
- [ ] **Inline images in the composer** — Lexxy's editor attachments are
  disabled; files go through the plain MIME attachment input. Pasting or
  uploading images as `cid:` parts in the HTML body is not supported.
- [ ] **Web Push for new mail** — the PWA service worker skeleton exists
  but is unused; clients must poll / IMAP IDLE.
- [ ] **Substring / prefix full-text search** — FTS matches whole words
  (the Dovecot trade-off — documented in `docs/store_contract.md`);
  queries the index can't express, and stores without `search_text`,
  keep the RFC-exact substring scan.

Protocol/delivery:

- [ ] **DANE for outbound (RFC 7672)** — outbound TLS is opportunistic
  and unverified; TLSA validation (and honoring recipient MTA-STS
  policies, which we publish but don't check when sending) would close
  the active-MITM gap on delivery.
- [ ] **TLS-RPT sending** — we ingest reports at `tls-rpt@` but never
  generate reports about our own inbound TLS failures.
- [ ] **ARC sealing (RFC 8617)** — forwarded/relayed mail carries no
  chain of custody.

Operations:

- [ ] **Offsite backups** — nightly `pg_dump` lands on the persistent
  volume; getting copies off the machine is still a manual runbook
  ([docs/backups.md](docs/backups.md)), not an automated push.

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
