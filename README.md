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

## Securing /metrics

The Prometheus endpoint is bearer-token gated (`METRICS_TOKEN`; when the
variable is unset the route answers 404). The token alone shouldn't be
the only wall: kamal-proxy has no per-path ACLs, so either scrape over a
private network/VPN or restrict the HTTPS port to the scraper's address
at the droplet/cloud-firewall layer. Rotate `METRICS_TOKEN`
periodically — update the deploy secret and the scraper config, then
redeploy.

## Roadmap

Web UI, roughly by value:

- [ ] **Roles / authorization (RBAC)** — every signed-in user is a full
  admin today (deliberate for a single-operator deployment, flagged in
  the 2026-08 security audit). Introduce roles (operator / mail admin /
  read-only), scope email-account access per user, and gate destructive
  actions (domain delete, user delete, DNS publish) behind the elevated
  role.
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

- [ ] **Vacation responder backscatter (RFC 3834 §4)** — the auto-reply is
  addressed from the `Reply-To`/`From` headers
  (`VacationResponder#reply_address`), which any unauthenticated sender
  sets freely. `bounce?` does validate the *envelope* return path, but
  that address is never used as the destination and the two are never
  compared — so a stranger can make a vacationing account send mail to a
  third party who never contacted us. Because the reply is queued with
  `mail_from: account.email`, `OutboundDeliverer#signed` DKIM-signs it
  under our domain and it leaves our IP: fully DMARC-aligned backscatter
  that reaches the victim's inbox rather than their spam folder, with the
  reputation damage landing on us.

  The per-correspondent window does not bound this. `VacationReply.claim`
  stores the address verbatim into a case-sensitive unique index, so
  `victim@x.com` and `Victim@x.com` are separate rows, and `+`-tagging
  yields unlimited variants that all reach the same real mailbox — "one
  reply per correspondent per week" is really one reply per *spelling*.
  Fan-out compounds it: the dedup is per-account, so a single message
  addressed to 100 vacationing accounts (`MAX_RECIPIENTS`) yields 100
  replies to the same victim. The only real ceiling today is `SendQuota`
  (~200/hour/account, genuinely shared with submission because
  `SOLID_QUEUE_IN_PUMA` runs the mailroom inside the SMTP process).
  Work, roughly in order of value:

  - address the reply to the validated envelope return path instead of
    `Reply-To`/`From`. This alone removes attacker control of the
    destination and makes the address-variant bypass moot, since the
    return path is the one address the sending MTA must be able to
    receive at;
  - normalize (downcase, optionally strip `+` tags) before
    `VacationReply.claim`, backed by a `citext` column or a functional
    index so the uniqueness constraint means what it reads as;
  - move `claim` after the quota check — today an exhausted quota has
    already written a fresh `last_sent_at`, so a genuine correspondent
    gets no reply *and* is then suppressed for the full seven days;
  - send with a null envelope sender (`MAIL FROM:<>`) as RFC 3834
    requires, so the auto-reply is itself unbounceable and a dead victim
    address stops generating bounces back to the vacationing user;
  - prune `vacation_replies` past the window. Nothing sweeps the table
    today (only `dependent: :delete_all` on account destroy), so an
    attacker cycling addresses grows it without limit.

  The loop protections themselves are sound and should survive the
  rework: null-sender and daemon suppression,
  `Auto-Submitted`/`Precedence`/`X-Auto-Response-Suppress`/`List-*`
  checks, the self-address check, junk and quarantine never earning a
  reply, and local delivery going straight to the inbox so replies can't
  re-enter the mailroom and ping-pong.
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
