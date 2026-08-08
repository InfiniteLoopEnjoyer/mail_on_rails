# mail_on_rails

A from-scratch mail server built around a Rails app: SMTP (MX + authenticated
submission), IMAP, and a web UI, with mail stored in PostgreSQL.

## Architecture

One container runs everything: Puma serves the web UI and Solid Queue,
and the `:mail_on_rails` Puma plugin boots the SMTP server (MX +
authenticated submission) and the IMAP server on background threads in
the same process. Both servers run on shared listener scaffolding
(`lib/mail_on_rails/netserv`) carrying the accept-side protections:
process-wide and per-IP connection caps, a per-IP connection-rate
tarpit, a per-IP lockout after repeated failed authentications, the
admin IP denylist, and fail-closed TLS when explicit cert paths are
configured (`SMTP_*` / `MAIL_ON_RAILS_IMAP_*` env knobs, `0` disables
any of them).

The protocol servers are Rails-free and vendored under
`lib/mail_on_rails/smtp*`, `lib/mail_on_rails/imap` and
`lib/mail_on_rails/netserv`; each speaks to a
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
the only wall: set `METRICS_ALLOW_IPS` (comma-separated IPs/CIDRs) so the
app itself 404s any caller that isn't your scraper, and additionally
scrape over a private network/VPN or restrict the HTTPS port to the
scraper's address at the droplet/cloud-firewall layer (kamal-proxy has no
per-path ACLs). Rotate `METRICS_TOKEN` periodically — update the deploy
secret and the scraper config, then redeploy.

When rspamd is configured, `/metrics` includes `mail_on_rails_rspamd_up`.
Alert on it: authenticated submission **fails open** when rspamd is down
(deliberately — an outage must not block all outbound mail), so
`rspamd_up == 0` combined with climbing outbound volume is the signature
of a compromised account spamming unchecked.

## Multi-user deployments

Until RBAC lands (see roadmap), every signed-in user is a full admin, so
each account's login is the whole system's perimeter. For any deployment
with more than one user, set `MAIL_ON_RAILS_REQUIRE_2FA=1`: users
without a second factor are parked on 2FA enrollment (authenticator app
or passkey) and can't reach anything else until one is registered.

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

- [ ] **ARC chain validation (RFC 8617)** — `ArcSealer` can seal a
  message as instance 1 (`cv=none`) with the domain's DKIM key, but
  nothing forwards mail today, so it is unwired groundwork for the
  filing-rules roadmap item's forward action. Extending an *existing*
  chain honestly (`cv=pass`, instance N+1) additionally needs an ARC
  chain validator, which does not exist yet.
- [ ] **DANE-TA name checks against TLSA base domain aliases** — DANE
  verification implements both usable usages (DANE-EE(3) ignoring
  name/expiry per RFC 7671 §5.1, DANE-TA(2) with chain, name and
  validity checks), but only matches the MX hostname itself, not the
  full RFC 7672 §3.2.3 candidate-name set (CNAME-expanded names,
  next-hop domain). Rarely load-bearing; noted for completeness.

Operations:

- [ ] **Offsite backups** — nightly `pg_dump` lands on the persistent
  volume; getting copies off the machine is still a manual runbook
  ([docs/backups.md](docs/backups.md)), not an automated push.

Already in place (not TODO): PostgreSQL-backed queuing (Solid Queue plus
the `smtp_outbound_messages` retry/backoff table), **verified outbound
TLS** — DANE (RFC 7672: DNSSEC-secure TLSA records make TLS mandatory
and pin the certificate chain, no cleartext fallback; needs a
DNSSEC-validating resolver, `MAIL_ON_RAILS_DANE=0` disables) and MTA-STS
(RFC 8461: recipient policies are fetched, cached for their `max_age`,
and in enforce mode restrict delivery to policy-matched MX hosts over
WebPKI-verified TLS; `MAIL_ON_RAILS_MTA_STS=0` disables), with every
attempt's TLS outcome recorded and **TLS-RPT reports** (RFC 8460) mailed
daily to recipient domains that publish a `_smtp._tls` rua (we also
still ingest reports for our own domains at `tls-rpt@`), the
**RFC 3834-hardened vacation responder** (replies go to the validated
envelope return path with a null envelope sender, claim keys are
case/`+tag`-normalized, quota-exhausted attempts don't burn the
correspondent's weekly slot, and the claim table is pruned daily),
SPF/DKIM/DMARC
verification of inbound mail (rspamd) and virus scanning (ClamAV,
consulted at SMTP DATA time so infected mail is rejected before
acceptance; authenticated writes that fail open during a scanner outage
are swept hourly by `RescanUnscannedMessagesJob` until every `unscanned`
row has a real verdict), **IMAP/SMTP accept-side parity** (per-IP
connection caps, connection-rate tarpit and auth lockout on both
protocols, from the shared `netserv` scaffolding), a **configurable
published MTA-STS mode** (`MAIL_ON_RAILS_MTA_STS_MODE`, `testing` by
default — flip to `enforce` once TLS-RPT comes back clean and the policy
id self-bumps on the next DNS publish), **spam-action routing** (rspamd-flagged mail is filed into
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
