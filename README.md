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

- [x] **DMARC enforcement (inbound)** — the app computes DMARC via rspamd
  and badges the result; `MAILROOM_DMARC_ENFORCE` now goes further: mail
  that failed DMARC under the sender domain's own published p=reject or
  p=quarantine is filed into Junk when set to `enforce` (log-only by
  default; `0` disables; p=none failures are never acted on). Complements
  the edge-side `SMTP_DMARC_ENFORCE` 550. (Distinct from the outbound-side
  DMARC *monitoring* also in place — see below.)
- [x] **Web composer outbound abuse gates** — SMTP submission has a
  per-account send quota (`Smtp::SendQuota`, RCPT-time 452) and an rspamd
  spam gate at DATA, the tripwires for a stolen SMTP password. The web
  composer now carries both: `ComposedEmail#deliver` counts each recipient
  against the same `SendQuota.shared` budget (keyed by the account email,
  as at RCPT) and scores the built message with `RspamdAnalyzer` before
  queueing — only rspamd's own refusal actions refuse, and an unreachable
  scorer fails open, mirroring the DATA gate.
- [x] **Sanitize `<style>` blocks instead of dropping them** —
  `EmailCssSanitizer` parses the stylesheet with Crass (already a
  transitive dependency via Loofah), keeps qualified rules whose
  declarations pass `Loofah::HTML5::Scrub.scrub_css`, recurses into
  `@media`, drops everything else (`@import`, `url()`, unknown at-rules),
  and re-serializes from the Crass AST — never from the raw text, and
  never emitting a literal `</` (the `<style>` breakout). Stylesheets are
  collected from head and body and re-emitted as one scrubbed `<style>`
  element. The sandboxed iframe stays the second layer regardless.
- [x] **Pin GitHub Actions to commit SHAs** — `actions/checkout@v7` etc.
  were mutable tags (the tj-actions/changed-files compromise worked by
  retargeting tags). All three repos' workflows now pin full SHAs with the
  version in a trailing comment; Dependabot understands and updates SHA
  pins (`github-actions` ecosystem already configured).
- [x] **Rate limiting beyond auth** — Rails-native `rate_limit` now also
  covers the composer (per-IP, alongside the per-account send quota),
  drafts autosave, password-reset token use, 2FA enrollment, message
  rescan, and the admin mutations (users, accounts, aliases, domains,
  mailboxes, bans, settings).
- [ ] **If the composer grows rich-text/HTML sending** — it is immune to
  the email-HTML-injection class today only because it sends text/plain
  exclusively. Before adding an HTML part: build it with a templating
  layer or an editor emitting constrained markup (never string
  concatenation), run the result through `EmailHtmlSanitizer` too, and
  keep the Mail gem's header encoding plus the whitespace-rejecting
  recipient validation.

### Feature gaps (capability scan, 2026-08)

Web UI, roughly by value:

- [x] **Full-text search** — a GIN-indexed tsvector over
  subject/from/to plus `body_text` (plain text extracted at delivery,
  backfilled by migration) powers an account-wide search page
  (websearch syntax: phrases, OR, `-word`) and an IMAP TEXT/BODY
  pushdown: the store contract grew an optional `search_text` op, so
  SEARCH resolves content keys in Postgres instead of shipping every
  raw message to Ruby for a substring scan. FTS matches whole words
  (the Dovecot trade-off — documented in `docs/store_contract.md`);
  queries an index can't express, and stores without `search_text`,
  keep the RFC-exact substring scan.
- [x] **Pagination** — mailbox pages render 50 messages at a time
  (newest first, Older/Newer links); an out-of-range page clamps.
- [x] **Attachments in the composer** — a multiple-file input on the
  composer; files become MIME parts in `ComposedEmail#build_raw` (the
  body stays the text part), capped at 22 MB raw so the base64-encoded
  message stays under the IMAP APPENDLIMIT (30 MiB). The built message
  passes through the same ClamAV and rspamd gates as any other composer
  send. Attachments travel with the send only — draft autosaves stay
  text. (Attachment *download* with a ClamAV gate already works.)
- [ ] **Per-account server-side filing rules** — inbound filtering is
  global only (rspamd, DMARC); no per-user "file sender X into folder Y"
  (Sieve or a simpler home-grown rule table acted on in the mailroom).
- [x] **Vacation autoresponder** — per-account subject/body/date-range on
  the account form; the mailroom fires `VacationResponder` for mail that
  earned the INBOX (never junk/quarantine), with RFC 3834 loop
  protections: no replies to bounces or the null sender, to
  `Auto-Submitted`/`Precedence: bulk`/`X-Auto-Response-Suppress` mail,
  or to `List-*` traffic; one reply per correspondent per week (an
  atomic upsert, so concurrent deliveries can't double-reply); each
  reply is marked `Auto-Submitted: auto-replied` and consumes a slot of
  the account's outbound send quota.
- [x] **Message threading** — In-Reply-To/References now land in columns
  at delivery and resolve to an account-wide `thread_id` (a reply adopts
  its stored ancestor's thread; with none it derives deterministically
  from the chain root, so out-of-order arrivals converge; backfilled by
  migration). The mailbox list shows one row per conversation (newest
  message, count badge, unread dot if any member is unread), paginated
  by latest activity. The same ids serve IMAP as real RFC 8474
  THREADIDs. (IMAP THREAD — see below.)
- [x] **Storage quotas** — per-account `quota_bytes` (blank = unlimited,
  edited in MB on the account form) with `used_bytes` maintained
  incrementally from message sizes. Enforced centrally in
  `EmailMessage.deliver_raw`, which covers SMTP DATA (mailroom, which
  skips a full recipient without blocking co-recipients), IMAP
  APPEND/COPY (`NO [OVERQUOTA]`), and the composer; same-account moves
  stay exempt so a full account can still file into Trash. Usage shows
  on the account page. (IMAP QUOTA — see below.)
- [x] **.eml download / mbox export** — "Download .eml" on the message
  page serves the stored bytes as `message/rfc822` (no scan gate: an
  .eml is not a browser-executable payload, and getting mail *out* must
  not depend on a verdict). "Export mbox" on the folder page streams the
  whole mailbox as an RFC 4155 mbox (mboxrd quoting, LF line endings),
  one message in memory at a time — see `MboxExport`.
- [ ] **Web Push for new mail** — the PWA service worker skeleton exists
  but is unused; clients must poll / IMAP IDLE.

Protocol/delivery:

- [x] **IMAP THREAD (RFC 5256)** — `THREAD REFERENCES` (full JWZ:
  ancestry forest, placeholder pruning, base-subject merge) and
  `THREAD=ORDEREDSUBJECT`, advertised in CAPABILITY; the FETCH
  `THREADID` NIL stub and the never-matching `THREADID` search key now
  use the store's real thread ids (`fetch` entries carry `thread_id` —
  see `docs/store_contract.md`).
- [x] **IMAP QUOTA (RFC 2087)** — `GETQUOTA`/`GETQUOTAROOT` on a single
  account-wide root `""` with the STORAGE resource (1024-octet units),
  `QUOTA QUOTA=RES-STORAGE` in CAPABILITY, and `NO [OVERQUOTA]` on
  APPEND/COPY; `SETQUOTA` is refused (limits are set in the web UI).
  Backed by the optional store `quota` op — see `docs/store_contract.md`.
- [ ] **DANE for outbound (RFC 7672)** — outbound TLS is opportunistic
  and unverified; TLSA validation (and honoring recipient MTA-STS
  policies, which we publish but don't check when sending) would close
  the active-MITM gap on delivery.
- [ ] **TLS-RPT sending** — we ingest reports at `tls-rpt@` but never
  generate reports about our own inbound TLS failures.
- [ ] **ARC sealing (RFC 8617)** — forwarded/relayed mail carries no
  chain of custody.

Operations:

- [x] **Backups** — `DatabaseBackupJob` (nightly, `config/recurring.yml`)
  writes a custom-format `pg_dump` of the primary database onto the
  persistent storage volume, pruned to `DB_BACKUP_KEEP_DAYS` (default 14)
  only after a successful dump. On demand: `bin/kamal backup` /
  `bin/db-backup`. Restore runbook and offsite guidance:
  [docs/backups.md](docs/backups.md).
- [x] **Metrics** — `GET /metrics` serves Prometheus exposition format,
  enabled by `METRICS_TOKEN` (scrape with it as a bearer token; unset =
  404). Series are computed on scrape from what the app already records:
  outbound queue depth by status and due backlog, queued-to-sent latency
  (last hour, summary sum/count), auth failures by protocol,
  quarantined/junked counts, accounts/messages/storage, and live SMTP/
  IMAP connection counts.
- [x] **Audit log** — an `audit_events` table written by hooks on every
  admin surface (users, accounts, aliases, domains, bans, settings sync
  and knobs, DNS publish, password regens): who did what to what, from
  where. Rows snapshot the actor's email and a subject label, so they
  stay legible after the user or subject is deleted; they are immutable
  and never pruned. Viewer at `/audit` (sidebar: Audit log), newest
  first, paginated.

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
