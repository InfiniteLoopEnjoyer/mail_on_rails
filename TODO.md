# TODO — ideas adopted from Postal analysis

Derived from reviewing [Postal](https://github.com/postalserver/postal)
(MIT, cloned at `/home/deploy/postal`) on 2026-07-21. Each item cites the
Postal source it's based on. Pending review — nothing here is committed
roadmap yet. Daemon-side items live in the sibling repos' TODO.md files.

## Outbound deliverability (DKIM/SPF/DMARC audit, 2026-07-22)

Audit of `DeliverSmtpOutboundJob` → `OutboundDeliverer`:

- **DKIM: implemented** — `OutboundDeliverer#signed` signs with the
  `dkim` gem using per-domain keys at `MAIL_ON_RAILS_DKIM_DIR/<domain>.pem`
  (`/rails/storage/dkim` in deploy.yml), selector
  `MAIL_ON_RAILS_DKIM_SELECTOR` (default `rail`).
- [ ] **Warn when sending unsigned** — if the domain's key file is
  missing, the message goes out silently unsigned (no log, no warning).
  Add a `Rails.logger.warn` in the fallback path.
- [ ] **DMARC alignment: sign with the From: header domain** — the
  signing domain is derived from the envelope `mail_from`, not the
  `From:` header. If those ever differ, the DKIM signature won't align
  for DMARC. Either sign with the header-From domain or enforce
  envelope/header domain match on enqueue.
- **SPF: DNS-only, nothing enforces it** — code only exposes
  `MAIL_ON_RAILS_HELO_HOST`; nothing verifies the published SPF record
  includes the sending IP. Covered by the "Domain-setup DNS checker"
  item below. Note: via `MAIL_ON_RAILS_SMARTHOST`, SPF is evaluated
  against the smarthost's IP, so its SPF posture is what matters.
- **DMARC: passes when the above hold** — needs aligned DKIM *or*
  aligned SPF; with a key present and envelope-from == header-from,
  outbound passes. No code needed beyond the alignment fix above.
- **Not covered by code (operator checklist)** — PTR/FCrDNS for the
  sending IP; also note outbound STARTTLS uses `tls_verify: false`
  (fine for deliverability, worth knowing).

## Outbound delivery

- [ ] **Cross-check DKIM signing against Postal's signer** — Postal's
  `app/lib/dkim_header.rb` is a self-contained, hand-rolled RFC 6376
  implementation (rsa-sha256, relaxed/relaxed): header canonicalization
  at lines 50-77, body canonicalization at 79-101. Use it as a
  correctness oracle for our canonicalization (the part of DKIM where
  interop bugs hide) — feed both signers identical tricky messages and
  diff the outputs. Note Postal generates 1024-bit keys (`domain.rb:84-86`);
  ours must stay 2048.
- [ ] **Port Postal's DKIM test vectors** — `spec/examples/dkim_signing/email1.msg`
  and `email2.msg` are self-contained signing vectors: YAML frontmatter
  with domain, timestamp, private key, and the expected `bh=` body hash
  and `b=` signature, followed by the raw message. `email2.msg` is a
  real-world quoted-printable HTML email with hard tabs, MSO conditional
  comments, and long folded `List-*` headers — exactly the
  relaxed-canonicalization stress case. Directly reusable as fixtures for
  our signer tests (driver: Postal's `spec/lib/dkim_header_spec.rb`).
- [ ] **Randomize equal-preference MX records** — when resolving MXes
  for outbound delivery, sort by preference but shuffle ties so load
  spreads across a destination's MX pool (Postal:
  `app/lib/dns_resolver.rb:61-72`). Check `OutboundDeliverer` does this.
- [ ] **Batch outbound messages by destination domain** — Postal tags
  queued messages with a `batch_key` (roughly destination domain +
  route) so a worker can deliver multiple queued messages over one SMTP
  connection (`lib/postal/message_db/message.rb:353-361`). Worth
  considering for `smtp_outbound_messages` if we ever send meaningful
  volume; connection reuse is the single biggest outbound throughput win.

## Inbound handling / UI

- [ ] **Domain-setup DNS checker** — Postal validates that a sending
  domain's published DNS is correct (SPF record includes the server,
  DKIM TXT matches the generated key, MX/return-path point home) and
  surfaces pass/fail in the UI (`app/models/concerns/has_dns_checks.rb:45-146`).
  A "is my domain configured correctly?" page would fit our web UI well
  and reuse the daemons' DNS code.
- [ ] **Optional spam-engine integration (adapter pattern)** — if we ever
  add SpamAssassin/rspamd/ClamAV scanning, Postal's
  `lib/postal/message_inspectors/{spam_assassin,rspamd,clamav}.rb` are
  clean, small adapter references (raw spamd/clamd socket protocols,
  rspamd HTTP `/checkv2`, 10-15s fail-open timeouts). Its handling model:
  stamp `X-*-Spam*`/threat headers, then act on per-route thresholds
  (deliver / quarantine / reject). Pairs with our existing
  verified/unverified badge UI.

## Explicitly NOT adopting from Postal

- **Per-server MySQL message databases** — Postal shards raw mail into
  per-tenant MySQL DBs with date-partitioned raw tables. Our
  single-Postgres design is deliberate; nothing to change.
- **Inbound SPF/DKIM/DMARC via spam engine** — Postal doesn't verify
  sender auth itself; our in-daemon verifiers are ahead. Keep them.

## Open question (deferred)

Postal's outbound retry/backoff schedule, bounce processing, suppression
lists, and webhook design were not analyzed (that deep-dive was skipped).
If we want to compare against our `smtp_outbound_messages` retry/backoff
design, start at `app/lib/message_dequeuer/` and `app/senders/smtp_sender.rb`
in the Postal clone.
