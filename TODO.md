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
- [x] **Warn when sending unsigned** (2026-07-25) — `OutboundDeliverer#signed`
  logs an UNSIGNED warning naming the keyless domain (and also warns
  instead of raising when signing itself fails).
- [x] **DMARC alignment: sign with the From: header domain** (2026-07-25) —
  the signing domain now comes from the `From:` header (the domain DMARC
  aligns against), falling back to the envelope `mail_from` when the
  header is missing/unparseable. Covered in
  `test/models/outbound_deliverer_test.rb`.
- **SPF: DNS-only, nothing enforces it** — code only exposes
  `SMTP_HELO_HOST`; nothing verifies the published SPF record
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

- [x] **Cross-check DKIM signing against Postal's signer** (2026-07-25) —
  `test/models/dkim_signing_test.rb` proves our canonicalization
  reproduces Postal's byte-exact: our bh= matches theirs, and Postal's
  b= signature verifies over OUR canonicalized headers (plus a round-trip
  verify of our own signature). Keys stay 2048-bit.
- [x] **Port Postal's DKIM test vectors** (2026-07-25) — both vectors
  copied to `test/fixtures/dkim_signing/` (MIT) and driven by the same
  test, including the quoted-printable stress case.
- [x] **Randomize equal-preference MX records** (2026-07-25) —
  `OutboundDeliverer#mx_hosts` shuffles preference ties.
- [ ] **DEFERRED: Batch outbound messages by destination domain** — Postal
  tags queued messages with a `batch_key` so a worker can deliver several
  over one SMTP connection (`lib/postal/message_db/message.rb:353-361`).
  Deliberately deferred (2026-07-25): connection reuse only pays off at
  sending volume we don't have; revisit if that changes.

## Inbound handling / UI

- [x] **Domain-setup DNS checker** (2026-07-25) — the domain page now
  live-checks published DNS against what it prescribes (`DnsCheck`:
  MX points at SMTP_HELO_HOST, SPF authorizes the server, DKIM TXT
  matches the key on disk, DMARC record exists) with
  pass/verify/missing/unknown badges per record, plus the DMARC
  monitoring section (aggregate-report ingestion + tighten-when-ready
  advice) built 2026-07-25.
- [x] **Optional spam-engine integration** — OBSOLETE: rspamd and ClamAV
  have been integrated for a while (mailroom sender-auth/spam verdicts +
  virus scanning, and since 2026-07-25 the exim edge also scans at DATA
  time). The one remaining idea from this item — acting on the spam
  score/action per message — is tracked in README.md's roadmap as
  "spam-action routing".

## Open question (deferred)

Postal's outbound retry/backoff schedule, bounce processing, suppression
lists, and webhook design were not analyzed (that deep-dive was skipped).
If we want to compare against our `smtp_outbound_messages` retry/backoff
design, start at `app/lib/message_dequeuer/` and `app/senders/smtp_sender.rb`
in the Postal clone.
