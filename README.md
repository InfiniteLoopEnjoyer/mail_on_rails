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

- [ ] **Spam-action routing** — the mailroom already gets an rspamd spam
  action/score per message (currently logged only); act on it, e.g. file a
  spam verdict into a Junk mailbox instead of INBOX.
- [ ] **DMARC enforcement (inbound)** — the app computes DMARC via rspamd
  and badges the result; go further and reject or quarantine on failure
  (behind a flag, log-only first) rather than only badging. (Distinct from
  the outbound-side DMARC *monitoring* already in place — see below.)
- [ ] **Rate limiting beyond auth endpoints** — Rails-native
  `rate_limit` covers login/password-reset only.

Already in place (not TODO): PostgreSQL-backed queuing (Solid Queue plus
the `smtp_outbound_messages` retry/backoff table), SPF/DKIM/DMARC
verification of inbound mail (rspamd) and virus scanning (ClamAV,
consulted at SMTP DATA time so infected mail is rejected before
acceptance), outbound DKIM signing, **dynamic domain management** (the
Domains admin UI creates/removes hosted domains live: a DKIM key is
generated per domain and the page shows the DNS records to publish), and
**DMARC monitoring** (aggregate reports
mailed to each domain's auto-created `dmarc@` account are virus-scanned,
sender-verified, parsed, and summarized into per-domain alignment stats
with advice on when it is safe to tighten the published policy).
