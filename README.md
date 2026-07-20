# mail_on_rails

A from-scratch mail server built around a Rails app: SMTP (MX + authenticated
submission), IMAP, and a web UI, with mail stored in PostgreSQL.

## Architecture

The protocol daemons live in sibling repos and deploy as their own Kamal
services:

- **mail_on_rails_smtp** — SMTP listeners (MX, submission, SMTPS) with
  STARTTLS/AUTH, SPF/DKIM/DMARC verification of inbound mail, and DoS caps.
  Sender-verification behavior (DMARC enforcement, DNS fail-open caveats)
  is documented in that repo's README.
- **mail_on_rails_imap** — the IMAP server.

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
