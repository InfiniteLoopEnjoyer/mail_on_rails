# mail_on_rails

[![CI](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/ci.yml)
[![Security](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/security.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/security.yml)
[![Lint](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/lint.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](MIT-LICENSE)
[![Databases](https://img.shields.io/badge/db-PostgreSQL%20%7C%20MySQL%20%7C%20SQLite-blueviolet.svg)](#requirements)

A complete mail server for Rails applications: in-process SMTP (RFC 5321
subset with SPF/DKIM/DMARC/ARC verification) and IMAP4rev1 (RFC 3501 subset
with CONDSTORE/QRESYNC) servers that store mail in your app's database
(PostgreSQL, MySQL, or SQLite). Modeled on solid_queue: the gem owns the
models and migrations, and the servers run standalone or inside your web
process as a Puma plugin.

Looking for a UI? The companion repo
**[mail_on_rails_admin](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin)**
is a complete example host application — webmail, a mail-server admin UI
(domains/DNS, accounts, users, live connections, security dashboards),
and a single-container Kamal deploy. Start there if you want a running
mail server; start here if you want to embed one in your own app.

## What's in the box

- **SMTP server** — port 25 MX ingress and authenticated submission
  (587/465), with sender verification, scanning, and abuse controls
  applied at DATA time (`lib/mail_on_rails/smtp`).
- **IMAP server** — IMAP4rev1 with CONDSTORE/QRESYNC, IDLE, and
  SPECIAL-USE, tested against real clients (`lib/mail_on_rails/imap`).
- **Shared listener scaffolding** — TLS, connection caps, tarpits,
  lockouts, and the supervisor that restarts a dead listener
  (`lib/mail_on_rails/netserv`).
- **Storage** — Active Record models and migrations for domains,
  accounts, aliases, mailboxes, messages, outbound queue, reports, and
  settings; the servers talk to storage through a documented
  [store contract](docs/store_contract.md).
- **Inbound pipeline** — mail is ingested as
  `ActionMailbox::InboundEmail` and processed by
  `MailOnRails::MailroomMailbox`; rspamd (SPF/DKIM/DMARC + spam) and
  ClamAV clients are built in.
- **Outbound delivery** — MX resolution, DANE (RFC 7672) and MTA-STS
  (RFC 8461) verified TLS, DKIM signing, per-recipient retry/backoff,
  and TLS-RPT (RFC 8460) report generation.
- **Domain/DNS tooling** — per-domain DKIM key generation, the DNS
  records to publish, live verification against public DNS
  (`DnsCheck`), and optional Cloudflare publishing.
- **Report handling** — DMARC aggregate and TLS-RPT report ingestion,
  parsing, and per-domain summaries; RFC 3834-hardened vacation
  auto-replies.
- **Settings system** — every tunable declared once in a schema,
  layered `default < ENV < initializer < database`, with live
  propagation to running listeners (see
  [Configuration](#configuration)).

## Requirements

- PostgreSQL 14+, MySQL 8.0.13+, or SQLite 3.35+. Full-text message
  search is fastest on PostgreSQL (a generated `tsvector` column with
  websearch semantics: quoted phrases, OR, `-exclusions`); the other
  adapters fall back to a case-insensitive all-terms substring match.
  MySQL operators: raw messages are stored as single-row `longblob`
  writes, so `max_allowed_packet` must exceed the largest message you
  accept; use a `utf8mb4` database.
- Active Record encryption configured in the host app (`bin/rails
  db:encryption:init`) — SCRAM credentials and DKIM private keys are
  stored encrypted
- Action Mailbox (inbound mail is ingested as `ActionMailbox::InboundEmail`)

## Installation

```ruby
# Gemfile
gem "mail_on_rails"
```

```sh
bin/rails generate mail_on_rails:install
bin/rails db:migrate
```

The generator creates `bin/mail_server`, a commented initializer, and
routes inbound mail to `MailOnRails::MailroomMailbox`. Mount the engine to
serve `/.well-known/mta-sts.txt`:

```ruby
mount MailOnRails::Engine => "/"
```

## Running the servers

**Inside Puma** (one process, `WEB_CONCURRENCY=1`):

```ruby
# config/puma.rb
plugin :mail_on_rails
```

**Standalone:**

```sh
bin/mail_server            # start (drains gracefully on TERM/INT)
bin/mail_server check      # validate settings/TLS/listener config without binding; exit 1 on errors
```

## Configuration

Every tunable is declared once in the settings schema
(`MailOnRails::Settings`), layered as

    gem default < ENV < initializer override < settings table

The legacy `MAIL_ON_RAILS_*` / `SMTP_*` environment variables all still
work - each schema entry declares its variable, so existing deployments
configure exactly as before. The full list is generated in
[docs/settings.md](docs/settings.md).

**Initializer tier** - typed, validated at boot:

```ruby
config.mail_on_rails.setting_overrides = { smtp_max_conn: 200, smtp_rbl_zones: %w[zen.spamhaus.org] }
```

**Database tier** - `scope: :dynamic` settings (feature toggles, limits,
rates, timeouts, scanner addresses, retention) can be overridden from the
host app's admin Settings page via `MailOnRails::Setting.write`. Changes
reach running listeners without a restart: connection caps/rates/lockouts
apply at the next connection, sender-auth/DNSBL/virus/spam scanning at the
next message, send quotas at the next recipient; open sessions are never
retro-limited. In-process changes apply immediately (an `after_commit`
push); other processes converge within ~5 s (a TTL cache that fails soft
to the last good snapshot if the database is unavailable). Boot-only
settings (ports, bind addresses, TLS material, secrets) never come from
the database.

A server whose listener dies is restarted automatically by a supervisor
thread with escalating backoff; while a protocol is down, `MailOnRails.ready?`
is false, so a `/up`-gated deploy or monitor sees it.

Rails-side object seams are plain `config.mail_on_rails.*` attributes:

```ruby
config.mail_on_rails.protocols = [ :imap, :smtp ]
```

Host apps extend the gem's models with `ActiveSupport.on_load` hooks
(`:mail_on_rails_email_account`, `:mail_on_rails_mailbox`,
`:mail_on_rails_email_message`, `:mail_on_rails_domain`, ...) — add
associations, broadcasts, or scopes without reopening classes.

The store contract the servers program against is documented in
[docs/store_contract.md](docs/store_contract.md).

## Security

Defaults are enforcing; every control below ships on unless a setting
turns it off.

**At the listener** (both protocols, shared `netserv` scaffolding):
process-wide and per-IP connection caps, a per-IP connection-rate
tarpit, per-IP lockout after repeated failed authentications, a
database-backed IP/CIDR denylist polled live, slow-client reaping, and
fail-closed TLS — configured cert paths that don't load are a boot
error, not a silent plaintext fallback.

**Authentication**: AUTH is submission-only (never on port 25), with
SCRAM-SHA-256 including the `-PLUS` channel-binding variants on both
SMTP and IMAP; credentials are stored as SCRAM verifiers (plus bcrypt),
encrypted with Active Record encryption, and unknown users get
constant-shape decoy challenges to block account enumeration.

**Inbound mail**: SPF/DKIM/DMARC verification and spam scoring via
rspamd, virus scanning via ClamAV — both consulted at SMTP DATA time so
a bad message is refused (550) before acceptance, scanner-down answers
451 and fails closed on the MX path; DNSBL checks and Spamhaus DROP
list refresh; DMARC policy is enforced on the MX edge. Trusted routing
headers stamped by the SMTP edge are HMAC-sealed (`IngressSeal`), so
nothing that reaches the mailroom by another route can forge
authenticated/verified status.

**Outbound mail**: DKIM signing; DANE and MTA-STS verified TLS with no
cleartext fallback when a policy is in force; per-account send quotas
and an rspamd gate on authenticated submission; SMTP smuggling defenses
on generated traffic (strict dot-stuffing/CRLF handling).

**Protocol robustness**: the suites include conformance tests ported
from Exim's and mox's test suites and regression tests for the known
CVE classes of mainstream SMTP/IMAP servers (18 SMTP and 16 IMAP
vulnerability classes — smuggling, header injection, literal/parser
DoS, auth bypass, and friends).

The reference deployment's operational security posture (2FA, RBAC,
metrics exposure, honeypot dashboards) lives in the
[companion app](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin).

## Testing

```sh
bundle exec rake test            # settings + IMAP + SMTP + DB suites
bundle exec rake test:imap       # protocol suites are Rails-free and run
bundle exec rake test:smtp       #   in a clean ruby subprocess
bundle exec rake test:settings
bundle exec rake test:db         # models/store against DATABASE_URL
                                 #   (defaults to SQLite)
```

CI runs the full matrix across PostgreSQL, MySQL, and SQLite.

## License

MIT.
