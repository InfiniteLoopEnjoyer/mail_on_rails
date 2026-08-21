# mail_on_rails

[![CI](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/ci.yml)
[![Security](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/security.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/security.yml)
[![Lint](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/lint.yml/badge.svg?branch=main&event=push)](https://github.com/InfiniteLoopEnjoyer/mail_on_rails/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](MIT-LICENSE)
[![Databases](https://img.shields.io/badge/db-PostgreSQL%20%7C%20MySQL%20%7C%20SQLite-blueviolet.svg)](#requirements)

A complete mail server for Rails applications that stores mail in your
app's database (PostgreSQL, MySQL, or SQLite). Modeled on solid_queue:
this gem owns the models and migrations; the protocol servers are
separate gems that depend on it, and run standalone or inside your web
process as a Puma plugin.

| Gem | Owns |
|---|---|
| **`mail_on_rails`** (this gem, the core) | models, migrations, jobs, the inbound mailroom, outbound delivery, the settings schema, the shared listener scaffolding (`Netserv`), SPF/DKIM/DMARC/ARC and SCRAM primitives, the runtime, the Puma plugin, the CLI |
| [`mail_on_rails_smtp`](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_smtp) | the SMTP server (MX / submission / SMTPS) and its Active Record store |
| [`mail_on_rails_imap`](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_imap) | the IMAP server (IMAP / IMAPS) and its Active Record store |

Install the core plus whichever protocols you want: SMTP only, IMAP only
(your own code fills the tables and IMAP serves them), or both. Each
protocol gem registers itself with the runtime when loaded - there is
nothing else to wire.

Looking for a UI? The companion repo
**[mail_on_rails_admin](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin)**
is a complete example host application - webmail, a mail-server admin UI
(domains/DNS, accounts, users, live connections, security dashboards),
and a Kamal deploy that runs web, SMTP and IMAP as separate containers
from one image. Start there if you want a running mail server; start
here if you want to embed one in your own app.

## What's in the box

- **Storage** - Active Record models and migrations for domains,
  accounts, aliases, mailboxes, messages, outbound queue, reports,
  settings, bans, and the ops state the servers project (live
  connections, lockouts, listener heartbeats, kick commands); the
  servers talk to storage through a documented
  [store contract](docs/store_contract.md).
- **Inbound pipeline** - mail accepted by the SMTP gem is ingested as
  `ActionMailbox::InboundEmail` and processed by
  `MailOnRails::MailroomMailbox`; rspamd (SPF/DKIM/DMARC + spam) and
  ClamAV clients are built in.
- **Outbound delivery** - MX resolution, DANE (RFC 7672) and MTA-STS
  (RFC 8461) verified TLS, DKIM signing, per-recipient retry/backoff,
  and TLS-RPT (RFC 8460) report generation.
- **Shared listener scaffolding** (`lib/mail_on_rails/netserv`) - TLS,
  connection caps, tarpits, lockouts, the admin denylist, slow-client
  reaping, session transcripts, the supervisor that restarts a dead
  listener, and the ops-state sync that makes the admin UI work across
  processes.
- **Mail primitives** - SPF/DKIM/DMARC/ARC verification and the DNS
  client (`MailOnRails::SenderAuth`), in-process DNSSEC validation,
  SCRAM-SHA-256(-PLUS) (`MailOnRails::Scram`), send quotas, IDN, the
  ingress seal.
- **Domain/DNS tooling** - per-domain DKIM key generation, the DNS
  records to publish, live verification against public DNS
  (`DnsCheck`), and optional Cloudflare publishing.
- **Report handling** - DMARC aggregate and TLS-RPT report ingestion,
  parsing, and per-domain summaries; RFC 3834-hardened vacation
  auto-replies.
- **Settings system** - every tunable declared once in a schema,
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
  db:encryption:init`) - SCRAM credentials and DKIM private keys are
  stored encrypted
- Action Mailbox (inbound mail is ingested as `ActionMailbox::InboundEmail`)

## Installation

```ruby
# Gemfile
gem "mail_on_rails"
gem "mail_on_rails_smtp"   # the SMTP server - omit for IMAP-only
gem "mail_on_rails_imap"   # the IMAP server - omit for SMTP-only
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

Two ways, same gems, same behavior; the admin UI reads the same tables
either way.

**Standalone** - each protocol in its own process or container (the
reference deploy runs web, smtp and imap as three containers from one
image):

```sh
bin/mail_server --protocols smtp         # just SMTP
bin/mail_server --protocols imap         # just IMAP
bin/mail_server                          # every installed protocol
bin/mail_server check                    # validate settings/TLS/listener config without binding
```

**Inside Puma** - one process for everything:

```ruby
# config/puma.rb
plugin :mail_on_rails
```

Which protocols the plugin runs in that process:

```text
MAIL_ON_RAILS_SERVERS=smtp,imap   # both
MAIL_ON_RAILS_SERVERS=smtp        # SMTP only (IMAP elsewhere, or not installed)
MAIL_ON_RAILS_SERVERS=0           # web only - the listeners run in other containers
```

Unset, development runs every installed protocol and every other
environment runs none (production opts in). `config.mail_on_rails.protocols`
is the initializer equivalent (`[]` = web only). With listeners in-process
the plugin refuses `WEB_CONCURRENCY > 1`; with none it is a no-op.

Host apps gate `/up` on `MailOnRails.ready?` **only when**
`MailOnRails::Runtime.in_process_protocols` is non-empty - a web
process whose listeners live elsewhere must not wait on ports it does
not bind.

### Jobs: Solid Queue is required

The listeners are only the edge. Everything that happens *after* accept
is an Active Job in this gem, and a `bin/mail_server` process runs
**no** job worker - so your deployment must run one (this stack uses
[Solid Queue](https://github.com/rails/solid_queue); the reference app
runs its supervisor inside the web role with `SOLID_QUEUE_IN_PUMA`) and
a recurring schedule. Without them:

- accepted inbound mail sits in `action_mailbox_inbound_emails` and is
  never routed by `MailroomMailbox` into mailboxes;
- submitted outbound mail sits in `smtp_outbound_messages` and is never
  sent (`DeliverSmtpOutboundJob` is a recurring job, every ~15 s);
- DMARC / TLS-RPT reports, DKIM rotation, Spamhaus DROP refresh,
  rescans, and every `prune!` never run.

The schedule itself lives in the host app, not the gem - copy the
`config/recurring.yml` from
[mail_on_rails_admin](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin)
as the reference. An SMTP-only or IMAP-only container therefore still
needs a sibling job process (`bin/jobs`) against the same database; a
standalone mode that runs Solid Queue inside `bin/mail_server` is on the
todo list.

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
config.mail_on_rails.protocols = [ :smtp ]            # what the Puma plugin runs here
config.mail_on_rails.on_connection_activity = ->(protocol) { ... }  # dashboard refresh hook
```

Host apps extend the gem's models with `ActiveSupport.on_load` hooks
(`:mail_on_rails_email_account`, `:mail_on_rails_mailbox`,
`:mail_on_rails_email_message`, `:mail_on_rails_domain`, ...) - add
associations, broadcasts, or scopes without reopening classes.

The store contract the servers program against is documented in
[docs/store_contract.md](docs/store_contract.md).

## Ops state across processes

Every running server projects its live picture into the database on a
short tick (`Netserv::OpsSync`, `ops_sync_interval`, default 2 s): a
`listeners` heartbeat row (protocol, pid, ports, readiness),
`open_connections` (the live connection table), and `accept_lockouts`
(addresses refused before a session exists). The same tick drops live
connections of newly banned addresses (a `BannedIp` row is the whole
command) and processes `connection_kicks` (drop this source now, without
a ban), acknowledging each with the count. A listener that stops
heartbeating is swept by the others after `ops_stale_after` (30 s).

An admin UI reads `Listener.alive`, `OpenConnection.live`,
`AcceptLockout.active`, and writes `ConnectionKick.request!` - and works
the same whether the listeners are in its process or in other
containers. `config.mail_on_rails.on_connection_activity` fires from the
tick right after a changed picture is written, so a Turbo refresh never
races the rows it announces.

## Security

Defaults are enforcing; every control below ships on unless a setting
turns it off.

**At the listener** (both protocols, shared `netserv` scaffolding):
process-wide and per-IP connection caps, a per-IP connection-rate
tarpit, per-IP lockout after repeated failed authentications, a
database-backed IP/CIDR denylist polled live (and applied to open
sessions), slow-client reaping, and fail-closed TLS - configured cert
paths that don't load are a boot error, not a silent plaintext
fallback; production refuses to boot on the self-signed fallback.

**Authentication**: AUTH is submission-only (never on port 25), with
SCRAM-SHA-256 including the `-PLUS` channel-binding variants on both
SMTP and IMAP; credentials are stored as SCRAM verifiers (plus bcrypt),
encrypted with Active Record encryption, and unknown users get
constant-shape decoy challenges to block account enumeration.

**Inbound mail**: SPF/DKIM/DMARC verification and spam scoring via
rspamd, virus scanning via ClamAV - both consulted at SMTP DATA time so
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

**Protocol robustness**: the protocol gems' suites include conformance
tests ported from Exim's and mox's test suites and regression tests for
the known CVE classes of mainstream SMTP/IMAP servers (18 SMTP and 16
IMAP vulnerability classes - smuggling, header injection, literal/parser
DoS, auth bypass, and friends).

The reference deployment's operational security posture (2FA, RBAC,
metrics exposure, honeypot dashboards) lives in the
[companion app](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_admin).

## Testing

```sh
bundle exec rake test               # every suite below
bundle exec rake test:settings      # the settings schema          (Rails-free)
bundle exec rake test:netserv       # listener scaffolding, ops sync (Rails-free)
bundle exec rake test:sender_auth   # SPF/DKIM/DMARC/ARC, DNS client (Rails-free)
bundle exec rake test:lib           # SCRAM, send quota, clamd, seal (Rails-free)
bundle exec rake test:dnssec        # the validating resolver       (Rails-free)
bundle exec rake test:db            # models/store plumbing against DATABASE_URL
                                    #   (defaults to SQLite)
```

The Rails-free suites run in a clean ruby subprocess. CI runs the db
suite across PostgreSQL, MySQL, and SQLite. The protocol servers' own
suites (wire, CVE, conformance, fuzz) live in their gems; their store
suites reuse this gem's harness, `MailOnRails::Testing::Database`
(`require "mail_on_rails/testing/database"`), which boots Active Record
without a Rails application, loads the models and runs every migration.

## License

MIT.
