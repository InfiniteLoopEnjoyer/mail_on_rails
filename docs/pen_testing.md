# Penetration testing SMTP and IMAP

How to security-test **mail_on_rails** responsibly. Only run these procedures
against environments you own or have written authorization to test (local dev,
staging, or a dedicated pentest VM). Do not point scanners or brute-force tools
at production without explicit approval.

## Quick start

1. Run the automated pen-test suites (fast, no live server required):

   ```bash
   bin/rails test:smtp_server   # includes test/vendored/smtp/pen_test.rb
   bin/rails test:imap_server   # includes test/vendored/imap/pen_test.rb
   bin/rails test test/integration/pen_test.rb
   ```

   To run only the pen-test files in isolation (Rails-free subprocess):

   ```bash
   ruby -Ilib -Itest/vendored/smtp -e 'require File.expand_path("test/vendored/smtp/pen_test.rb")'
   ruby -Ilib -Itest/vendored/imap -e 'require File.expand_path("test/vendored/imap/pen_test.rb")'
   ```

2. **Deep fuzz runs** (stateful random sessions + security oracles):

   ```bash
   bin/rails fuzz:smtp
   bin/rails fuzz:imap

   # longer / reproducible runs
   FUZZ_ROUNDS=10000 FUZZ_SEED=42 FUZZ_VERBOSE=1 bin/rails fuzz:smtp
   ```

   | Variable | Default | Purpose |
   | --- | --- | --- |
   | `FUZZ_ROUNDS` | `100` | Sessions per run |
   | `FUZZ_SEED` | `0xFEED_F00D` | PRNG seed (printed on failure for replay) |
   | `FUZZ_TIMEOUT` | `2` | Per-read socket timeout (seconds) |
   | `FUZZ_VERBOSE` | off | Log oracle failure details |

3. Start the full stack locally:

   ```bash
   bin/setup   # if needed
   bin/dev
   ```

   Dev listeners (internal ports): SMTP MX `1025`, submission `1587`, IMAP
   `1143`, IMAPS `1993`. Seeded accounts live in `db/seeds.rb`.

3. Work through the checklist below against `localhost`, recording results.

## Stateful fuzz harness

`bin/rails fuzz:smtp` and `bin/rails fuzz:imap` drive grammar-shaped sessions
with byte-level mutations against the in-memory store on loopback. Each round
picks a profile, mutates arguments, and checks security oracles afterward.

**SMTP profiles:** `garbage`, `mx_relay_attempt`, `submission_no_auth`,
`auth_garbage`, `stateful_delivery`, `data_smuggle`, `pipelined`.

**IMAP profiles:** `garbage_preauth`, `garbage_postauth`, `stateful_commands`,
`literal_flood`, `auth_garbage`, `cross_account_probe`.

**Oracles (both protocols):** no session crash; relay/envelope-spoof paths never
queue unauthorized mail; garbage rounds store nothing; IMAP pre-auth commands
cannot read mail; cross-account probes never leak another user's mailbox names
or message content.

Replay a failing seed from the summary line:

```bash
FUZZ_SEED=4277006349 FUZZ_ROUNDS=200 bin/rails fuzz:smtp
```

## Automated coverage map

| Area | Primary suites |
| --- | --- |
| SMTP parser abuse / fuzzing | `test/vendored/smtp/smtp_parser_abuse_test.rb` |
| SMTP RFC conformance | `test/vendored/smtp/smtp_conformance_test.rb` |
| SMTP pen-test scenarios | `test/vendored/smtp/pen_test.rb` |
| SMTP stateful fuzz (CI smoke) | `test/vendored/smtp/fuzz_smoke_test.rb` |
| SMTP virus scanning | `test/vendored/smtp/smtp_virus_scan_test.rb` |
| IMAP RFC compliance audits | `test/vendored/imap/*_audit_test.rb` |
| IMAP account isolation | `test/vendored/imap/cross_account_isolation_test.rb` |
| IMAP pen-test scenarios | `test/vendored/imap/pen_test.rb` |
| IMAP stateful fuzz (CI smoke) | `test/vendored/imap/fuzz_smoke_test.rb` |
| Full-stack wire tests | `test/integration/pen_test.rb`, `test/integration/in_process_servers_test.rb` |
| Auth throttling / lockout | `test/vendored/smtp/auth_throttle_test.rb`, `test/vendored/imap/accept_hardening_test.rb` |

Add a regression test in the matching suite whenever manual testing finds a bug.

---

## Pre-flight

- [ ] Scope documented (hostnames, ports, accounts, date range).
- [ ] Staging or local only — not production unless explicitly authorized.
- [ ] Throwaway mailboxes created; no real user passwords in notes.
- [ ] `SMTP_SENDER_AUTH=0` in dev if you want to skip live DNS during MX tests
      (the integration suite sets this automatically).
- [ ] ClamAV available for malware tests (`bin/dev` starts `clamav-dev` when
      Docker is present; see [virus_scanning.md](virus_scanning.md)).

---

## SMTP checklist

### Transport and TLS

- [ ] **STARTTLS offered** on MX (`1025`) and submission (`1587`); inspect with
      `openssl s_client -starttls smtp -connect localhost:1587`.
- [ ] **Implicit TLS** on SMTPS (`1465` internal / `465` production mapping).
- [ ] **Cert/name mismatch** rejected when verification is enabled (staging with
      real certs).
- [ ] **Downgrade**: cleartext session must not advertise `AUTH` on submission
      (`test_auth_is_refused_on_an_unencrypted_channel`).

### Authentication

- [ ] **Submission requires AUTH** before `MAIL FROM` (expect `530`).
- [ ] **AUTH only over TLS** on submission (expect `538` in the clear).
- [ ] **Brute force / lockout** — after `SMTP_AUTH_LOCKOUT_FAILURES` bad auths
      from one IP, next connection gets `421` before banner (see
      `accept_hardening_test.rb`). Verify lockout expires
      (`SMTP_AUTH_LOCKOUT_SECONDS`).
- [ ] **Per-session auth cap** — three failures on one connection drop it
      (`MAX_AUTH_ATTEMPTS`).
- [ ] **Credentials never in logs** — enable `SMTP_TRACE=1`, fail and succeed
      AUTH, confirm `[redacted]` in trace output.
- [ ] **Throttled auth** returns `454` (temporary), not `535` (wrong password).

### Envelope and relay

- [ ] **Open relay closed** — MX must refuse foreign recipients (`550 5.7.1
      Relaying denied`). Covered by `pen_test.rb` and `smtp_session_test.rb`.
- [ ] **Unknown local user** returns `550 5.1.1`, not relay denied.
- [ ] **Submission envelope spoof** — after AUTH as `alice@domain`, `MAIL
      FROM:<bob@domain>` must get `550 Sender address must match authenticated
      account`.
- [ ] **SASL PLAIN authzid** — authenticating with authzid set to another user
      must bind the session to the credential identity, not the authzid.
- [ ] **Remote RCPT only on submission** after AUTH; MX stays local-only.
- [ ] **Null sender** (`MAIL FROM:<>`) accepted only where RFC-legal (bounces).

### Parser and smuggling

- [ ] **Overlong lines** rejected without setting envelope state.
- [ ] **Null bytes / control chars** in commands do not crash the session.
- [ ] **Pipelining blast** — every command gets a well-formed reply.
- [ ] **DATA smuggling** — bare-LF dot lines must not terminate DATA early;
      stuffed `..` lines round-trip correctly.
- [ ] **Dot-stuffed command injection** after DATA terminator — next line must
      be parsed as a fresh command, not absorbed into the body.
- [ ] **Recipient cap** — `MAX_RECIPIENTS` then `452`.
- [ ] **Message cap** — `MAX_MESSAGES_PER_SESSION` then `421` on next DATA.

### Content and malware

- [ ] **EICAR test string** in SMTP DATA → `550` before acceptance (see
      [virus_scanning.md](virus_scanning.md) manual procedure).
- [ ] **Scanner down** → `451` (fail closed), nothing stored as clean.
- [ ] **Received: loop** — more than `MAX_RECEIVED_HOPS` → `550 Loop detected`.
- [ ] **Oversized message** → `552`, session stays alive.

### Manual SMTP tools

```bash
# Interactive MX
nc localhost 1025

# STARTTLS submission
openssl s_client -starttls smtp -connect localhost:1587

# Scripted delivery / relay probe
swaks --to user@yourdomain.test --from attacker@evil.test \
  --server localhost --port 1025

# Authenticated submission
swaks --to friend@elsewhere.test --from user@yourdomain.test \
  --auth-user user@yourdomain.test --auth-password '...' \
  --server localhost --port 1587 --tls
```

---

## IMAP checklist

### Transport and TLS

- [ ] **STARTTLS** on port `1143`; greeting advertises `STARTTLS` and
      `LOGINDISABLED`, not `AUTH=PLAIN`.
- [ ] **IMAPS** on `1993` — implicit TLS from first byte.
- [ ] **Post-STARTTLS capabilities** include `AUTH=PLAIN AUTH=SCRAM-SHA-256`;
      pre-upgrade must not.
- [ ] **STARTTLS mid-session** clears selected mailbox state (no stale
      `mailbox_id` after upgrade).

### Authentication

- [ ] **LOGIN / AUTHENTICATE refused on cleartext** (`[PRIVACYREQUIRED]`).
- [ ] **SCRAM-SHA-256** — replayed or truncated proofs rejected.
- [ ] **Failed LOGIN** does not burn quota on a refused plaintext attempt.
- [ ] **Second LOGIN while authenticated** → `BAD` (no identity rebind).
- [ ] **SASL PLAIN authzid** cannot switch accounts (session binds to
      authcid).
- [ ] **Auth lockout** mirrors SMTP (`MAIL_ON_RAILS_IMAP_AUTH_LOCKOUT_*`).

### Authorization (account isolation)

Run `test/vendored/imap/cross_account_isolation_test.rb` and manually verify:

- [ ] **LIST** never reveals another account's mailbox names.
- [ ] **SELECT / EXAMINE / STATUS / DELETE / RENAME / APPEND** on another
      account's mailbox → `NO`.
- [ ] **COPY / MOVE** to another account's mailbox → `NO [TRYCREATE]`, source
      message intact.
- [ ] **COPY to shared mailbox name** lands in caller's own namespace only.
- [ ] **UID STORE / EXPUNGE / SEARCH** cannot reach another account's messages.

### Pre-auth command surface

- [ ] **SELECT, APPEND, FETCH, SEARCH, IDLE** before LOGIN → `NO` / `BAD`.
- [ ] **CAPABILITY, NOOP, LOGOUT, STARTTLS** allowed pre-auth.

### Parser and literals

- [ ] **Oversize synchronizing literal** → `NO [TOOBIG]`, session survives.
- [ ] **LITERAL+ payload that looks like commands** is drained, not executed.
- [ ] **AUTHENTICATE continuation** over `MAX_LINE` → `BAD`, connection dropped.
- [ ] **Mailbox names with quotes / UTF-7 edge cases** do not break quoting or
      leak other users' data.

### Content

- [ ] **APPEND with EICAR** (app store path) → `NO APPEND failed: virus
      detected` when ClamAV is up (`imap_backend_scan_test.rb`).
- [ ] **APPEND with scanner down** — user's own mail stored `unscanned`, not
      silently dropped.

### Manual IMAP tools

```bash
# Implicit TLS
openssl s_client -connect localhost:1993

# STARTTLS
openssl s_client -starttls imap -connect localhost:1143

# After +OK greeting on 1143:
a1 CAPABILITY
a2 STARTTLS
# reconnect TLS socket, then:
a3 LOGIN user@yourdomain.test 'password'
a4 SELECT INBOX
```

---

## Full-stack / integration checks

With `bin/dev` or the in-process integration harness:

- [ ] Inbound MX → message in INBOX via IMAP with correct `Received` /
      `X-MailOnRails-Client-Ip` trace headers.
- [ ] Authenticated submission → row in `smtp_outbound_messages` with
      `mail_from` equal to authenticated identity, not client envelope.
- [ ] Failed SMTP/IMAP AUTH → row in `auth_attempts` with correct `source`.
- [ ] `/metrics` returns **404** without `METRICS_TOKEN`.
- [ ] Admin **banned IP** list blocks new connections (`SMTP_DENYLIST_FILE`).

```bash
bin/rails test test/integration/pen_test.rb
bin/rails test test/integration/in_process_servers_test.rb
```

---

## TLS audit (staging with real certificates)

```bash
testssl.sh --starttls smtp staging.example.com:587
testssl.sh staging.example.com:993
nmap -sV -p 25,143,465,587,993 staging.example.com
```

Check: no SSLv3/TLS1.0, sensible cipher order, valid chain, OCSP stapling if
expected.

---

## What not to do

- Do not run untuned `hydra` or `nmap --script brute` against production — you
  will mostly trigger your own tarpit and lockout.
- Do not use real malware binaries; **EICAR** is the standard safe test pattern.
- Do not treat green scanner output as a substitute for protocol-aware manual
  sessions — custom servers need hand-crafted state-machine probes.

---

## Reporting template

For each finding:

1. **Title** — e.g. "Submission accepts MAIL FROM ≠ AUTH identity"
2. **Severity** — Critical / High / Medium / Low / Informational
3. **Environment** — hostname, port, commit SHA
4. **Steps to reproduce** — exact wire dialogue or command
5. **Expected vs actual**
6. **Evidence** — redacted trace/log snippet
7. **Regression test** — path to new test file if added
