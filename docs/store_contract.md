# The store contract

The IMAP server (the `mail_on_rails_imap` gem, extracted to a sibling repo)
never touches the database (or Rails) directly. It is constructed with a
**store** and talks to the world only through it. This document is the
contract that store must honor; the executable version is the shared test
suite the gem carries (`MailOnRails::Imap::Store::Contracts`), which runs
against the gem's production store (`Store::Http`, HTTP-backed — the daemon
holds no database credentials), this app's Active Record adapter behind the
imap endpoints (`MailOnRails::Store::ImapBackend`), and the gem's
dependency-free reference implementation (`MailOnRails::Imap::Store::Memory`).

> **The in-process SMTP server has a store contract of its own**
> (`MailOnRails::Smtp::Store::Contracts::Smtp`, in
> `lib/mail_on_rails/smtp/store/contracts.rb`), honored by the Active
> Record implementation `MailOnRails::Store::SmtpBackend` and the
> dependency-free `MailOnRails::Smtp::Store::Memory`. The trust-boundary
> details (header stamping, forged-header stripping) live with the
> backend and its tests
> (`test/lib/mail_on_rails/store/smtp_stamping_test.rb`).

## Ground rules

- **Plain values only.** Every return is built from hashes, arrays,
  strings, integers, and nil — never Active Record objects. Symbol keys.
- **Error envelope.** A method that fails returns
  `{ error: "<human message>", code: <symbol> }` instead of its normal
  shape. Every method may return `code: :internal` for unexpected
  failures; method-specific codes are listed below. Stores must not raise
  into protocol code.
- **Thread safety.** Stores are called concurrently from many connection
  threads. Implementations must be safe under concurrent calls.
- **Blocking is fine.** Calls run inline on the connection thread; there
  is no async contract.

## IMAP store interface

### `log(level, message)`

Route a message to the host's logging. `level` is a symbol
(`:debug`/`:info`/`:warn`/`:error`). Returns nil. Must never raise.

### `authenticate(email, password, ip: nil, source: nil)`

Check credentials against the account base. `ip` is the mail client's
address as the edge saw it, used for throttling (below); it is optional,
and a store must behave sanely without it. `source` names the calling
edge (`"imap"`/`"smtp"`) for the app's attempt log; it must never affect
the verdict, and a store is free to ignore it.

Returns `{ account_id:, email: }` — both non-nil on success (`email`
normalized as stored), both nil on failure (unknown account, wrong
password). Email lookup is case-insensitive and ignores surrounding
whitespace. A throttled attempt returns
`{ account_id: nil, email: nil, throttled: true, retry_after: <seconds> }`.

`account_id` below is the id returned by `authenticate`. `mailbox_id`
comes from `select_mailbox`. Mailbox name matching: `INBOX` is
case-insensitive (per RFC 3501); all other names are exact. A new account
has at least `INBOX`.

Flags are arrays of IMAP system-flag strings (`"\\Seen"`, `"\\Deleted"`,
…), stored per message, order not significant.

### Brute-force throttling

A store must refuse credential checks for an address or an account that
has failed too often, in two independent scopes: per source IP and per
account. This is separate from any per-connection cap the protocol server
applies — that one bounds a single connection, this one bounds an
attacker who hangs up and dials again, which is the only bound that
actually matters.

Requirements, in the order they matter:

- Once throttled, **the correct password is still refused.** Otherwise an
  attacker who guesses right on attempt 500 still wins.
- The check runs **before** the password comparison, so a blocked caller
  costs an indexed lookup rather than a KDF. This is a CPU-exhaustion
  control as much as a credential-guessing one.
- `scram_credentials` is refused the same way. Salt and iteration count
  are all a SCRAM client receives before proving anything, and they are
  enough to grind a password offline.
- Throttling is scoped: blocking one identity must not lock out everyone
  else, or the control becomes a denial-of-service tool.
- A successful login clears that **account's** counter. The IP counter is
  left alone, so one lucky guess doesn't restore an attacker's budget.
- Attempts made *during* a block must not extend it, or an attacker could
  pin a shared address (or someone else's account) indefinitely.
- Serving a block restores the full budget, rather than leaving the
  counter at the limit where the next failure re-blocks immediately —
  that difference is a throttle versus an endless lockout for a user
  whose own device is retrying a stale password.
- A refused attempt is not counted in either scope. Hammering an
  already-blocked account must not climb the source's counter (one
  target, nearly always a stale client, and escalating to an address
  block would hit everyone else behind it), and a blocked source must
  not be able to push accounts toward blocks (that would turn the
  throttle into a lockout tool). The scopes still trip independently
  across *different* targets, which is what stops a blocked account
  being used as a shield: every fresh address is adjudicated normally
  and feeds the address counter.

Limits, windows and block durations are the implementation's to choose;
the contract suite discovers them rather than assuming any. The app's
implementation is `AuthThrottle` (counters in the database, so the IMAP
daemon's worker Ractors and the in-process SMTP server share one budget
and it survives a restart); `Store::Memory` mirrors the semantics in a
Hash.

### `record_auth_failure(email, ip: nil, source: nil)`

Count one failed credential check that the store did not adjudicate
itself. SCRAM proofs are verified in the daemon against verifier
material, so the store never sees those failures — without this, SCRAM
would be an unthrottled path around the `authenticate` throttle. Returns
`{}`.

### `scram_credentials(email, ip: nil)`

SCRAM-SHA-256 verifier material (RFC 5802/7677) for the daemon's
AUTHENTICATE exchange: `{ account_id:, email:, salt_base64:,
iterations:, stored_key_base64:, server_key_base64: }`. Never returns
the password. `code: :notfound` for unknown accounts or accounts whose
credentials haven't been derived (the app derives them at
password-set time; bcrypt digests can't be converted). Returns
`{ throttled: true, retry_after: }` instead of any material when the
caller is throttled.

### `list_mailboxes(account_id)`

`{ mailboxes: [<name>, ...] }`, sorted by name.

### `create_mailbox(account_id, name)`

`{}` on success. `code: :exists` if a mailbox by that name exists
(including `inbox` vs `INBOX`).

### `delete_mailbox(account_id, name)`

`{}` on success, removing the mailbox and its messages (not its
children in the `/` hierarchy — RFC 3501 DELETE is exact-name).
`code: :notfound` for an unknown mailbox. The IMAP server refuses
`DELETE INBOX` before calling this.

### `rename_mailbox(account_id, from, to)`

`{}` on success. Renames the mailbox **and** every child under
`from/` in the `/` hierarchy, keeping messages and UIDs intact.
`code: :notfound` for an unknown source, `code: :exists` when the
target name is taken. The IMAP server refuses `RENAME INBOX` before
calling this.

### `select_mailbox(account_id, name)`

`{ mailbox_id:, name:, uid_validity:, uid_next:, highest_modseq:,
messages: [[uid, flags, modseq], ...] }` with messages in ascending UID
order and `name` in its stored form. `code: :notfound` for an unknown
mailbox.

UID semantics (RFC 3501): UIDs start at 1 per mailbox, strictly ascend,
and are never reused; `uid_next` is the UID the next stored message will
receive; `uid_validity` is fixed at mailbox creation.

Modseq semantics (RFC 7162 CONDSTORE): every content mutation — delivery,
flag change, expunge — claims the mailbox's next mod-sequence;
`highest_modseq` never regresses and is always ≥ every message's
`modseq`. Per-message modseqs ascend with delivery order.

### `status(account_id, name)`

`{ messages:, unseen:, uid_next:, uid_validity:, highest_modseq: }`
(counts as integers; `unseen` = messages without `\Seen`).
`code: :notfound` for an unknown mailbox.

### `fetch(mailbox_id, uids, with_raw)`

`{ messages: [{ uid:, flags:, internal_date:, size:, modseq: }, ...] }`
in ascending UID order, silently skipping unknown UIDs (an unknown
`mailbox_id` yields an empty list). `internal_date` is a Unix epoch
integer; `size` the stored byte size. When `with_raw` is true each entry
also carries `raw:` with the full stored message bytes.

### `store_flags(mailbox_id, uids, mode, flags)`

Mode `"+"` adds, `"-"` removes, `"="` replaces. Returns
`{ messages: [[uid, new_flags, modseq], ...] }` for each matched message,
where `modseq` reflects the flag change just applied.

### `append(account_id, mailbox_name, raw, flags, internal_date_epoch)`

Store a message. Bare LFs in `raw` are normalized to CRLF before storage;
`size` reflects the normalized bytes. `internal_date_epoch` nil means a
server-chosen default (the Active Record store falls back to the
message's Date header, then now). Returns `{ uid:, uid_validity: }`.
`code: :notfound` for an unknown mailbox.

The app's adapter additionally virus-scans `raw` (on by default —
`SMTP_CLAMAV_ADDR` defaults to the clamav accessory, `""` disables):
an infected upload is refused
with `code: :infected` (the IMAP server renders any error envelope as
`NO APPEND failed: <error>`); a scanner outage stores the message in
place flagged `unscanned` rather than refusing — the client is an
authenticated user writing their own Sent/Drafts copies.

### `expunge(mailbox_id, uids = nil)`

Permanently removes messages flagged `\Deleted`. With `uids: nil` every
`\Deleted` message goes; with a uid list (UID EXPUNGE, RFC 4315) removal
is restricted to `\Deleted` messages whose uid is in the list — listed
uids without `\Deleted` are ignored. Returns
`{ uids: [<removed uid>, ...] }` in ascending order (empty when nothing
was flagged).

### `copy(mailbox_id, uids, dest_name)`

Copy messages (bytes, flags, internal date) into `dest_name` on the same
account, assigning fresh UIDs in the destination. Returns
`{ uid_validity:, src_uids:, dest_uids: }` (`uid_validity` of the
destination; the two uid arrays correspond pairwise, ascending source
order). `code: :notfound` for an unknown destination.

### `move(mailbox_id, uids, dest_name)`

Like `copy`, but atomically removes the source messages in the same
operation (RFC 6851 MOVE) — a failure must leave each message in
exactly one mailbox. Same return shape and `:notfound` semantics as
`copy`.

### `expunged_since(mailbox_id, since_modseq)`

QRESYNC (RFC 7162): `{ uids: [...], complete: bool }` — the uids
expunged (by expunge or move) after `since_modseq`, from per-mailbox
tombstones. Tombstone history is bounded; when `since_modseq` predates
the retained history the store must return `complete: false` with the
over-approximation of every uid ever allocated but no longer present
(correct because uids are never reused). An unknown mailbox yields
`{ uids: [], complete: true }`.

## Conformance

Include `MailOnRails::Imap::Store::Contracts::Imap` (from the gem) in a
Minitest class, provide `build_store(**limits)` and
`create_account(email:, password:)`, and the suite asserts everything
above that is observable through the interface.

## The SMTP trust boundary

Inbound mail enters Action Mailbox through `SmtpBackend#smtp_store`, which
**strips any forged `X-Original-To` / `Return-Path` / `X-MailOnRails-*`
headers and stamps the authoritative values** the live SMTP connection
knows (`Return-Path`, one `X-Original-To` per envelope recipient,
`X-MailOnRails-Authenticated`, `X-MailOnRails-Client-Ip`,
`X-MailOnRails-Helo`). `MailroomMailbox` trusts exactly those headers to
route recipients and to feed the app-side checks — SPF/DKIM/DMARC via the
rspamd accessory (`MailOnRails::RspamdAnalyzer`, using the stamped IP /
HELO / envelope sender) and virus scanning via ClamAV
(`MailOnRails::ClamavScanner`). The SMTP session's own connection-time
SPF/DKIM/DMARC results stay a connection-time gate and are deliberately
not forwarded as headers; the mailroom recomputes every verdict itself.
