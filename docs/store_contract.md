# The store contract

The SMTP and IMAP servers (the `mail_on_rails_smtp` / `mail_on_rails_imap`
gems, extracted to sibling repos) never touch the database (or Rails)
directly. Each server is constructed with a **store** and talks to the
world only through it. This document is the contract a store must honor;
the executable version is the shared test suite each gem carries
(`MailOnRails::Smtp::Store::Contracts` / `MailOnRails::Imap::Store::Contracts`),
which runs against the gems' production stores (`Store::Http`, HTTP-backed
- the daemons hold no database credentials), this app's Active Record
adapter behind the imap endpoints (`MailOnRails::Store::ImapBackend`), and
each gem's dependency-free reference implementation
(`MailOnRails::Smtp::Store::Memory` / `MailOnRails::Imap::Store::Memory`).

Servers depend only on the interface they need: the SMTP server takes any
object satisfying the **SMTP store** interface, the IMAP server the
**IMAP store** interface. This split is deliberate — it is the future
database-privilege boundary (an SMTP daemon whose credentials cannot read
mailboxes, an IMAP daemon that cannot touch the spool).

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

## Shared interface (both protocols)

### `log(level, message)`

Route a message to the host's logging. `level` is a symbol
(`:debug`/`:info`/`:warn`/`:error`). Returns nil. Must never raise.

### `authenticate(email, password)`

Check credentials against the account base.

Returns `{ account_id:, email: }` — both non-nil on success (`email`
normalized as stored), both nil on failure (unknown account, wrong
password). Email lookup is case-insensitive and ignores surrounding
whitespace.

## SMTP store interface

Construction accepts `outbound_limit:` (integer) so capacity behavior is
testable; the production default comes from `MAIL_ON_RAILS_OUTBOUND_LIMIT`.
Implementations may bound inbound acceptance however they like (the app's
adapter hands inbound mail to an HTTP ingress and surfaces its failures
as the `:internal` envelope; the memory store keeps a `spool_limit:`
cap).

### `local_rcpts(addresses)`

Given candidate recipient addresses, returns
`{ local: [<normalized email>, ...] }` — the subset that maps to a real
local account. Matching is case- and whitespace-insensitive; the returned
strings are the normalized forms.

### `smtp_store(mail_from, rcpt_to, data, authenticated_as, auth_results: nil, scan_status: nil)`

Accept a message. `rcpt_to` is split into local recipients (handed to the
host's inbound delivery pipeline, with the full local recipient list) and
remote recipients (queued one entry per recipient for outbound delivery,
sender recorded as `authenticated_as`).

`authenticated_as` (nil or the authenticated account's email),
`auth_results` (an Authentication-Results-style string, or nil), and
`scan_status` (`"clean"` when a virus scan ran, nil when scanning is
disabled) **must travel with the message bytes, beyond the sender's
reach** — this trust stamp is how the rest of the system distinguishes
verified from potentially spoofed mail, and scanned from unscanned mail.
(The app's adapter stamps them as `X-MailOnRails-*` headers after
stripping any forged copies from the submitted data; see
`MailOnRails::Smtp::IngressClient`.)

Returns `{ id:, outbound: }` — `id` a non-nil identifier for the accepted
inbound message (an implementation-chosen placeholder when there were
only remote recipients), `outbound` the number of remote recipients
queued.

Errors:
- `code: :relay_denied` — remote recipients present and
  `authenticated_as` is nil. Nothing is stored.
- `code: :insufficient_storage` — accepting would exceed `outbound_limit`
  pending outbound entries (or an implementation-defined inbound cap).
  Nothing is stored.
- `code: :internal` — the inbound pipeline is unavailable (e.g. the
  ingress endpoint is down). The session answers 451 and the sending
  server retries; SMTP's retry schedule is the durability buffer.

### `quarantine(mail_from, rcpt_to, data, authenticated_as, auth_results:, scan_status:, virus: nil)`

Best-effort delivery of an infected (`scan_status: "infected"`, `virus`
naming the clamd signature) or unscanned (`"unscanned"`) message copy for
review, after the SMTP session already refused the sender (550/451 —
decided by the scan verdict alone, never by this call's outcome). Targets
the local recipients, falling back to the authenticated sender's own
account for remote-only submissions. Always returns nil and never raises:
a lost review copy is logged, not surfaced. The app files these copies
into the account's Quarantine mailbox, deduped by Message-ID (a 451 makes
the sender retry the same message repeatedly).

## IMAP store interface

`account_id` below is the id returned by `authenticate`. `mailbox_id`
comes from `select_mailbox`. Mailbox name matching: `INBOX` is
case-insensitive (per RFC 3501); all other names are exact. A new account
has at least `INBOX`.

Flags are arrays of IMAP system-flag strings (`"\\Seen"`, `"\\Deleted"`,
…), stored per message, order not significant.

### `list_mailboxes(account_id)`

`{ mailboxes: [<name>, ...] }`, sorted by name.

### `create_mailbox(account_id, name)`

`{}` on success. `code: :exists` if a mailbox by that name exists
(including `inbox` vs `INBOX`).

### `select_mailbox(account_id, name)`

`{ mailbox_id:, name:, uid_validity:, uid_next:, messages: [[uid, flags], ...] }`
with messages in ascending UID order and `name` in its stored form.
`code: :notfound` for an unknown mailbox.

UID semantics (RFC 3501): UIDs start at 1 per mailbox, strictly ascend,
and are never reused; `uid_next` is the UID the next stored message will
receive; `uid_validity` is fixed at mailbox creation.

### `status(account_id, name)`

`{ messages:, unseen:, uid_next:, uid_validity: }` (counts as integers;
`unseen` = messages without `\Seen`). `code: :notfound` for an unknown
mailbox.

### `fetch(mailbox_id, uids, with_raw)`

`{ messages: [{ uid:, flags:, internal_date:, size: }, ...] }` in
ascending UID order, silently skipping unknown UIDs (an unknown
`mailbox_id` yields an empty list). `internal_date` is a Unix epoch
integer; `size` the stored byte size. When `with_raw` is true each entry
also carries `raw:` with the full stored message bytes.

### `store_flags(mailbox_id, uids, mode, flags)`

Mode `"+"` adds, `"-"` removes, `"="` replaces. Returns
`{ messages: [[uid, new_flags], ...] }` for each matched message.

### `append(account_id, mailbox_name, raw, flags, internal_date_epoch)`

Store a message. Bare LFs in `raw` are normalized to CRLF before storage;
`size` reflects the normalized bytes. `internal_date_epoch` nil means a
server-chosen default (the Active Record store falls back to the
message's Date header, then now). Returns `{ uid:, uid_validity: }`.
`code: :notfound` for an unknown mailbox.

The app's adapter additionally virus-scans `raw` when a scanner is
configured (`SMTP_CLAMAV_ADDR`): an infected upload is refused
with `code: :infected` (the IMAP server renders any error envelope as
`NO APPEND failed: <error>`); a scanner outage stores the message in
place flagged `unscanned` rather than refusing — the client is an
authenticated user writing their own Sent/Drafts copies.

### `expunge(mailbox_id)`

Permanently removes messages flagged `\Deleted`. Returns
`{ uids: [<removed uid>, ...] }` in ascending order (empty when nothing
was flagged).

### `copy(mailbox_id, uids, dest_name)`

Copy messages (bytes, flags, internal date) into `dest_name` on the same
account, assigning fresh UIDs in the destination. Returns
`{ uid_validity:, src_uids:, dest_uids: }` (`uid_validity` of the
destination; the two uid arrays correspond pairwise, ascending source
order). `code: :notfound` for an unknown destination.

## Conformance

Include `MailOnRails::Smtp::Store::Contracts::Smtp` or
`MailOnRails::Imap::Store::Contracts::Imap` (from the respective gem) in a
Minitest
class, provide `build_store(**limits)` and
`create_account(email:, password:)`, and the suite asserts everything
above that is observable through the interface.
The trust-stamp persistence requirement is not observable through the
SMTP interface (it has no read side) and is covered by adapter-specific
tests instead.
