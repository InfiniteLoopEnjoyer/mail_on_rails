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

> **The SMTP edge does not use a store.** It is the external
> [`mail_on_rails_exim`](https://github.com/InfiniteLoopEnjoyer/mail_on_rails_exim)
> service — an Exim MTA that terminates SMTP and reaches this app over
> plain HTTP, not through a store object. Its contract with the app is the
> **[HTTP edge contract](#the-http-edge-contract-exim)** below, and the
> trust-boundary details (header stamping, forged-header stripping) live in
> that repo's README. The store abstraction remains only for IMAP, where the
> daemon runs in-process (dev) or as its own service and genuinely needs a
> database-free seam.

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

### `authenticate(email, password)`

Check credentials against the account base.

Returns `{ account_id:, email: }` — both non-nil on success (`email`
normalized as stored), both nil on failure (unknown account, wrong
password). Email lookup is case-insensitive and ignores surrounding
whitespace.

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

Include `MailOnRails::Imap::Store::Contracts::Imap` (from the gem) in a
Minitest class, provide `build_store(**limits)` and
`create_account(email:, password:)`, and the suite asserts everything
above that is observable through the interface.

## The HTTP edge contract (exim)

The `mail_on_rails_exim` service does not use a store — it POSTs directly
to three app endpoints. This is the app's side of that contract; the
`mail_on_rails_exim` README is authoritative for what exim sends and the
trust boundary it enforces.

- **Relay ingress** (`config.action_mailbox.ingress = :relay`,
  authenticated with `action_mailbox.ingress_password`). Every inbound
  message exim accepts is POSTed here as raw RFC822. Exim has already
  **stripped any forged `X-Original-To` / `Return-Path` / `X-MailOnRails-*`
  headers and stamped the authoritative values** the live SMTP connection
  knows (`Return-Path`, one `X-Original-To` per envelope recipient,
  `X-MailOnRails-Authenticated`, `X-MailOnRails-Client-Ip`,
  `X-MailOnRails-Helo`). `MailroomMailbox` trusts exactly those headers to
  route recipients and to feed the app-side checks — SPF/DKIM/DMARC via the
  rspamd accessory (`MailOnRails::RspamdAnalyzer`, using the stamped IP /
  HELO / envelope sender) and virus scanning via ClamAV
  (`MailOnRails::ClamavScanner`). Exim itself does neither.

- **`POST mail_on_rails/internal/authenticate`** (basic-auth'd with
  `mail_on_rails.internal_api_password`, or the `SMTP_INTERNAL_API_PASSWORD`
  env fallback). Exim's AUTH check calls this; a 2xx with a non-null
  `account_id` grants the login. Backed by the same account base as the
  IMAP store's `authenticate`.

- **`POST mail_on_rails/internal/outbound_messages`** (same auth). Remote
  recipients of an authenticated submission are queued here for the app to
  DKIM-sign and deliver; the sender is forced to the authenticated
  identity. A `507` tells exim its outbound queue is full so it retries;
  a `4xx` bounces.

See `MailOnRails::InternalController` for the endpoint implementations.
