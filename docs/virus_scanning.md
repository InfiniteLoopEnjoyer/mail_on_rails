# Virus scanning (ClamAV)

Mail is scanned by a clamd daemon — the `clamav` Kamal accessory in
`config/deploy.yml` — reached over TCP 3310 on the shared `kamal` docker
network, by **two independent readers**:

1. **The in-process SMTP server, at DATA time** (`SMTP_CLAMAV_ADDR`,
   `SMTP_CLAMAV_TIMEOUT` seconds, default 10): infected mail is rejected
   with `550` *before acceptance* — the sender's own MTA carries the
   bounce, and the message never enters storage (a review copy is
   quarantined). Fails closed: a scanner outage defers with `451`
   (senders retry; no unscanned mail is accepted). Authenticated
   submissions are scanned too, so outbound malware is stopped before it
   is DKIM-signed.
2. **The mailroom, on ingress, and IMAP APPEND** (same env): a full
   rescan as defense in depth — the mailroom never trusts an inbound
   `X-MailOnRails-Scan`-style header (the SMTP session deliberately
   stamps no verdict, so a copy on the wire could only be forged).

Both stream the whole raw RFC822 message via clamd's INSTREAM protocol
(clamd decodes MIME itself, so attachments are covered). The app path is
**on by default**: the clamav accessory always boots before the app, so
`SMTP_CLAMAV_ADDR` defaults to `mail_on_rails-clamav:3310` (the
accessory's container name on the kamal docker network) and only needs
setting to override — `""` disables scanning. The test suite pins it to
`""`; in development the `clamav_dev` Puma plugin
(`lib/puma/plugin/clamav_dev.rb`) manages a local `clamav-dev` docker
container and repoints the env at it (or pins `""` when docker is
unavailable), so dev scanning works with no setup. One env var governs
both readers - there is no separate switch to fall out of sync.

## Policy

| Where | Verdict | Result |
| --- | --- | --- |
| SMTP DATA | infected | `550` to the sender, before acceptance — a review copy goes to Quarantine, nothing else is stored |
| SMTP DATA | scanner down | `451` (fail closed; sender retries, nothing skips scanning; an `unscanned` review copy goes to Quarantine, deduped across retries) |
| SMTP DATA | clean | accepted and routed through Action Mailbox |
| Action Mailbox (mailroom) | all inbound mail | rescanned locally; non-clean goes to Quarantine instead of INBOX; with scanning disabled here, DMARC report parsing is skipped until the recurring catch-up job scans late |
| IMAP APPEND (app) | infected | `NO APPEND failed: message rejected: virus detected (...)` |
| IMAP APPEND (app) | scanner down | stored in place flagged `unscanned` (a user's own Sent/Drafts must not vanish) |

App-side review copies land in the account's auto-created `Quarantine`
mailbox — visible in the web UI, hidden from IMAP `LIST`, deduped by
Message-ID across sender retries; a later clean delivery sweeps stale
`unscanned` copies (never `infected` ones). There are deliberately no
post-acceptance bounce emails: senders learn of rejection from their own
MTA (no backscatter). One extra gate rides on the app scan: mail to a
domain's `dmarc@` ingestion account is only parsed for aggregate reports
after a *clean local verdict* (plus sender verification) — see
`IngestDmarcReportJob` / `ScanPendingDmarcReportsJob`.

## Automated tests

Neither repo's suite needs ClamAV installed: both use a scripted
`FakeClamd` TCP server (`test/fake_clamd.rb` in the smtp gem,
`test/test_helpers/fake_clamd.rb` here) that speaks just enough INSTREAM
to script clean / infected / garbage / hang replies.

## Real-engine smoke (dev, manual)

The one thing the fakes can't prove is protocol fit against real clamd.
Run this once before deploying scanner changes (first boot downloads
~300 MB of signatures and takes minutes to turn healthy):

    docker run --rm -d --name clamav-smoke -p 3310:3310 \
      -v clamav-db:/var/lib/clamav clamav/clamav:1.4
    # wait until: docker inspect -f '{{.State.Health.Status}}' clamav-smoke → healthy

Build the EICAR test string at runtime — keep it out of files so desktop
AV doesn't eat your checkout (the two halves below are inert):

    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

- **SMTP path**: speak SMTP to the dev server's port (1025 by default)
  with the EICAR string as the body — expect `550 ... virus detected
  (Eicar-Signature)` after the final `.`. Stop the clamd container and
  resend: expect `451`.
- **Mailroom path**: automatic in development — booting the server starts (or
  reuses) the `clamav-dev` container via the `clamav_dev` Puma plugin and
  points `SMTP_CLAMAV_ADDR` at it, so the manual `docker run` above isn't
  needed. Submit an EICAR message through the Action Mailbox conductor at
  `/rails/conductor/action_mailbox/inbound_emails` — expect a Quarantine
  row with `virus_name` in the web UI instead of an INBOX delivery. The
  container is left running across server restarts (clamd cold starts are
  slow); `docker stop clamav-dev` reclaims its ~1.5 GB when done.

## Ops notes

- clamd needs ~3–4 GiB RAM (~1.5 GiB resident, briefly doubling during
  signature reloads): the deploy host needs ≥4 GB total. If tight, mount
  a clamd.conf with `ConcurrentDatabaseReload no` and/or set a docker
  `memory:` limit on the accessory.
- clamd's `StreamMaxLength` default is 25 MB; the SMTP server caps
  messages at 24 MB (`MAX_MESSAGE_BYTES`) precisely so a max-size message
  (plus the headers it adds) stays scannable on both the DATA and
  mailroom paths. If larger mail is ever needed, raise `StreamMaxLength`
  via a mounted clamd.conf *before* raising the message limit.
- **The DATA-time scan fails closed**: with `SMTP_CLAMAV_ADDR` set, a
  clamd outage (including its minutes-long cold start after a restart)
  defers all inbound and submission mail with `451` until clamd is
  healthy again — senders retry, nothing is lost, but keep the accessory
  healthy.
- The SMTP session stamps **no scan verdict**: the mailroom trusts no
  inbound scan header and always rescans locally, so a forged header on
  the wire can never skip the mailroom's own scan.
