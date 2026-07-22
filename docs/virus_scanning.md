# Virus scanning (ClamAV)

Inbound mail is scanned by a clamd daemon — the `clamav` Kamal accessory
in `config/deploy.yml` — reached over TCP 3310 on the shared `kamal`
docker network. Scanning is enabled wherever `MAIL_ON_RAILS_CLAMAV_ADDR`
(`host:port`) is set and disabled where it isn't; `MAIL_ON_RAILS_CLAMAV_TIMEOUT`
(seconds, default 10) bounds each scan. The whole raw RFC822 message is
streamed via clamd's INSTREAM protocol (clamd decodes MIME itself, so
attachments are covered).

## Policy

| Where | Verdict | Result |
| --- | --- | --- |
| SMTP DATA (daemon) | infected | `550 5.7.1` to the sender + stamped review copy quarantined |
| SMTP DATA (daemon) | scanner down | `451 4.7.1` (sender retries; nothing skips scanning) + `unscanned` review copy |
| SMTP DATA (daemon) | clean | accepted, stamped `X-MailOnRails-Scan: clean` (the app skips re-scanning) |
| Action Mailbox (app) | stampless mail | scanned locally; non-clean goes to Quarantine instead of INBOX |
| IMAP APPEND (app) | infected | `NO APPEND failed: message rejected: virus detected (...)` |
| IMAP APPEND (app) | scanner down | stored in place flagged `unscanned` (a user's own Sent/Drafts must not vanish) |

The scan verdict rides the same trusted stamped-header channel as
authentication (`X-MailOnRails-Scan` / `X-MailOnRails-Virus`; forged
copies are stripped at the ingress boundary). Review copies land in the
account's auto-created `Quarantine` mailbox — visible in the web UI,
hidden from IMAP `LIST`, deduped by Message-ID across sender retries; a
later clean delivery sweeps stale `unscanned` copies (never `infected`
ones). There are deliberately no post-acceptance bounce emails: senders
learn of rejection from their own MTA (no backscatter).

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

    MAIL_ON_RAILS_CLAMAV_ADDR=127.0.0.1:3310 bin/dev

Send the EICAR test string (build it at runtime — keep it out of files so
desktop AV doesn't eat your checkout; the two halves below are inert):

    ruby -e 'eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" \
                   + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
             require "net/smtp";
             Net::SMTP.start("127.0.0.1", 1025) { |s|
               s.send_message "Subject: eicar\r\n\r\n#{eicar}\r\n",
                              "probe@remote.test", "user@example.test" }'

Expect `550 5.7.1 ... (Eicar-Test-Signature)` and a Quarantine row with
`virus_name` in the web UI. Then `docker stop clamav-smoke` and resend:
expect `451 4.7.1` and a single `unscanned` Quarantine row. A clean
resend after restarting the container delivers to INBOX and sweeps it.

## Ops notes

- clamd needs ~3–4 GiB RAM (~1.5 GiB resident, briefly doubling during
  signature reloads): the deploy host needs ≥4 GB total. If tight, mount
  a clamd.conf with `ConcurrentDatabaseReload no` and/or set a docker
  `memory:` limit on the accessory.
- clamd's `StreamMaxLength` default (25 MB) equals the daemon's message
  cap; a message right at the cap may scan-fail and degrade to the
  451/unscanned path. Raise it via a mounted clamd.conf if that bites.
- Deploy order when rolling out scanner changes: app before smtp daemon
  (an old mailroom would file an `infected`-stamped copy into INBOX; the
  reverse direction is safe).
