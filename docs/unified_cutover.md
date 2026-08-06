# Unified cutover runbook

The `unified` branch replaces the three-container stack (web + the
standalone SMTP edge + standalone IMAP) with one container: Puma runs the
web UI, Solid Queue, and the in-process SMTP/IMAP servers. The cutover is a teardown and
rebuild with a database dump/restore - not an in-place migration.

## Before

1. Dump all four production databases from the db accessory and pull the
   dumps off the host:

       ssh root@HOST 'docker exec mail_on_rails-db pg_dumpall -U mail_on_rails' > prod-$(date +%F).sql

   (Or per-database `pg_dump` if you prefer selective restores.)
2. Belt-and-suspenders: snapshot the Active Storage volume contents
   (`mail_on_rails_storage`) - named volumes survive `kamal remove`, so
   this is recovery insurance, not a required step.
3. `/etc/letsencrypt` is a host path and survives everything. Verify the
   mail cert is current: `ssh root@HOST 'certbot certificates'`.

## Teardown

From each repo's main-era checkout:

    (mail_on_rails, old branch)   bin/kamal remove -d prod
    (../<the SMTP edge repo>)     bin/kamal remove -d prod
    (../mail_on_rails_imap)       bin/kamal remove -d prod

`kamal remove` stops/deletes containers and the proxy but leaves named
volumes in place.

## Rebuild

From the `unified` branch:

    bin/kamal setup -d prod

- The proxy boots stock kamal-proxy (443/80 only); the app container
  publishes 25/587/465/143/993 itself.
- The entrypoint runs `db:prepare` (recreates empty databases if the db
  volume was wiped; no-op otherwise) and `banned_ips:sync`.
- `/up` stays down until both mail listeners are bound, so the deploy
  only reports healthy when every protocol is live.

## Restore

    ssh root@HOST 'docker exec -i mail_on_rails-db psql -U mail_on_rails postgres' < prod-DATE.sql
    bin/kamal app exec -d prod 'bin/rails mail_on_rails:banned_ips:sync'

Spot-check row counts (accounts, mailboxes, messages) in the console.

## Verify

- `swaks --to user@zipzipzoom.ca --server mail.zipzipzoom.ca` (inbound MX)
- `swaks --to elsewhere@example.com --server mail.zipzipzoom.ca:587 -tls
  --auth --auth-user user@zipzipzoom.ca` (submission -> outbound queue)
- IMAP login + IDLE from a real client (iOS Mail), then run a no-op
  `bin/kamal deploy -d prod` and watch: expect a short outage, the old
  container draining sessions, the client reconnecting cleanly.

## Deploy behavior from now on

Every deploy stops the old container before booting the new one
(.kamal/hooks/pre-app-boot - the host ports can't be shared), so expect
~20-40s where all protocols are down. SMTP senders retry per RFC, IMAP
clients reconnect, and the web UI returns once /up is healthy. If that
window ever grates, the kamal-proxy fork's TCP forwarding
(/home/deploy/kamal-proxy, commits c60aa52/e3ca46f) is the upgrade path:
the proxy would own the mail ports and hold connections across deploys,
at the cost of PROXY-protocol support in both listeners.
