# Database backups and restore

## What is backed up

`DatabaseBackupJob` (nightly at 01:30, `config/recurring.yml`) runs
`pg_dump --format=custom` against the **primary** database and writes the
dump to `DB_BACKUP_DIR` (default `storage/backups`, which in production is
the persistent `mail_on_rails_storage` volume - backups survive container
replacement). Dumps older than `DB_BACKUP_KEEP_DAYS` (default 14) are
pruned after each successful dump, never before one, so a failing pg_dump
cannot age the last good backup out.

Only the primary database is dumped, deliberately:

- **primary** holds everything that matters: accounts, aliases, domains
  (including encrypted DKIM keys), every mail message's raw bytes, users,
  settings, bans.
- **cache / queue / cable** are derived state. `bin/rails db:prepare`
  (which the container entrypoint runs at boot) recreates them empty; the
  queue's only durable payload, outbound mail, lives in the primary's
  `smtp_outbound_messages` table anyway.

Not covered by pg_dump: the TLS certificates (`/etc/letsencrypt` on the
host, reissuable via certbot) and the banned-ips file on the `mailconf`
volume (regenerated from the primary's `banned_ips` table by `bin/kamal
app exec --reuse "bin/rails runner 'BannedIpsFile.sync!'"` or the
Settings page's Sync button).

## Taking a backup by hand

```sh
bin/kamal backup -d prod          # runs bin/db-backup in the app container
```

It prints the dump path, e.g.
`/rails/storage/backups/mail_on_rails_production-20260806T013000Z.dump`.

## Getting backups off the machine

A backup on the same disk protects against bad deploys and fat fingers,
not against losing the machine. Copy the directory offsite on your own
schedule; the dumps are plain files, so anything works:

```sh
# from the deploy workstation / a backup host
rsync -av --delete deploy@mail-host:/var/lib/docker/volumes/mail_on_rails_storage/_data/backups/ ./offsite-backups/
```

(Adjust the volume path if `docker volume inspect mail_on_rails_storage`
says otherwise.)

## Restore runbook

Scenario: restore the primary database from a dump onto a running
deployment. Expect full mail downtime for the duration (SMTP senders
retry; nothing is lost upstream).

1. **Stop the app** so nothing writes mid-restore:

   ```sh
   bin/kamal app stop -d prod
   ```

2. **Pick the dump.** List what exists on the host:

   ```sh
   ls /var/lib/docker/volumes/mail_on_rails_storage/_data/backups/
   ```

3. **Restore into the postgres accessory.** The dump is custom-format, so
   `pg_restore --clean` drops and recreates the objects inside the
   existing database:

   ```sh
   docker exec -i mail_on_rails-db \
     pg_restore --username mail_on_rails --dbname mail_on_rails_production \
                --clean --if-exists --no-owner \
     < /var/lib/docker/volumes/mail_on_rails_storage/_data/backups/<dump-file>
   ```

   For a brand-new postgres accessory (machine rebuilt): boot the app once
   so `db:prepare` creates the four empty databases, stop it again, then
   run the same pg_restore.

4. **Start the app:**

   ```sh
   bin/kamal app boot -d prod
   ```

   The entrypoint's `db:prepare` runs any migrations newer than the dump
   and recreates cache/queue/cable if they were lost. `/up` turns healthy
   only after the mail listeners are bound.

5. **Verify.** Sign in to the web UI, open an account with mail, and run
   `bin/kamal backup -d prod` once so the newest backup postdates the
   restore. If bans were lost with the machine, resync the file from the
   Settings page.

## Restoring a single account or message

Custom-format dumps restore selectively into a scratch database without
touching production:

```sh
createdb scratch_restore
pg_restore --dbname scratch_restore --no-owner <dump-file>
psql scratch_restore   # dig out what you need (email_messages.raw etc.)
```
