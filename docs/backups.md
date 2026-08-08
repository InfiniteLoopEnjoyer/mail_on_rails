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

## Encryption

A dump holds every message body, all password digests, and the encrypted
DKIM/SCRAM/TOTP material - treat backup files as secrets. With
`DB_BACKUP_ENCRYPTION_KEY` set (generate once: `openssl rand -hex 32`,
store it as a Kamal secret next to the other deploy secrets), the job
streams the dump through AES-256-GCM and writes `.dump.enc` files; the
plaintext never touches disk. The key lives only in the container
environment while the ciphertext lives on the storage volume, so a leaked
volume snapshot or stolen disk no longer yields the mail store by itself.

Two consequences to plan for:

- **Escrow the key offsite** (password manager, secrets vault). Losing it
  means losing every backup; rotating it only affects future dumps, so
  keep old keys until their dumps age out.
- **Decrypt before pg_restore**:

  ```sh
  DB_BACKUP_ENCRYPTION_KEY=<64 hex> bin/db-backup-decrypt <file>.dump.enc
  ```

  `bin/db-backup-decrypt` is standalone (ruby + openssl, no Rails, no
  database), so it runs anywhere the ciphertext was copied to. It prints
  the output path (input minus `.enc`), refuses to overwrite, and fails
  loudly on a wrong key or tampered/truncated file (the GCM tag
  authenticates the whole stream).

Unset, the job writes plain `.dump` files as before (the development
default) and logs a warning at each production run.

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

3. **Decrypt if needed.** A `.dump.enc` file must be decrypted first
   (anywhere with ruby - the host works):

   ```sh
   DB_BACKUP_ENCRYPTION_KEY=<64 hex> bin/db-backup-decrypt <dump-file>.enc
   ```

4. **Restore into the postgres accessory.** The dump is custom-format, so
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

5. **Start the app:**

   ```sh
   bin/kamal app boot -d prod
   ```

   The entrypoint's `db:prepare` runs any migrations newer than the dump
   and recreates cache/queue/cable if they were lost. `/up` turns healthy
   only after the mail listeners are bound.

6. **Verify.** Sign in to the web UI, open an account with mail, and run
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
