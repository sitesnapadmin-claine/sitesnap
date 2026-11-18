# Database backups

A Railway cron service (`db-backup`, root directory `backup`) runs `backup.sh` every night at 03:00 UTC:

1. `pg_dump` over Railway's private network. The database is never exposed to the internet.
2. The dump is compressed and encrypted with AES-256, using `BACKUP_PASSPHRASE`.
3. It's uploaded to the Cloudflare R2 bucket:
   - `daily/` copies are deleted after 30 days by an R2 lifecycle rule.
   - On the 1st of each month a copy also goes to `monthly/`, kept for a year.

If a run fails, it emails `ALERT_TO`.

## Variables on the db-backup service

| Variable | Value |
|---|---|
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` (reference) |
| `R2_ACCOUNT_ID` | Cloudflare account ID |
| `R2_BUCKET` | `sitesnap-backups` |
| `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | R2 API token with Object Read & Write on that bucket only |
| `BACKUP_PASSPHRASE` | Long random secret. **Keep a copy in your password manager**: without it the backups can't be opened |
| `RESEND_API_KEY`, `ALERT_FROM`, `ALERT_TO` | Optional failure email: `${{sitesnap.RESEND_API_KEY}}`, `${{sitesnap.RESET_FROM_EMAIL}}`, your inbox |

## Restoring

1. Download a file from the R2 bucket in the Cloudflare dashboard.
2. Decrypt and load it into an empty database. Use OpenSSL 1.1.1 or newer, or LibreSSL 3.1 or newer:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in sitesnap-<date>.sql.gz.enc | gunzip > sitesnap.sql
psql "<DATABASE_URL of the empty database>" < sitesnap.sql
```

`openssl` asks for the passphrase.
