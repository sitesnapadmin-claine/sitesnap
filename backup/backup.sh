#!/bin/sh
# Dumps the SiteSnap database, compresses and encrypts it, and uploads it to R2.
# Daily copies go to daily/ (R2 deletes them after 30 days); on the 1st of each
# month a copy also goes to monthly/ (kept for a year).
set -eu
set -o pipefail

need() { eval "v=\${$1:-}"; [ -n "$v" ] || { echo "Missing variable $1" >&2; exit 2; }; }
for v in DATABASE_URL R2_ACCOUNT_ID R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY R2_BUCKET BACKUP_PASSPHRASE; do need "$v"; done

# Email the owner if anything below fails (optional, uses the app's Resend settings)
alert() {
  [ -n "${RESEND_API_KEY:-}" ] && [ -n "${ALERT_FROM:-}" ] && [ -n "${ALERT_TO:-}" ] || return 0
  curl -fsS https://api.resend.com/emails -H "Authorization: Bearer $RESEND_API_KEY" -H 'Content-Type: application/json' \
    -d "{\"from\":\"$ALERT_FROM\",\"to\":[\"$ALERT_TO\"],\"subject\":\"SiteSnap: the nightly database backup failed\",\"html\":\"<p>The backup job on Railway failed. Open the db-backup service in Railway and check its latest run.</p>\"}" >/dev/null || true
}
trap 'status=$?; [ "$status" -eq 0 ] || alert' EXIT

STAMP=$(date -u +%Y-%m-%dT%H-%M-%SZ)
NAME="sitesnap-$STAMP.sql.gz.enc"
FILE="/tmp/$NAME"

echo "Dumping database…"
pg_dump --no-owner --no-privileges "$DATABASE_URL" \
  | gzip -9 \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_PASSPHRASE -out "$FILE"

SIZE=$(wc -c < "$FILE")
[ "$SIZE" -gt 1000 ] || { echo "Backup is suspiciously small ($SIZE bytes)" >&2; exit 1; }

export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" AWS_DEFAULT_REGION=auto
# R2 doesn't support every checksum newer AWS CLIs send by default
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
ENDPOINT="https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com"

aws s3 cp "$FILE" "s3://$R2_BUCKET/daily/$NAME" --endpoint-url "$ENDPOINT" --only-show-errors
if [ "$(date -u +%d)" = "01" ]; then
  aws s3 cp "$FILE" "s3://$R2_BUCKET/monthly/$NAME" --endpoint-url "$ENDPOINT" --only-show-errors
fi
rm -f "$FILE"
echo "Backup uploaded: $NAME ($SIZE bytes)"
