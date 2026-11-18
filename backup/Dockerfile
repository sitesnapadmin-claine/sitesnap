# Nightly encrypted database backup to Cloudflare R2.
# Runs as its own Railway cron service (root directory: backup). pg_dump must be
# at least the server's version, so keep this in step with Railway's Postgres (18).
FROM postgres:18-alpine
RUN apk add --no-cache aws-cli openssl curl
COPY backup.sh /backup.sh
RUN chmod +x /backup.sh
# Replace the image's entrypoint, which would start a database server
ENTRYPOINT ["/backup.sh"]
