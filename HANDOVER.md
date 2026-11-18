# SiteSnap handover

For whoever takes over development, including a rewrite in another language. It covers:

- how the current app works
- the security rules it follows today
- what must stay compatible so existing accounts, sites and payments keep working
- how to change things without breaking the live site

Written 18 November 2026. There are no real customers yet; the production database holds test data only.

---

## 1. Ground rules for working on it

1. **`main` is production.** Railway deploys every push to `main` to www.site-snap.app within about a minute. `main` is protected: changes go in through a pull request, and the GitHub tests must pass first.
2. **Use a staging copy for a rewrite.** In Railway, create a second environment with its own Postgres. Point it at a branch and test there. Never run a development build against the production database.
3. **Keep database changes additive** (new tables and columns) until the old app is retired. Before the first real customer, switch on the nightly backup (see section 9) and take a backup before any migration.
4. **Use your own logins.** Get your own access to GitHub, Railway, Cloudflare and PayPal developer, never shared passwords. When the handover is done, rotate the keys listed in section 8.

---

## 2. What runs where

| Piece | Where | Notes |
|---|---|---|
| App (API, marketing page, wizard, dashboard, customer sites) | Railway service `sitesnap`, project `humorous-flow` | Node 20–24, Express 4. Deploys from `main` |
| Database | Railway Postgres 18 (`postgres-volume`) | Private network only. Hobby plan, so no Railway backups |
| Images | Cloudinary | Uploads go to `sitesnap/`, resized to 1600px |
| Customer custom domains | Cloudflare for SaaS (custom hostnames) and Worker `sitesnap-domain-proxy` | See section 6 |
| Email sending | Resend, from an address on site-snap.app | Password reset, email confirmation, contact forms, admin alerts |
| Email receiving | Cloudflare Email Routing | `support@site-snap.app` forwards to sitesnap.admin@gmail.com |
| Payments | PayPal (live) | Stripe code is legacy and switched off |
| Errors | Sentry (`SENTRY_DSN`) | |
| Tests and uptime | GitHub Actions | `test.yml` runs on PRs and `main`; `uptime.yml` runs every 10 minutes |

DNS for site-snap.app is on Cloudflare, in the Cloudflare account owned by clainegross@gmail.com.

---

## 3. Code map

| File | What it does |
|---|---|
| `server.js` | Everything server-side: auth, uploads, sites, domains, billing, admin, legal pages, and the HTML generator for customer sites (`buildWebsite`) |
| `paypal.js` | PayPal checkout (Starter order, Pro subscription), return confirmation, webhook handling, the refund check |
| `cloudflare.js` | Custom hostnames through Cloudflare for SaaS, and reading the Worker's original-host header |
| `planlimits.js` | What happens when Pro ends: domains disconnect, then 7 days to delete extra sites, then the account is restricted |
| `public/index.html` | The whole front end: landing page, five-step wizard, live preview, dashboard, plan screen |
| `public/admin.html` | Admin dashboard at `/admin` |
| `tests/` | 151 Jest and Supertest tests (see section 7) |
| `backup/` | Not merged yet (PR #18): nightly encrypted backup to Cloudflare R2 |

### Routes

- **Auth:** `POST /api/auth/register`, `login`, `forgot-password`, `reset-password`, `set-password`, `resend-verification`
- **Account:** `GET /api/me`, `PUT /api/account/profile`, `DELETE /api/account`
- **Sites:**
  - create, list, read, update and delete: `POST /api/sites`, `GET /api/sites`, `GET|PUT|DELETE /api/sites/:uuid`
  - addresses: `POST /api/sites/:uuid/subdomain` (Starter), `POST /api/sites/:uuid/domain` (Pro), `GET /api/domain/dns-check`, `GET /api/domain/verify`
- **Uploads:** `POST /api/upload`
- **Billing:**
  - `POST /api/checkout/:plan`
  - `POST /api/billing/cancel`, `POST /api/billing/portal`
  - `POST /api/sync-plan`
  - `GET /billing/success`, `GET /billing/cancel`
- **Payment notifications:** `POST /api/paypal/webhook` (raw body, signature checked)
- **Contact forms on customer sites:** `POST /api/contact/:uuid` (form-encoded, then redirects back)
- **Admin:**
  - `POST /api/admin/login`, `forgot-password`, `reset-password`, `change-password`, `check-refunds`
  - `GET /api/admin/overview`, `GET /api/admin/customers`
  - pages: `/admin`, `/admin/reset-password`
  - `GET /api/_diag`: only for the account matching `ADMIN_EMAIL`
- **Public pages:** `/`, `/preview/:uuid`, `/terms`, `/privacy`, `/reset-password`, `/verify-email`, `/robots.txt`, `/sitemap.xml`
- **Front-end settings:** `GET /api/config` (which features are switched on, and the support email)
- **Customer domains and subdomains:** any request whose host is a customer's domain or subdomain gets that customer's site, before any of the routes above.

---

## 4. Security rules the current app follows

Each of these fixed a real problem found in the audits. A rewrite must keep every one. Most have tests in `tests/security.test.js`, `tests/prelaunch.test.js`, `tests/admin-password.test.js` and `tests/paypal-refunds.test.js`.

### Customer sites (built from what customers type)
- [ ] **Escape everything customers type** before putting it into HTML (`escHtml`). That includes names, text, links, the address, the hours and alt text.
- [ ] **Colours** must be exactly `#rgb` or `#rrggbb` (`safeColor`). Anything else falls back to the theme colour; nothing goes into CSS raw.
- [ ] **Image URLs** must be `http(s)` or a path on this server, with no characters that could break out of an attribute or a CSS `url()` (`safeImageUrl`). `javascript:` and `data:` are refused.
- [ ] **Button links** are checked the same way. A `mailto:` prefix typed by the user is normalised.
- [ ] **Customer sites contain no JavaScript at all.** They're served with a strict Content Security Policy (`SITE_CSP`): `script-src 'none'`, `default-src 'none'`, `base-uri 'none'`, `object-src 'none'`, and `form-action` limited to the app's own origin. Even if escaping failed somewhere, injected script couldn't run. The phone menu is CSS-only for this reason.
- [ ] **Site data is limited to 300 KB** (`siteDataProblem`).

### Uploads
- [ ] **The file type comes from the file's first bytes, never from the browser's claim** (`sniffImageType`). Only JPG, PNG, WebP and GIF are allowed. SVG is refused because it can carry script.
- [ ] **The saved name is random,** with the extension of the real type.
- [ ] **Limits:** 15 MB, plus a per-IP rate limit.
- [ ] **In production, uploads go to Cloudinary or fail.** Never fall back to the local disk, which Railway wipes on every deploy.

### Domains and hosts
- [ ] **Customers can never claim SiteSnap's own hosts as a custom domain or subdomain** (`isReservedHost`): site-snap.app and anything under it, the Railway domains, localhost, and the CNAME target. If a customer could claim one, that host would serve their page instead of the app.
- [ ] **Reserved subdomain labels can't be used:** www, app, api, admin, support, billing, login, mail, status, staging and others (`RESERVED_SUBDOMAINS`).
- [ ] **The original host from the Cloudflare Worker is trusted only with the shared secret.** It arrives in `X-Original-Host`, and is only believed when `X-Sitesnap-Edge` matches `EDGE_SECRET`. Otherwise anyone could set the header and pick which site they get.

### Accounts and sessions
- [ ] **Passwords** are hashed with bcrypt, at least 8 characters, at most 200.
- [ ] **Login tokens** are signed with `JWT_SECRET`. The app refuses to start in production without it.
- [ ] **Changing or resetting a password signs out every other device.** `users.token_version` is in the token as `tv`, and every request compares the two.
- [ ] **Reset and confirmation links:** only a SHA-256 hash of the token is stored. Reset links work once and expire after 1 hour.
- [ ] **Forgot password** gives the same answer whether or not the email has an account, so it can't be used to find out who has one.
- [ ] **Rate limits** apply to login, register, forgot and reset password, resending confirmation, uploads, contact forms, and admin login and reset.
- [ ] **Deleting an account** also deletes its sites and disconnects its custom domains.

### Admin
- [ ] **The admin password starts as `ADMIN_PASSWORD`.** Once it's changed or reset, a bcrypt hash in `admin_settings` replaces the environment variable. New passwords must be at least 12 characters.
- [ ] **Admin reset links go only to `ADMIN_EMAIL`** (or `SIGNUP_NOTIFY_EMAIL`), never to an address typed into the request. They work once and expire after 30 minutes.
- [ ] **Changing the admin password signs out all other admin sessions** (`session_version`).
- [ ] **The password check is timing-safe.**

### Payments
- [ ] **Every PayPal webhook is verified** with PayPal's `verify-webhook-signature` against `PAYPAL_WEBHOOK_ID` before anything is done with it.
- [ ] **A plan is only granted from PayPal's own data:** the capture amount must be exactly 29.00 USD, and the Pro plan ID must match. Nothing the browser sends is trusted.
- [ ] **Stripe routes only exist** when `PAYMENT_PROVIDER` isn't `paypal` and Stripe keys are set.

### General
- [ ] **Security headers on every response:** `nosniff`, `X-Frame-Options: SAMEORIGIN`, a Referrer-Policy, and HSTS over HTTPS. No `X-Powered-By`.
- [ ] **Async errors always reach the error handler** (`wrapAsync`). A failure returns a reply instead of a hanging request.
- [ ] **No secrets in the repository.** It's public, and the full history has been checked and is clean.

---

## 5. Data that must stay compatible

### Tables (Postgres in production, SQLite locally and in tests)

**`users`**
- `id`, `email` (unique, lower-case), `password_hash`, `name`
- Plan: `plan` (`free` / `starter` / `pro`)
- PayPal: `paypal_subscription_id`, `paypal_order_id`, `paypal_access_until`
- Stripe (legacy): `stripe_customer_id`, `stripe_subscription_id`
- Plan limits: `over_limit_deadline`
- Password reset: `reset_token_hash`, `reset_expires`
- Sessions: `token_version`
- Email confirmation: `email_verified`, `verify_token_hash`
- Activity: `last_seen_at`, `created_at`

**`sites`**
- `id`, `uuid` (public ID), `user_id`
- `data`: JSON text holding everything from the wizard
- Addresses: `subdomain`, `custom_domain`, `railway_domain_id`
- Stats and dates: `views`, `created_at`, `updated_at`

**`payments`**
- `id`, `user_id`, `provider`
- `kind`: `starter` / `pro` / `refund`
- `amount_cents` (refunds are negative), `currency`, `created_at`
- `external_id`: PayPal's ID, unique, used to stop duplicates
- `related_id`: on a refund, the payment it refunds

**`admin_settings`** (key and value)
- `password_hash`, `session_version`
- `reset_token_hash`, `reset_expires`
- `paypal_webhook_last_ok`, `paypal_webhook_last_rejected`, `paypal_refund_check`

### Things that would break existing accounts if changed
- **Password hashes** are bcrypt (`$2a$`/`$2b$`, cost 10, made by `bcryptjs`). The new language must verify them, or nobody can log in. Every mainstream bcrypt library can.
- **Hash placeholders:** a few old accounts have a placeholder hash that can never match. The app detects it (`isUsablePasswordHash`) and asks the user to set a password.
- **`email_verified`:** `NULL` means the account predates email confirmation and counts as confirmed. `0` means waiting, and `1` means confirmed.
- **`sites.data`** is a JSON object written by the wizard in `public/index.html`, and `buildWebsite` turns it into HTML. Its fields are the contract between the two. Any new renderer must read the same fields, or existing sites will change.
- **Login tokens** use HS256 with the claims `{ id, email, plan, tv }` and last 30 days. Changing the format just means everyone logs in again, which is acceptable.
- **`payments.external_id`** must stay unique. It's what stops a PayPal webhook and the refund check counting the same money twice.
- **Dates:** `paypal_access_until`, `last_seen_at` and the admin dates are ISO 8601 strings in UTC.

---

## 6. How the business rules work

### Plans
- **Free:** 1 site, preview link, and the "Built with SiteSnap" badge.
- **Starter ($29, one time):** no badge. Subdomains once `SUBDOMAINS_ENABLED`.
- **Pro ($12 a month):** unlimited sites and custom domains.
- **When Pro ends:** custom domains disconnect, and the customer gets 7 days to delete any sites over their limit. After that they can't edit or create sites until they do. Nothing is deleted automatically.

### PayPal
- **Starter** is a PayPal Order. The capture is checked to be 29.00 USD, with `custom_id` = `userId:starter`.
- **Pro** is a PayPal Subscription, with `custom_id` = `userId`.
- **Cancelling Pro** keeps Pro until the paid month ends (`paypal_access_until`). An hourly job ends expired plans, because PayPal doesn't send an event for that.

**Webhook events handled:**
- Subscriptions: `BILLING.SUBSCRIPTION.ACTIVATED`, `CANCELLED`, `EXPIRED`, `SUSPENDED`, `PAYMENT.FAILED`
- Payments: `PAYMENT.SALE.COMPLETED`, `PAYMENT.SALE.REFUNDED`, `PAYMENT.CAPTURE.COMPLETED`, `PAYMENT.CAPTURE.REFUNDED`
- Disputes: `CUSTOMER.DISPUTE.CREATED`

**Refunds:**
- A full Starter refund puts the customer back on Free.
- A refunded Pro payment leaves Pro on and emails the owner to decide.
- A dispute emails the owner.
- Every 6 hours the app also asks PayPal about recent payments, in case a refund notice was missed. The admin page has a button for the same check.

### Custom domains
- The customer points a CNAME at `CF_CNAME_TARGET`. The app creates a Cloudflare custom hostname, and Cloudflare issues the certificate.
- Traffic goes through the Worker `sitesnap-domain-proxy`, which forwards to Railway with `X-Original-Host` and `X-Sitesnap-Edge`.
- There's a fallback through the Railway domain API (`RAILWAY_*` variables) if Cloudflare isn't configured.

### Email
- Email only switches on when both `RESEND_API_KEY` and `RESET_FROM_EMAIL` are set. Until then, reset, confirmation and contact forms are hidden rather than half-working.
- Replies go to `SUPPORT_EMAIL` (default support@site-snap.app).
- Admin alerts go to `SIGNUP_NOTIFY_EMAIL`.

### Visit counts
`sites.views` counts visits to customer sites, skipping bots and visits that come from the app itself.

---

## 7. Using the tests as a specification

The tests use Supertest against the Express app, so they describe behaviour over HTTP: status codes, JSON fields and HTML content. For a rewrite:

1. Keep this repo's tests running against the old app as the reference.
2. Port them to drive the new server over HTTP (Supertest can target a URL instead of the app object), or translate them into the new language's test framework.
3. Treat a missing or failing security test as a blocker for switching over.

Run them:

```bash
npm install
npm test
```

PayPal, Resend and Cloudflare calls are mocked in the tests, so no keys are needed.

---

## 8. Environment variables and keys to rotate after handover

The full list with notes is in `.env.example`. Production values are set in Railway under the `sitesnap` service, Variables. Rotate these once the handover is done, and whenever anyone with access leaves:

- `JWT_SECRET`: signs everyone out, which is harmless
- `ADMIN_PASSWORD`, or change the password from the admin page
- `PAYPAL_CLIENT_SECRET`
- `CLOUDINARY_API_SECRET`
- `RESEND_API_KEY`
- `CLOUDFLARE_API_TOKEN`, `EDGE_SECRET` (update the Worker at the same time), `RAILWAY_API_TOKEN`
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`: unused. Delete them, and the Stripe code, if Stripe isn't coming back

---

## 9. Open items

| Item | Status |
|---|---|
| Database backups | Ready in PR #18 (nightly, encrypted, to Cloudflare R2), not merged. **Switch on before the first real customer.** Needs Cloudflare R2 enabled, an R2 key, and a `BACKUP_PASSPHRASE` kept in a password manager |
| Legal review | Terms and Privacy need a lawyer's review before launch |
| Dependencies | 23 moderate `npm audit` findings, all in Sentry's OpenTelemetry packages and `uuid`. No high or critical. Fixed by a Sentry major upgrade, or by the rewrite |
| Old branches and PR #10 | Already merged or replaced. Safe to delete |
| Repository visibility | Public. To make it private, move the uptime check to every 30 minutes or to UptimeRobot first. Every 10 minutes would use up GitHub's free minutes for private repos |
| Analytics | Off. Turn on Plausible (`PLAUSIBLE_DOMAIN`) or Cloudflare Web Analytics when there are customers |
