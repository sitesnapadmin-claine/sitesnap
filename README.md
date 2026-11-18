# SiteSnap

> Taking over development or planning a rewrite? Start with [HANDOVER.md](HANDOVER.md).

**Build a website for your small business in minutes, with no coding.**

Live at [www.site-snap.app](https://www.site-snap.app). Hosted on Railway, which deploys automatically from the `main` branch.

---

## Run it locally

```bash
npm install
npm start
```

Open http://localhost:3000. Without `DATABASE_URL` the app uses a local SQLite file (`sitesnap.db`), which is fine for development.

Run the tests:

```bash
npm test
```

Node 20 to 24 is supported.

---

## How it works

- **Wizard.** Five steps: business info, branding, message and contact details, style, preview.
- **Customer sites** are plain HTML and CSS with no scripts, served with a strict Content Security Policy. They're available at `/preview/<id>`, on a custom domain (Pro), or on a subdomain once subdomains are switched on.
- **Images** are checked by their contents (JPG, PNG, WebP or GIF only) and stored on Cloudinary.
- **Accounts** use JWT logins. Changing the password signs out every other device.
- **Plans** are paid through PayPal:
  - **Free:** 1 site, preview link, "Built with SiteSnap" badge.
  - **Starter, $29 one time:** badge removed (plus a subdomain once enabled).
  - **Pro, $12 a month:** unlimited sites and your own domain.
- **Custom domains** are set up through Cloudflare for SaaS when its variables are set, otherwise through the Railway API.
- **Admin dashboard** is at `/admin`. It shows signups, money actually received (from the payments ledger) and customers.
  - The first password is `ADMIN_PASSWORD`. "Change password" in the dashboard, or "Forgot password?" on the login screen, saves a new one in the database, which then replaces `ADMIN_PASSWORD`.
  - Reset links go only to `ADMIN_EMAIL` (or `SIGNUP_NOTIFY_EMAIL` if that isn't set) and need email to be set up.

| File | What it does |
|---|---|
| `server.js` | Express app: auth, uploads, sites, domains, billing, customer site HTML |
| `paypal.js` | PayPal checkout, confirmations and webhook handling |
| `cloudflare.js` | Custom domains through Cloudflare for SaaS |
| `planlimits.js` | What happens to extra sites when Pro ends |
| `public/index.html` | The whole front end (landing page, wizard, dashboard) |
| `public/admin.html` | Admin dashboard |
| `tests/` | Jest and Supertest tests |

---

## Environment variables

See `.env.example` for the full list with notes. The ones production must have:

| Variable | Why |
|---|---|
| `NODE_ENV=production` | Turns on production safety checks |
| `JWT_SECRET` | Signs logins. The app refuses to start in production without it |
| `DATABASE_URL` | Postgres. Without it every redeploy wipes all customer data |
| `BASE_URL`, `APP_DOMAIN` | `https://www.site-snap.app` and `site-snap.app` |
| `PAYMENT_PROVIDER=paypal` and the `PAYPAL_*` variables | Payments |
| `CLOUDINARY_*` | Image storage. In production uploads fail rather than use the temporary disk |
| `RESEND_API_KEY`, `RESET_FROM_EMAIL` | Email: password reset, email confirmation, contact forms, alerts |

---

## PayPal setup

Starter uses PayPal Orders and Pro uses PayPal Subscriptions.

1. In PayPal Developer, create an app under Apps & Credentials (Live for real payments).
2. Set `PAYMENT_PROVIDER=paypal`, `PAYPAL_MODE`, `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET`.
3. Create a Pro plan ($12 a month) and set its ID as `PAYPAL_PRO_PLAN_ID`.
4. Add a webhook pointing at `https://www.site-snap.app/api/paypal/webhook` (with `www`, because PayPal doesn't follow redirects), subscribed to:
   - Billing subscription: activated, cancelled, expired, suspended, payment failed
   - Payment sale: completed, refunded
   - Payment capture: completed, refunded
   - Customer dispute: created
5. Copy the webhook's ID into `PAYPAL_WEBHOOK_ID`.

What the webhook does with refunds and disputes:
- **A full Starter refund** puts the customer back on Free.
- **A refunded Pro payment** leaves Pro on and emails you to decide.
- **A dispute** emails you so you can respond in PayPal before the deadline.
- **Payments and refunds** are recorded in the `payments` table, which the admin dashboard reads.

Stripe is legacy code. It only runs when `PAYMENT_PROVIDER` isn't `paypal` and `STRIPE_SECRET_KEY` is set.

---

## Email (Resend)

Set `RESEND_API_KEY` and `RESET_FROM_EMAIL` (an address on a domain verified in Resend, for example `SiteSnap <hello@site-snap.app>`). This switches on:
- Password reset
- Email confirmation for new accounts
- Contact forms on customer sites
- Sign-up, dispute and failed-payment alerts to `SIGNUP_NOTIFY_EMAIL`

Until both are set, these features stay hidden instead of half-working.

---

## Monitoring

- GitHub Actions runs the tests on every pull request and push to `main` (`.github/workflows/test.yml`).
- `.github/workflows/uptime.yml` checks the live site every 10 minutes. If it fails, GitHub emails the repository owner.

- `SENTRY_DSN` sends server errors to Sentry.
- Point an uptime checker (UptimeRobot or Better Stack) at `https://www.site-snap.app/api/config`.
- Turn on backups for the Railway Postgres database.
- `/api/_diag` (signed in as `ADMIN_EMAIL`) shows whether Postgres, Cloudinary and the domain API are connected.
