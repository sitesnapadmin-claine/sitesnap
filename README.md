# SiteSnap 🚀

**Build a beautiful website in minutes — no coding required.**

---

## Quick Start (3 steps)

```bash
npm install
node server.js
```

Open **http://localhost:3000** in your browser. That's it.

---

## Features

- **5-step wizard** — Business info → Branding → Message → Style → Preview
- **Image uploads** — Logo, hero photo, about photo (up to 15MB each)
- **6 design themes** — Light & Airy, Bold & Modern, Earthy, Luxe, Playful, Professional
- **User accounts** — Sign up / log in to save sites
- **Shareable links** — Every saved site gets a public URL (`/preview/:uuid`)
- **My Sites drawer** — View and reopen all your saved sites

**Paid features (PayPal):**
- **Free** — Full wizard + shareable link + "Built with SiteSnap" badge
- **$29 one-time (Starter)** — Badge removed + `yourbrand.sitesnap.app` subdomain
- **$12/month (Pro)** — Custom domain (`yourbrand.com`) + everything in Starter

---

## Environment Variables

Create a `.env` file or set these in your hosting dashboard:

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | Yes | Random secret for auth tokens. Use `openssl rand -hex 32` |
| `BASE_URL` | Yes | Your public URL, e.g. `https://sitesnap.app` |
| `APP_DOMAIN` | No | Your domain without protocol, default: `sitesnap.app` |
| `PAYMENT_PROVIDER` | For payments | `paypal` (current). Defaults to `stripe` if not set |
| `PAYPAL_MODE` | For payments | `live` or `sandbox` |
| `PAYPAL_CLIENT_ID` | For payments | From PayPal Developer → Apps & Credentials |
| `PAYPAL_CLIENT_SECRET` | For payments | From the same app. Keep it private |
| `PAYPAL_WEBHOOK_ID` | For payments | ID of the webhook you add in PayPal (see below) |
| `PAYPAL_PRO_PLAN_ID` | For payments | ID of the "SiteSnap Pro Monthly" plan ($12 a month) |
| `PORT` | No | Port to listen on, default: `3000` |

---

## PayPal Setup (to accept payments)

Starter ($29 one time) uses PayPal Orders. Pro ($12 a month) uses PayPal Subscriptions.

1. In PayPal Developer, create an app under Apps & Credentials (use Live for real payments).
2. Set `PAYMENT_PROVIDER=paypal`, `PAYPAL_MODE`, `PAYPAL_CLIENT_ID` and `PAYPAL_CLIENT_SECRET`.
3. Create a Pro plan in PayPal ($12 a month) and set its ID as `PAYPAL_PRO_PLAN_ID`.
4. Add a webhook to the app:
   - URL: `https://www.yourdomain.com/api/paypal/webhook` (use the exact address PayPal should reach, including `www` if your site redirects to it, because PayPal does not follow redirects)
   - Events: Billing subscription activated, cancelled, expired, suspended and payment failed, Payment sale completed, Payment capture completed
   - Copy the **Webhook ID** and set it as `PAYPAL_WEBHOOK_ID`
5. Refunds are handled by hand in PayPal. A refund does not change the customer's plan automatically.

> **Stripe is paused.** The Stripe code is still in the project. To switch back, set `PAYMENT_PROVIDER=stripe` and set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` (webhook URL `/api/webhook`, events `checkout.session.completed`, `customer.subscription.deleted`, `invoice.payment_failed`).

> **Testing:** Set `PAYPAL_MODE=sandbox` with sandbox credentials and a sandbox buyer account.

---

## Deploying to the Internet

### Option A — Render.com (easiest, free tier)

1. Push this folder to a GitHub repo
2. [render.com](https://render.com) → New → Web Service → connect repo
3. Build command: `npm install`
4. Start command: `node server.js`
5. Add environment variables in Render's dashboard
6. Deploy

> Render's free tier has **ephemeral storage** — uploaded images are lost on restart. For production, use [Cloudinary](https://cloudinary.com) or [AWS S3](https://aws.amazon.com/s3/) instead of local disk.

### Option B — VPS with Caddy (custom domains + SSL)

Use this when you want `*.sitesnap.app` subdomains and customer custom domains with automatic SSL.

**Requirements:**
- A VPS (DigitalOcean, Hetzner, Linode, etc.)
- Your domain pointed at the VPS IP
- [Caddy](https://caddyserver.com/docs/install) installed

**Steps:**

```bash
# 1. Install Caddy
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudflare.com/caddy/stable/debian.deb.pkg.cloudsmith.io/public.gpg' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudflare.com/caddy/stable/debian.deb.pkg.cloudsmith.io/caddy/stable/debian.deb.list' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy

# 2. Clone your app
git clone https://github.com/yourusername/sitesnap.git /opt/sitesnap
cd /opt/sitesnap && npm install

# 3. Set environment variables (create /opt/sitesnap/.env or use systemd)
# 4. Copy Caddyfile to /etc/caddy/Caddyfile (edit domain names first)
# 5. Start your app (use pm2 or systemd to keep it running)
npm install -g pm2
pm2 start server.js --name sitesnap
pm2 save

# 6. Restart Caddy
sudo systemctl reload caddy
```

**For wildcard subdomains (`*.sitesnap.app`):** You need a DNS challenge. The Caddyfile includes commented-out Cloudflare DNS instructions. See [Caddy DNS challenge docs](https://caddyserver.com/docs/automatic-https#dns-challenge).

**How custom domains work:** When a Pro user connects `yourbrand.com`, they point their DNS CNAME to `sitesnap.app`. Caddy intercepts the request, calls `/api/domain/verify` to confirm the domain is registered, then issues a Let's Encrypt cert automatically (on-demand TLS). Zero manual cert management.

---

## Project Structure

```
sitebuilder-app/
├── server.js          # Express backend — auth, uploads, payments, site CRUD, preview
├── package.json
├── Caddyfile          # Caddy reverse proxy config (production)
├── sitesnap.db        # SQLite database (auto-created on first run)
├── uploads/           # Uploaded images (auto-created)
└── public/
    └── index.html     # Full wizard frontend (vanilla HTML/CSS/JS)
```

---

## Tech Stack

| Layer | Tech |
|---|---|
| Server | Node.js + Express |
| Database | SQLite (better-sqlite3) |
| Auth | JWT (jsonwebtoken + bcryptjs) |
| File uploads | Multer (local disk) |
| Payments | PayPal Orders and Subscriptions + webhooks (Stripe paused) |
| SSL / Proxy | Caddy (on-demand TLS) |
| Frontend | Vanilla HTML/CSS/JS |
| Deploy | Render / Railway / any Node host |

