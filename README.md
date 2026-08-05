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

**Paid features (Stripe):**
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
| `STRIPE_SECRET_KEY` | For payments | From [Stripe dashboard](https://dashboard.stripe.com/apikeys) — starts with `sk_live_` |
| `STRIPE_WEBHOOK_SECRET` | For payments | From Stripe → Developers → Webhooks |
| `PORT` | No | Port to listen on, default: `3000` |

---

## Stripe Setup (to accept payments)

1. Create a [Stripe account](https://stripe.com)
2. Get your **Secret Key** from Stripe Dashboard → Developers → API Keys
3. Set `STRIPE_SECRET_KEY` in your environment
4. Set up a webhook:
   - Go to Stripe → Developers → Webhooks → Add endpoint
   - URL: `https://yourdomain.com/api/webhook`
   - Events to listen for: `checkout.session.completed`, `customer.subscription.deleted`, `invoice.payment_failed`
   - Copy the **Signing Secret** and set it as `STRIPE_WEBHOOK_SECRET`

> **Testing:** Use `sk_test_...` key and Stripe test cards (e.g. `4242 4242 4242 4242`, any future date, any CVC).

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
├── server.js          # Express backend — auth, uploads, Stripe, site CRUD, preview
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
| Payments | Stripe Checkout + webhooks |
| SSL / Proxy | Caddy (on-demand TLS) |
| Frontend | Vanilla HTML/CSS/JS |
| Deploy | Render / Railway / any Node host |
