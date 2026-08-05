const express = require('express');
const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const multer = require('multer');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Stripe = require('stripe');

// ── CLOUDINARY (optional — falls back to local disk if not configured) ─────────
let cloudinary = null;
if (process.env.CLOUDINARY_CLOUD_NAME) {
  try {
    cloudinary = require('cloudinary').v2;
    cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key:    process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
    });
    console.log('☁️  Cloudinary enabled — images stored in the cloud');
  } catch(e) {
    console.warn('Cloudinary package not installed — run: npm install cloudinary');
    cloudinary = null;
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sitesnap-dev-secret-change-in-production';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const APP_DOMAIN = process.env.APP_DOMAIN || 'sitesnap.app';
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

// ── PLANS ──────────────────────────────────────────────────────────────────────
const PLANS = {
  starter: { name: 'Starter', price: 2900, mode: 'payment',      label: '$29 one-time' },
  pro:     { name: 'Pro',     price: 1200, mode: 'subscription',  label: '$12/month'    },
};

// ── DIRECTORIES ────────────────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── DATABASE ───────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'sitesnap.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan TEXT DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    user_id INTEGER,
    data TEXT NOT NULL,
    subdomain TEXT UNIQUE,
    custom_domain TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);
// Safe migrations for existing databases
[
  "ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'",
  "ALTER TABLE users ADD COLUMN stripe_customer_id TEXT",
  "ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT",
  "ALTER TABLE sites ADD COLUMN subdomain TEXT",
  "ALTER TABLE sites ADD COLUMN custom_domain TEXT",
].forEach(sql => { try { db.exec(sql); } catch (_) {} });

// ── FILE UPLOAD ────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) return cb(null, true);
    cb(new Error('Only image files are accepted'));
  }
});

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
// Stripe webhook needs raw body — mount BEFORE express.json()
app.post('/api/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);

app.use(express.json({ limit: '2mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));

// ── DOMAIN ROUTING (check custom domains & subdomains first) ───────────────────
app.use((req, res, next) => {
  const host = req.hostname;

  // Custom domain: any host that isn't our app domain or localhost
  if (host && !host.endsWith(APP_DOMAIN) && host !== 'localhost' && host !== '127.0.0.1') {
    const site = db.prepare('SELECT uuid, data FROM sites WHERE custom_domain = ?').get(host);
    if (site) {
      const data = JSON.parse(site.data);
      return res.send(buildWebsite(data, site.uuid, `https://${host}`));
    }
  }

  // Subdomain: yourbrand.sitesnap.app
  const parts = host.split('.');
  if (parts.length >= 3 || (host.endsWith('localhost') && parts.length >= 2)) {
    const sub = parts[0];
    if (sub && sub !== 'www' && sub !== 'app') {
      const site = db.prepare('SELECT uuid, data FROM sites WHERE subdomain = ?').get(sub);
      if (site) {
        const data = JSON.parse(site.data);
        return res.send(buildWebsite(data, site.uuid, BASE_URL));
      }
    }
  }

  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

function requirePlan(plan) {
  const order = ['free', 'starter', 'pro'];
  return (req, res, next) => {
    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
    if (order.indexOf(user?.plan || 'free') >= order.indexOf(plan)) return next();
    res.status(403).json({ error: `This feature requires the ${plan} plan.`, required: plan });
  };
}

// ── AUTH ROUTES ────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(
      email.toLowerCase().trim(), hash
    );
    const token = jwt.sign({ id: result.lastInsertRowid, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: email.toLowerCase(), plan: 'free' });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'That email is already registered' });
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email?.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email, plan: user.plan || 'free' });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, email, plan, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ── UPLOAD ─────────────────────────────────────────────────────────────────────
app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  // If Cloudinary is configured, upload there and delete the local temp file
  if (cloudinary) {
    try {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'sitesnap',
        transformation: [{ width: 1600, crop: 'limit', quality: 'auto', fetch_format: 'auto' }]
      });
      fs.unlink(req.file.path, () => {}); // clean up local temp file
      return res.json({ url: result.secure_url });
    } catch (e) {
      console.error('Cloudinary upload error:', e.message);
      // Fall through to local URL as backup
    }
  }

  // Local disk fallback (fine for dev; ephemeral on Render free tier)
  res.json({ url: `${BASE_URL}/uploads/${req.file.filename}` });
});

// ── SITES ──────────────────────────────────────────────────────────────────────
app.post('/api/sites', requireAuth, (req, res) => {
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'Site data is required' });
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
  const plan = user?.plan || 'free';
  const uuid = uuidv4();
  db.prepare('INSERT INTO sites (uuid, user_id, data) VALUES (?, ?, ?)').run(uuid, req.user.id, JSON.stringify(data));
  res.json({ uuid, url: `${BASE_URL}/preview/${uuid}`, plan });
});

// ── UPDATE SITE ────────────────────────────────────────────────────────────────
app.put('/api/sites/:uuid', requireAuth, (req, res) => {
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'Site data is required' });
  const site = db.prepare('SELECT user_id FROM sites WHERE uuid = ?').get(req.params.uuid);
  if (!site) return res.status(404).json({ error: 'Site not found' });
  if (site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });
  db.prepare('UPDATE sites SET data = ? WHERE uuid = ?').run(JSON.stringify(data), req.params.uuid);
  res.json({ uuid: req.params.uuid, url: `${BASE_URL}/preview/${req.params.uuid}` });
});

app.get('/api/sites', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT uuid, subdomain, custom_domain, created_at, data FROM sites WHERE user_id = ? ORDER BY created_at DESC'
  ).all(req.user.id);
  res.json(rows.map(r => {
    const d = JSON.parse(r.data);
    return { uuid: r.uuid, subdomain: r.subdomain, customDomain: r.custom_domain, created_at: r.created_at, bizName: d.bizName, industry: d.industry, designStyle: d.designStyle };
  }));
});

app.get('/api/sites/:uuid', (req, res) => {
  const row = db.prepare('SELECT data FROM sites WHERE uuid = ?').get(req.params.uuid);
  if (!row) return res.status(404).json({ error: 'Site not found' });
  res.json(JSON.parse(row.data));
});

app.delete('/api/sites/:uuid', requireAuth, (req, res) => {
  const row = db.prepare('SELECT user_id FROM sites WHERE uuid = ?').get(req.params.uuid);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });
  db.prepare('DELETE FROM sites WHERE uuid = ?').run(req.params.uuid);
  res.json({ ok: true });
});

// ── SUBDOMAIN (Starter+) ───────────────────────────────────────────────────────
app.post('/api/sites/:uuid/subdomain', requireAuth, requirePlan('starter'), (req, res) => {
  const { subdomain } = req.body || {};
  if (!subdomain) return res.status(400).json({ error: 'Subdomain is required' });
  const clean = subdomain.toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 30);
  if (!clean) return res.status(400).json({ error: 'Invalid subdomain' });

  const site = db.prepare('SELECT user_id FROM sites WHERE uuid = ?').get(req.params.uuid);
  if (!site || site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });

  try {
    db.prepare('UPDATE sites SET subdomain = ? WHERE uuid = ?').run(clean, req.params.uuid);
    res.json({ subdomain: clean, url: `https://${clean}.${APP_DOMAIN}` });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'That subdomain is already taken' });
    res.status(500).json({ error: 'Could not set subdomain' });
  }
});

// ── CUSTOM DOMAIN (Pro) ────────────────────────────────────────────────────────
app.post('/api/sites/:uuid/domain', requireAuth, requirePlan('pro'), (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain is required' });
  const clean = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/$/, '');

  const site = db.prepare('SELECT user_id FROM sites WHERE uuid = ?').get(req.params.uuid);
  if (!site || site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });

  try {
    db.prepare('UPDATE sites SET custom_domain = ? WHERE uuid = ?').run(clean, req.params.uuid);
    res.json({ domain: clean, dnsTarget: APP_DOMAIN });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'That domain is already connected to another site' });
    res.status(500).json({ error: 'Could not set domain' });
  }
});

// Caddy on-demand TLS: called by Caddy before issuing a cert for a custom domain
app.get('/api/domain/verify', (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).end();
  const site = db.prepare('SELECT id FROM sites WHERE custom_domain = ?').get(domain);
  site ? res.status(200).end() : res.status(404).end();
});

// DNS check: resolve domain CNAME and report if it points to sitesnap
app.get('/api/domain/dns-check', requireAuth, async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  try {
    let cnames = [];
    try { cnames = await dns.resolveCname(domain); } catch(_) {}
    const pointed = cnames.some(c => c.includes(APP_DOMAIN) || c.includes('railway.app') || c.includes('up.railway.app'));
    res.json({ domain, cnames, pointed, target: APP_DOMAIN });
  } catch (e) {
    res.status(500).json({ error: 'DNS lookup failed', detail: e.message });
  }
});

// ── STRIPE CHECKOUT ────────────────────────────────────────────────────────────
app.post('/api/checkout/:plan', requireAuth, async (req, res) => {
  const planKey = req.params.plan;
  if (!PLANS[planKey]) return res.status(400).json({ error: 'Unknown plan' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const plan = PLANS[planKey];

  try {
    // Get or create Stripe customer
    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, metadata: { userId: String(user.id) } });
      customerId = customer.id;
      db.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').run(customerId, user.id);
    }

    const priceData = {
      currency: 'usd',
      unit_amount: plan.price,
      product_data: { name: `SiteSnap ${plan.name}` },
    };
    if (plan.mode === 'subscription') priceData.recurring = { interval: 'month' };

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: plan.mode,
      line_items: [{ price_data: priceData, quantity: 1 }],
      success_url: `${BASE_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}&plan=${planKey}`,
      cancel_url: `${BASE_URL}/billing/cancel`,
      metadata: { userId: String(user.id), plan: planKey },
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe checkout error:', e.message);
    res.status(500).json({ error: 'Could not create checkout session. Check your Stripe key.' });
  }
});

// Billing portal (manage subscription)
app.post('/api/billing/portal', requireAuth, async (req, res) => {
  const user = db.prepare('SELECT stripe_customer_id FROM users WHERE id = ?').get(req.user.id);
  if (!user?.stripe_customer_id) return res.status(400).json({ error: 'No billing account found' });
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: BASE_URL,
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: 'Could not open billing portal' });
  }
});

// ── STRIPE WEBHOOK ─────────────────────────────────────────────────────────────
async function handleStripeWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;

  try {
    event = secret
      ? stripe.webhooks.constructEvent(req.body, sig, secret)
      : JSON.parse(req.body.toString());
  } catch (e) {
    console.error('Webhook signature error:', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const userId = parseInt(session.metadata?.userId);
      const plan = session.metadata?.plan;
      if (userId && plan) {
        db.prepare('UPDATE users SET plan = ? WHERE id = ?').run(plan, userId);
        if (session.subscription) {
          db.prepare('UPDATE users SET stripe_subscription_id = ? WHERE id = ?').run(session.subscription, userId);
        }
        console.log(`✓ User ${userId} upgraded to ${plan}`);
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      db.prepare("UPDATE users SET plan = 'free', stripe_subscription_id = NULL WHERE stripe_subscription_id = ?").run(sub.id);
      console.log(`User downgraded — subscription cancelled: ${sub.id}`);
      break;
    }
    case 'invoice.payment_failed': {
      console.warn('Payment failed for subscription:', event.data.object.subscription);
      break;
    }
  }
  res.json({ received: true });
}

// ── PREVIEW ROUTE ──────────────────────────────────────────────────────────────
app.get('/preview/:uuid', (req, res) => {
  const row = db.prepare('SELECT data FROM sites WHERE uuid = ?').get(req.params.uuid);
  if (!row) return res.status(404).send(notFoundHtml());
  res.send(buildWebsite(JSON.parse(row.data), req.params.uuid, BASE_URL));
});

// ── BILLING PAGES ──────────────────────────────────────────────────────────────
app.get('/billing/success', (req, res) => {
  const plan = req.query.plan || 'starter';
  const planLabel = PLANS[plan]?.name || 'Starter';
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Welcome to ${planLabel}!</title>
<meta http-equiv="refresh" content="4; url=/">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0;}body{font-family:'Inter',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#F0EBFF,#EEF2FF);}
.box{text-align:center;background:white;border-radius:24px;padding:56px 48px;box-shadow:0 12px 48px rgba(108,71,255,0.15);max-width:420px;width:90%;}
.icon{font-size:56px;margin-bottom:20px;}h1{font-size:26px;font-weight:800;color:#1A1A2E;margin-bottom:10px;}
p{font-size:15px;color:#6B7280;line-height:1.5;margin-bottom:24px;}
.badge{display:inline-block;background:#EEE9FF;color:#6C47FF;font-size:13px;font-weight:700;padding:6px 16px;border-radius:20px;margin-bottom:8px;}
a{display:inline-block;padding:12px 32px;background:#6C47FF;color:white;border-radius:10px;font-weight:700;text-decoration:none;font-size:15px;}
</style></head><body><div class="box">
<div class="badge">Plan activated</div>
<div class="icon">🎉</div>
<h1>Welcome to ${planLabel}!</h1>
<p>Your account has been upgraded. Redirecting you back to the app in a moment…</p>
<a href="/">Go to my account →</a>
</div></body></html>`);
});

app.get('/billing/cancel', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Checkout cancelled</title>
<meta http-equiv="refresh" content="3; url=/">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0;}body{font-family:'Inter',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f9fafb;}
.box{text-align:center;padding:48px;}.icon{font-size:40px;margin-bottom:16px;}h1{font-size:20px;color:#1A1A2E;margin-bottom:8px;}p{color:#6B7280;font-size:14px;}</style>
</head><body><div class="box"><div class="icon">👋</div><h1>No worries!</h1><p>Checkout cancelled. Taking you back…</p></div></body></html>`);
});

function notFoundHtml() {
  return `<!DOCTYPE html><html><head><title>Not Found — SiteSnap</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f9fafb;}
.box{text-align:center;}.logo{font-size:22px;font-weight:800;color:#6C47FF;margin-bottom:16px;}
h1{font-size:18px;color:#1a1a2e;margin-bottom:8px;}p{color:#6b7280;font-size:14px;}a{color:#6C47FF;}</style></head>
<body><div class="box"><div class="logo">SiteSnap</div><h1>Site not found</h1>
<p>This link may be invalid. <a href="/">Build your own →</a></p></div></body></html>`;
}

// ── WEBSITE BUILDER ────────────────────────────────────────────────────────────
function buildWebsite(s, uuid, baseUrl) {
  const name = s.bizName || 'Your Business';
  const tagline = s.tagline || `Serving ${s.industry || 'clients'} with passion and purpose`;
  const audience = s.audience || 'people who value quality';
  const problem = s.problem || `We make it easy to get exactly what you need.`;
  const diff = s.differentiator || `We bring a unique approach that sets us apart.`;
  const cta = s.ctaType || 'Get Started';
  const loc = s.location ? ` · ${s.location}` : '';
  const f = getTheme(s);

  // Check if this site has badge removed (Starter+ user)
  const siteRow = db.prepare('SELECT user_id FROM sites WHERE uuid = ?').get(uuid);
  let showBadge = true;
  if (siteRow?.user_id) {
    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(siteRow.user_id);
    showBadge = !user || user.plan === 'free';
  }

  const logoHtml = s.logoUrl
    ? `<img src="${s.logoUrl}" alt="${escHtml(name)}" style="max-height:52px;max-width:160px;object-fit:contain;">`
    : `<div style="font-size:20px;font-weight:900;letter-spacing:-0.5px;color:${f.navText}">${escHtml(name)}</div>`;

  const heroImg = s.heroUrl
    ? `<img src="${s.heroUrl}" alt="Hero" style="width:100%;height:100%;object-fit:cover;border-radius:${f.imgRadius};">`
    : `<span style="font-size:64px;">${f.heroEmoji}</span>`;

  const aboutImg = s.aboutUrl
    ? `<img src="${s.aboutUrl}" alt="About" style="width:100%;height:100%;object-fit:cover;border-radius:${f.imgRadius};">`
    : `<span style="font-size:72px;">${f.aboutEmoji}</span>`;

  const badge = showBadge ? `
    <div style="position:fixed;bottom:0;left:0;right:0;z-index:9999;background:rgba(15,15,30,0.92);backdrop-filter:blur(8px);
      padding:10px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
      <span style="font-size:13px;color:rgba(255,255,255,0.7);">Built with <strong style="color:#6C47FF;">SiteSnap</strong></span>
      <a href="${baseUrl}" target="_blank" style="font-size:12px;font-weight:700;color:#6C47FF;text-decoration:none;
        padding:6px 16px;background:rgba(108,71,255,0.15);border-radius:20px;border:1px solid rgba(108,71,255,0.3);">
        Create your own →</a>
    </div>` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="${escHtml(tagline)}">
<title>${escHtml(name)}</title>
<link href="https://fonts.googleapis.com/css2?family=${f.fontUrl}&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}html{scroll-behavior:smooth;}
body{font-family:${f.bodyFont};background:${f.bg};color:${f.text};line-height:1.6;${showBadge ? 'padding-bottom:52px;' : ''}}
a{text-decoration:none;color:inherit;}
nav{background:${f.navBg};padding:18px 48px;display:flex;align-items:center;justify-content:space-between;border-bottom:${f.navBorder};position:sticky;top:0;z-index:100;}
.nav-links{display:flex;gap:32px;font-size:14px;font-weight:500;color:${f.navText};opacity:0.8;}
.nav-cta{padding:10px 24px;background:${f.primary};color:${f.ctaText};border-radius:${f.btnRadius};font-size:14px;font-weight:700;cursor:pointer;border:none;}
.hero{padding:${f.heroPadding};background:${f.heroBg};display:grid;grid-template-columns:1fr ${f.heroImgCol};gap:64px;align-items:center;${f.heroExtra}}
.hero-img-wrap{border-radius:${f.imgRadius};overflow:hidden;aspect-ratio:4/3;background:${f.heroImgBg};display:flex;align-items:center;justify-content:center;${f.heroImgExtra}}
.hero h1{font-family:${f.headFont};font-size:clamp(32px,5vw,58px);font-weight:${f.heroWeight};line-height:1.1;color:${f.heroText};margin-bottom:20px;letter-spacing:${f.heroTracking};}
.hero h1 em{color:${f.accent};font-style:normal;}
.hero-eyebrow{font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:${f.accent};margin-bottom:16px;}
.hero-sub{font-size:17px;color:${f.heroSubText};max-width:480px;margin-bottom:36px;line-height:1.6;}
.hero-btns{display:flex;gap:16px;flex-wrap:wrap;}
.btn-p{padding:16px 36px;background:${f.primary};color:${f.ctaText};border-radius:${f.btnRadius};font-size:16px;font-weight:700;border:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px;transition:transform 0.15s;}
.btn-p:hover{transform:translateY(-2px);}
.btn-s{padding:16px 32px;background:transparent;color:${f.heroText};border-radius:${f.btnRadius};font-size:16px;font-weight:600;border:2px solid ${f.heroBorder};cursor:pointer;}
.trust-bar{padding:20px 48px;background:${f.trustBg};border-top:${f.trustBorder};border-bottom:${f.trustBorder};display:flex;align-items:center;justify-content:center;gap:48px;flex-wrap:wrap;}
.trust-item{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;color:${f.trustText};opacity:0.75;}
.trust-dot{width:6px;height:6px;border-radius:50%;background:${f.accent};}
section{padding:96px 48px;}
.eyebrow{font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:${f.accent};margin-bottom:12px;}
.section-title{font-family:${f.headFont};font-size:clamp(26px,4vw,42px);font-weight:${f.heroWeight};color:${f.headingColor};margin-bottom:16px;line-height:1.2;letter-spacing:${f.heroTracking};}
.section-sub{font-size:16px;color:${f.subTextColor};max-width:520px;line-height:1.6;margin-bottom:52px;}
.about{background:${f.aboutBg};}
.about-grid{display:grid;grid-template-columns:1fr 1fr;gap:64px;align-items:center;}
.about-img{border-radius:${f.imgRadius};aspect-ratio:4/3;background:${f.aboutImgBg};display:flex;align-items:center;justify-content:center;overflow:hidden;${f.aboutImgExtra}}
.about p{font-size:16px;color:${f.subTextColor};line-height:1.8;margin-bottom:16px;}
.features{background:${f.featureBg};}
.features-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:28px;}
.feature-card{background:${f.cardBg};border-radius:${f.cardRadius};padding:32px;border:${f.cardBorder};transition:transform 0.2s;}
.feature-card:hover{transform:translateY(-4px);}
.feature-icon{font-size:36px;margin-bottom:16px;}
.feature-title{font-family:${f.headFont};font-size:18px;font-weight:700;color:${f.headingColor};margin-bottom:8px;}
.feature-text{font-size:14px;color:${f.subTextColor};line-height:1.6;}
.testimonial-section{background:${f.testimonialBg};text-align:center;}
.testimonial-card{max-width:640px;margin:0 auto;padding:48px;background:${f.testimonialCardBg};border-radius:${f.cardRadius};border:${f.testimonialBorder};}
.quote-mark{font-size:64px;color:${f.accent};line-height:0.8;margin-bottom:24px;font-family:Georgia,serif;}
.quote-text{font-size:20px;color:${f.headingColor};font-style:italic;line-height:1.5;margin-bottom:24px;font-family:${f.headFont};}
.quote-author{font-size:14px;font-weight:600;color:${f.subTextColor};}
.cta-section{background:${f.ctaSectionBg};text-align:center;padding:96px 48px;${f.ctaExtra}}
.cta-section h2{font-family:${f.headFont};font-size:clamp(32px,5vw,48px);font-weight:${f.heroWeight};color:${f.ctaSectionText};margin-bottom:16px;letter-spacing:${f.heroTracking};}
.cta-section p{font-size:18px;color:${f.ctaSectionSub};margin-bottom:40px;max-width:500px;margin-left:auto;margin-right:auto;}
footer{background:${f.footerBg};border-top:${f.footerBorder};padding:40px 48px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;}
.footer-name{font-size:18px;font-weight:800;color:${f.footerText};}
.footer-copy{font-size:13px;color:${f.footerText};opacity:0.5;}
.footer-links{display:flex;gap:24px;font-size:13px;color:${f.footerText};opacity:0.6;}
@media(max-width:700px){.hero,.about-grid{grid-template-columns:1fr;}.hero-img-wrap{display:none;}.features-grid{grid-template-columns:1fr;}nav,section,footer{padding-left:24px;padding-right:24px;}.trust-bar{gap:20px;}nav{padding:14px 20px;}}
</style></head><body>
<nav>
  ${logoHtml}
  <div class="nav-links"><a href="#about">About</a><a href="#services">Services</a><a href="#contact">Contact</a></div>
  <button class="nav-cta">${escHtml(cta)}</button>
</nav>
<div class="hero">
  <div>
    <div class="hero-eyebrow">${escHtml(s.industry || 'Premium Service')}${escHtml(loc)}</div>
    <h1>${heroHeadline(name, s.industry)}</h1>
    <p class="hero-sub">${escHtml(tagline)}</p>
    <div class="hero-btns"><button class="btn-p">${escHtml(cta)} →</button><button class="btn-s">Learn More</button></div>
  </div>
  <div class="hero-img-wrap">${heroImg}</div>
</div>
${s.showTrustBar !== false ? `<div class="trust-bar">
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust1 || 'Trusted by clients worldwide')}</div>
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust2 || '5-star rated')}</div>
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust3 || '100% satisfaction')}</div>
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust4 || s.location || 'Available online')}</div>
</div>` : ''}
<section class="about" id="about">
  <div class="about-grid">
    <div class="about-img">${aboutImg}</div>
    <div>
      <div class="eyebrow">Our Story</div>
      <div class="section-title">We exist for ${escHtml(audience.split(' ').slice(0,6).join(' '))}…</div>
      <p>${escHtml(problem)}</p>
      <p>${escHtml(diff)}</p>
      <button class="btn-p" style="margin-top:16px;">${escHtml(cta)} →</button>
    </div>
  </div>
</section>
<section class="features" id="services">
  <div style="text-align:center;max-width:600px;margin:0 auto 52px;">
    <div class="eyebrow">Why Choose Us</div>
    <div class="section-title">What makes ${escHtml(name)} different</div>
    <div class="section-sub">We don't just talk the talk — here's what you can expect every single time.</div>
  </div>
  <div class="features-grid">
    <div class="feature-card"><div class="feature-icon">${f.feat1}</div><div class="feature-title">Quality First</div><div class="feature-text">Everything we do is crafted with care and relentless attention to detail.</div></div>
    <div class="feature-card"><div class="feature-icon">${f.feat2}</div><div class="feature-title">Personal Touch</div><div class="feature-text">You're not a ticket number — we tailor our approach to your unique situation.</div></div>
    <div class="feature-card"><div class="feature-icon">${f.feat3}</div><div class="feature-title">Real Results</div><div class="feature-text">Our clients see measurable, meaningful outcomes every single time.</div></div>
  </div>
</section>
<section class="testimonial-section">
  <div class="eyebrow" style="text-align:center;margin-bottom:32px;">What Clients Say</div>
  <div class="testimonial-card">
    <div class="quote-mark">"</div>
    <div class="quote-text">Working with ${escHtml(name)} completely changed everything for me. I came in not knowing what to expect and left with exactly what I needed — and more.</div>
    <div class="quote-author">— A Happy Client${escHtml(loc ? ', ' + loc : '')}</div>
  </div>
</section>
<section class="cta-section" id="contact">
  <h2>${escHtml(s.ctaHeadline || 'Ready to get started?')}</h2>
  <p>${escHtml(s.ctaSubtext || `Join the people already working with ${name}. Your journey begins with one simple step.`)}</p>
  <button class="btn-p" style="background:${f.ctaSectionBtn};color:${f.ctaSectionBtnText};font-size:17px;padding:18px 44px;">${escHtml(cta)} →</button>
</section>
<footer>
  <div class="footer-name">${escHtml(name)}</div>
  <div class="footer-links"><a href="#">Privacy</a><a href="#">Terms</a><a href="#contact">Contact</a></div>
  <div class="footer-copy">© ${new Date().getFullYear()} ${escHtml(name)}. All rights reserved.</div>
</footer>
${badge}
</body></html>`;
}

// ── HELPERS ────────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function heroHeadline(name, industry) {
  const map = {'Photography':`Capturing your story,<br><em>beautifully.</em>`,'Beauty & Wellness':`Feel your best,<br><em>inside &amp; out.</em>`,'Food & Beverage':`Made with love,<br><em>served with pride.</em>`,'Fashion & Apparel':`Style that speaks<br><em>for itself.</em>`,'Health & Fitness':`Your strongest self<br><em>starts here.</em>`,'Home & Interior':`Spaces you'll<br><em>love to live in.</em>`,'Art & Creative':`Art that moves<br><em>the world.</em>`,'Coaching & Consulting':`Clarity, strategy,<br><em>results.</em>`,'Real Estate':`Find the home<br><em>you deserve.</em>`,'Technology':`Built for the<br><em>future, today.</em>`,'Retail / E-commerce':`Shop smarter,<br><em>live better.</em>`,'Non-profit':`Making a difference,<br><em>together.</em>`};
  return map[industry] || `${escHtml(name)}:<br><em>Where quality meets purpose.</em>`;
}
function getTheme(s) {
  const p = s.colorPrimary||'#6C47FF', a = s.colorAccent||'#FF6B6B', font = s.fontStyle||'modern', style = s.designStyle||'light-airy';
  const fm = {modern:{headFont:"'Inter',sans-serif",fontUrl:"Inter:wght@400;700;800",bodyFont:"'Inter',sans-serif",heroWeight:800,heroTracking:'-1px'},elegant:{headFont:"'Playfair Display',serif",fontUrl:"Playfair+Display:wght@400;700",bodyFont:"'Inter',sans-serif",heroWeight:700,heroTracking:'-0.5px'},playful:{headFont:"'Inter',sans-serif",fontUrl:"Inter:wght@400;800;900",bodyFont:"'Inter',sans-serif",heroWeight:900,heroTracking:'-2px'}};
  const f = fm[font]||fm.modern;
  const base = {...f,primary:p,accent:a};
  const themes = {
    'light-airy':{...base,bg:'#FAF7F2',text:'#3D2B1F',navBg:'#FFFEF9',navBorder:'1px solid #F0E8DC',navText:'#3D2B1F',heroBg:'#FAF7F2',heroText:'#3D2B1F',heroSubText:'#7B6E65',heroImgBg:'linear-gradient(135deg,#F5E6D3,#EDD5B8)',heroImgCol:'0.9fr',heroPadding:'80px 48px',heroExtra:'',heroImgExtra:'',heroEmoji:'🌸',heroBorder:'#D4B8A0',trustBg:'#F5EFE6',trustBorder:'1px solid #E8D5C4',trustText:'#7B6E65',aboutBg:'#FFFEF9',aboutImgBg:'linear-gradient(135deg,#EDD5B8,#F5E6D3)',aboutImgExtra:'',aboutEmoji:'✨',featureBg:'#FAF7F2',cardBg:'#FFFEF9',cardRadius:'16px',cardBorder:'1px solid #F0E8DC',testimonialBg:'#F5EFE6',testimonialCardBg:'#FFFEF9',testimonialBorder:'1px solid #E8D5C4',ctaSectionBg:'#C4966A',ctaExtra:'',ctaSectionText:'#FFFEF9',ctaSectionSub:'rgba(255,255,255,0.8)',ctaSectionBtn:'#FFFEF9',ctaSectionBtnText:'#3D2B1F',footerBg:'#3D2B1F',footerBorder:'none',footerText:'#FAF7F2',headingColor:'#3D2B1F',subTextColor:'#7B6E65',imgRadius:'20px',btnRadius:'8px',ctaText:'#FFFEF9',feat1:'🌺',feat2:'🤝',feat3:'⭐'},
    'bold-modern':{...base,bg:'#0D0D0D',text:'#FFFFFF',navBg:'#0D0D0D',navBorder:'1px solid #1F1F1F',navText:'#FFFFFF',heroBg:'#0D0D0D',heroText:'#FFFFFF',heroSubText:'#9CA3AF',heroImgBg:`linear-gradient(135deg,${p}33,${a}33)`,heroImgCol:'0.8fr',heroPadding:'100px 48px',heroExtra:'',heroImgExtra:'border:1px solid #1F1F1F;',heroEmoji:'⚡',heroBorder:'#333',trustBg:'#111',trustBorder:'1px solid #1F1F1F',trustText:'#9CA3AF',aboutBg:'#111',aboutImgBg:`linear-gradient(135deg,#1F1F1F,${p}22)`,aboutImgExtra:'border:1px solid #2A2A2A;',aboutEmoji:'🚀',featureBg:'#0D0D0D',cardBg:'#111',cardRadius:'12px',cardBorder:'1px solid #1F1F1F',testimonialBg:'#111',testimonialCardBg:'#1A1A1A',testimonialBorder:'1px solid #2A2A2A',ctaSectionBg:`linear-gradient(135deg,${p},${a})`,ctaExtra:'',ctaSectionText:'#FFFFFF',ctaSectionSub:'rgba(255,255,255,0.8)',ctaSectionBtn:'#FFFFFF',ctaSectionBtnText:'#0D0D0D',footerBg:'#000',footerBorder:'1px solid #1F1F1F',footerText:'#FFFFFF',headingColor:'#FFFFFF',subTextColor:'#9CA3AF',imgRadius:'12px',btnRadius:'6px',ctaText:'#FFFFFF',feat1:'⚡',feat2:'🛡️',feat3:'🎯'},
    'earthy':{...base,bg:'#F4F1EC',text:'#2C1A0E',navBg:'#EDE9E0',navBorder:'1px solid #D4C4A8',navText:'#2C1A0E',heroBg:'#F4F1EC',heroText:'#2C1A0E',heroSubText:'#6B5544',heroImgBg:'linear-gradient(135deg,#D4C4A8,#C4A882)',heroImgCol:'0.9fr',heroPadding:'80px 48px',heroExtra:'',heroImgExtra:'',heroEmoji:'🌿',heroBorder:'#C4A882',trustBg:'#EDE9E0',trustBorder:'1px solid #D4C4A8',trustText:'#6B5544',aboutBg:'#FFFDF8',aboutImgBg:'linear-gradient(135deg,#C4A882,#D4C4A8)',aboutImgExtra:'',aboutEmoji:'🍃',featureBg:'#F4F1EC',cardBg:'#FFFDF8',cardRadius:'16px',cardBorder:'1px solid #E8DDD0',testimonialBg:'#EDE9E0',testimonialCardBg:'#FFFDF8',testimonialBorder:'1px solid #D4C4A8',ctaSectionBg:'#5A7A3A',ctaExtra:'',ctaSectionText:'#FFFDF8',ctaSectionSub:'rgba(255,253,248,0.8)',ctaSectionBtn:'#FFFDF8',ctaSectionBtnText:'#2C1A0E',footerBg:'#2C1A0E',footerBorder:'none',footerText:'#F4F1EC',headingColor:'#2C1A0E',subTextColor:'#6B5544',imgRadius:'20px',btnRadius:'40px',ctaText:'#FFFDF8',feat1:'🌱',feat2:'🤝',feat3:'🍀'},
    'luxe':{...base,primary:'#C9A84C',accent:'#C9A84C',bg:'#0A0A0A',text:'#F5F0E8',navBg:'#0A0A0A',navBorder:'1px solid #C9A84C33',navText:'#F5F0E8',heroBg:'#0A0A0A',heroText:'#F5F0E8',heroSubText:'#9A8C6E',heroImgBg:'linear-gradient(135deg,#1C1C1C,#2A2008)',heroImgCol:'0.8fr',heroPadding:'100px 48px',heroExtra:'',heroImgExtra:'border:1px solid #C9A84C44;',heroEmoji:'👑',heroBorder:'#C9A84C66',trustBg:'#0F0F0F',trustBorder:'1px solid #C9A84C22',trustText:'#9A8C6E',aboutBg:'#0F0F0F',aboutImgBg:'linear-gradient(135deg,#1C1C1C,#2A2008)',aboutImgExtra:'border:1px solid #C9A84C33;',aboutEmoji:'💫',featureBg:'#0A0A0A',cardBg:'#111',cardRadius:'8px',cardBorder:'1px solid #C9A84C22',testimonialBg:'#0F0F0F',testimonialCardBg:'#111',testimonialBorder:'1px solid #C9A84C33',ctaSectionBg:'linear-gradient(135deg,#1C1400,#2A2008)',ctaExtra:'border-top:1px solid #C9A84C33;border-bottom:1px solid #C9A84C33;',ctaSectionText:'#C9A84C',ctaSectionSub:'#9A8C6E',ctaSectionBtn:'#C9A84C',ctaSectionBtnText:'#0A0A0A',footerBg:'#050505',footerBorder:'1px solid #C9A84C22',footerText:'#9A8C6E',headingColor:'#F5F0E8',subTextColor:'#9A8C6E',imgRadius:'4px',btnRadius:'3px',ctaText:'#0A0A0A',feat1:'💎',feat2:'🤍',feat3:'✦'},
    'playful':{...base,bg:'#FFF8F0',text:'#1A0A00',navBg:'#FFFFFF',navBorder:'1px solid #FFE0B2',navText:'#1A0A00',heroBg:'#FFF8F0',heroText:'#1A0A00',heroSubText:'#7A4A00',heroImgBg:'linear-gradient(135deg,#FFE566,#FFB347)',heroImgCol:'0.85fr',heroPadding:'80px 48px',heroExtra:'',heroImgExtra:'border-radius:40% 60% 60% 40%/50% 40% 60% 50%;',heroEmoji:'🎉',heroBorder:'#FFB347',trustBg:'#FFF3E0',trustBorder:'1px solid #FFE0B2',trustText:'#7A4A00',aboutBg:'#FFFEF9',aboutImgBg:'linear-gradient(135deg,#FFE566,#FF6B6B)',aboutImgExtra:'border-radius:30% 70% 70% 30%/50%;',aboutEmoji:'🌟',featureBg:'#FFF8F0',cardBg:'#FFFFFF',cardRadius:'24px',cardBorder:'2px solid #FFE0B2',testimonialBg:'#FFF3E0',testimonialCardBg:'#FFFFFF',testimonialBorder:'2px solid #FFE0B2',ctaSectionBg:'#FF6B6B',ctaExtra:'',ctaSectionText:'#FFFFFF',ctaSectionSub:'rgba(255,255,255,0.85)',ctaSectionBtn:'#FFFFFF',ctaSectionBtnText:'#FF6B6B',footerBg:'#1A0A00',footerBorder:'none',footerText:'#FFF8F0',headingColor:'#1A0A00',subTextColor:'#7A4A00',imgRadius:'24px',btnRadius:'50px',ctaText:'#FFFFFF',feat1:'🎈',feat2:'🌈',feat3:'🏆'},
    'professional':{...base,bg:'#F0F4FA',text:'#0F172A',navBg:'#1E3A5F',navBorder:'none',navText:'#FFFFFF',heroBg:'#F0F4FA',heroText:'#0F172A',heroSubText:'#475569',heroImgBg:'linear-gradient(135deg,#CBD5E1,#94A3B8)',heroImgCol:'0.85fr',heroPadding:'80px 48px',heroExtra:'',heroImgExtra:'',heroEmoji:'💼',heroBorder:'#CBD5E1',trustBg:'#1E3A5F',trustBorder:'none',trustText:'#FFFFFF',aboutBg:'#FFFFFF',aboutImgBg:'linear-gradient(135deg,#CBD5E1,#E2E8F0)',aboutImgExtra:'',aboutEmoji:'🏢',featureBg:'#F0F4FA',cardBg:'#FFFFFF',cardRadius:'10px',cardBorder:'1px solid #E2E8F0',testimonialBg:'#1E3A5F',testimonialCardBg:'#163255',testimonialBorder:'1px solid #2A4E7A',ctaSectionBg:'#0F172A',ctaExtra:'',ctaSectionText:'#FFFFFF',ctaSectionSub:'rgba(255,255,255,0.7)',ctaSectionBtn:'#FFFFFF',ctaSectionBtnText:'#0F172A',footerBg:'#0F172A',footerBorder:'1px solid #1E3A5F',footerText:'#FFFFFF',headingColor:'#0F172A',subTextColor:'#475569',imgRadius:'10px',btnRadius:'6px',ctaText:'#FFFFFF',feat1:'📊',feat2:'🔒',feat3:'✅'},
  };
  return themes[style]||themes['light-airy'];
}

// ── START ──────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 SiteSnap running at http://localhost:${PORT}`);
  if (!process.env.STRIPE_SECRET_KEY) console.warn('   ⚠️  STRIPE_SECRET_KEY not set — payments will not work');
});
