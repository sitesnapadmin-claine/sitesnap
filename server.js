const express = require('express');
const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const crypto = require('crypto');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

// ── SENTRY (optional error monitoring — inactive until SENTRY_DSN is set) ──────
let Sentry = null;
if (process.env.SENTRY_DSN) {
  try {
    Sentry = require('@sentry/node');
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV || 'production',
      tracesSampleRate: 0, // errors only — no perf tracing (keeps free-tier usage low)
    });
    console.log('🔭 Sentry error monitoring enabled');
  } catch (e) {
    console.warn('Sentry package not installed — run: npm install @sentry/node');
    Sentry = null;
  }
}
// better-sqlite3 is a native module and only needed for the SQLite fallback —
// required lazily so a Postgres deploy never depends on it compiling.
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Stripe = require('stripe');
const paypal = require('./paypal')({
  dbGet, dbRun,
  onProEnded: (userId) => planLimits.onProEnded(userId),
  recordPayment: (p) => recordPayment(p),
  notifyAdmin: (subject, text) => notifyAdmin(subject, text),
});

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
// Railway sits in front of the app as a reverse proxy — without this,
// express-rate-limit sees Railway's proxy IP for every request (or throws,
// depending on version) instead of the real client IP.
app.set('trust proxy', 1);
app.disable('x-powered-by');

// Express 4 does not catch errors thrown by async route handlers: the request
// just hangs and the rejection goes unhandled. Wrap every route handler so a
// failure always reaches the error handler and the visitor gets a reply.
function wrapAsync(fn) {
  if (typeof fn !== 'function' || fn.length === 4) return fn; // leave error handlers alone
  return function (req, res, next) {
    try {
      const out = fn(req, res, next);
      if (out && typeof out.catch === 'function') out.catch(next);
    } catch (e) { next(e); }
  };
}
for (const method of ['get', 'post', 'put', 'delete']) {
  const original = app[method].bind(app);
  app[method] = (path, ...handlers) => {
    // app.get('setting') with one argument reads a setting; don't touch that
    if (handlers.length === 0) return original(path);
    return original(path, ...handlers.map(wrapAsync));
  };
}

// Basic security headers on every response.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  next();
});

// ── RATE LIMITING (auth endpoints only — brute force / spam prevention) ────────
// Keyed by IP. Generous enough that a real person retyping a password a few
// times never gets blocked, tight enough to make automated abuse pointless.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many accounts created from this network. Please try again later.' },
});
const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 6,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many reset requests. Please check your email or try again later.' },
});
const PORT = process.env.PORT || 3000;
// The fallback is for local development only. In production a missing secret
// would let anyone sign their own login (or admin) tokens, so refuse to start.
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET must be set in production. Refusing to start.');
}
if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
  console.warn('⚠️  JWT_SECRET is shorter than 32 characters. Generate a longer one with: openssl rand -hex 32');
}
const JWT_SECRET = process.env.JWT_SECRET || 'sitesnap-dev-secret-change-in-production';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const APP_DOMAIN = process.env.APP_DOMAIN || 'sitesnap.app';
// Where customers point their CNAME records. Must be the host that actually
// serves the app (Railway/Render/etc), NOT the marketing domain.
// Railway injects RAILWAY_PUBLIC_DOMAIN, so this stays correct on its own even
// if the deployment moves — no hardcoded hostname to go stale.
const CNAME_TARGET =
  process.env.CNAME_TARGET ||
  process.env.RAILWAY_PUBLIC_DOMAIN ||
  'sitesnap-production-b50b.up.railway.app';
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');
// Stripe is legacy. Its routes only work when it is the chosen provider and has a key.
const STRIPE_ENABLED = (process.env.PAYMENT_PROVIDER || '').toLowerCase() !== 'paypal' && Boolean(process.env.STRIPE_SECRET_KEY);

// Only this account can read /api/_diag. Unset = the endpoint doesn't exist.
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();

// Starter subdomains (yourbrand.ourdomain.com) need a domain we control with a
// wildcard certificate. Railway's own *.up.railway.app cert covers exactly one
// label, so brand.myapp.up.railway.app can never present a valid certificate.
// Rather than sell a feature that cannot work, hide it until APP_DOMAIN is a
// real product domain — at which point this flips back on by itself.
// Deliberately keyed off the raw env var, not APP_DOMAIN, which falls back to a
// placeholder. An unconfigured deploy must not advertise subdomains on a domain
// nobody owns — off unless someone explicitly sets a real one.
const APP_DOMAIN_CONFIGURED = (process.env.APP_DOMAIN || '').trim();
const SUBDOMAINS_ENABLED =
  Boolean(APP_DOMAIN_CONFIGURED) &&
  !/\.up\.railway\.app$/i.test(APP_DOMAIN_CONFIGURED) &&
  !/^localhost(:|$)/i.test(APP_DOMAIN_CONFIGURED);

// ── RAILWAY API ────────────────────────────────────────────────────────────────
// Lets us register customer domains with Railway automatically instead of
// adding each one by hand in the dashboard. If these aren't set, the app falls
// back to showing generic manual instructions (see saveCustomDomain).
// Railway injects PROJECT/ENVIRONMENT/SERVICE ids into every deployment
// automatically, so the only thing that ever needs setting by hand is the token.
const RAILWAY_API_TOKEN = process.env.RAILWAY_API_TOKEN || '';
const RAILWAY_PROJECT_ID = process.env.RAILWAY_PROJECT_ID || '';
const RAILWAY_ENVIRONMENT_ID = process.env.RAILWAY_ENVIRONMENT_ID || '';
const RAILWAY_SERVICE_ID = process.env.RAILWAY_SERVICE_ID || '';
const RAILWAY_READY = Boolean(
  RAILWAY_API_TOKEN && RAILWAY_PROJECT_ID && RAILWAY_ENVIRONMENT_ID && RAILWAY_SERVICE_ID
);

async function railwayGraphQL(query, variables = {}) {
  const res = await fetch('https://backboard.railway.com/graphql/v2', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RAILWAY_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query, variables }),
  });

  if (res.status === 429) {
    const retry = res.headers.get('Retry-After');
    throw new Error(`Railway rate limit reached. Try again in ${retry || 'a few'} seconds.`);
  }

  const json = await res.json().catch(() => null);
  if (!json) throw new Error(`Railway API returned a non-JSON response (HTTP ${res.status})`);
  if (json.errors?.length) throw new Error(json.errors.map(e => e.message).join('; '));
  return json.data;
}

// Register a domain with Railway and return the DNS records the customer needs.
// Railway is the source of truth here — we display exactly what it gives us
// rather than guessing, which also picks up the required TXT verification record.
async function railwayAddDomain(domain) {
  const avail = await railwayGraphQL(
    `query ($domain: String!) {
       customDomainAvailable(domain: $domain) { available message }
     }`,
    { domain }
  );
  if (!avail?.customDomainAvailable?.available) {
    throw new Error(avail?.customDomainAvailable?.message || 'That domain is not available.');
  }

  const created = await railwayGraphQL(
    `mutation ($input: CustomDomainCreateInput!) {
       customDomainCreate(input: $input) {
         id
         domain
         status {
           verificationToken
           dnsRecords { hostlabel requiredValue currentValue status recordType zone }
         }
       }
     }`,
    { input: {
        projectId: RAILWAY_PROJECT_ID,
        environmentId: RAILWAY_ENVIRONMENT_ID,
        serviceId: RAILWAY_SERVICE_ID,
        domain,
    } }
  );
  return created.customDomainCreate;
}

async function railwayDomainStatus(domainId) {
  const data = await railwayGraphQL(
    `query ($id: String!, $projectId: String!) {
       customDomain(id: $id, projectId: $projectId) {
         id
         domain
         status {
           verificationToken
           certificateStatus
           dnsRecords { hostlabel requiredValue currentValue status recordType zone }
         }
       }
     }`,
    { id: domainId, projectId: RAILWAY_PROJECT_ID }
  );
  return data.customDomain;
}

async function railwayDeleteDomain(domainId) {
  return railwayGraphQL(`mutation ($id: String!) { customDomainDelete(id: $id) }`, { id: domainId });
}

// ── CLOUDFLARE CUSTOM DOMAINS ──────────────────────────────────────────────────
// When Cloudflare is configured it takes over customer domains, so Railway's
// small domain limit no longer applies. Without it the app uses Railway as before.
const cloudflare = require('./cloudflare')();

// Add a customer domain with whichever provider is set up. Returns the id to
// store and the DNS records the customer needs to add.
async function registerDomain(domain) {
  if (cloudflare.ready) return cloudflare.addDomain(domain);
  const rw = await railwayAddDomain(domain);
  return { id: rw.id, records: formatDnsRecords(rw) };
}

// Ids from Cloudflare start with "cf:", everything else is a Railway id
async function removeDomain(id) {
  if (cloudflare.isCloudflareId(id)) return cloudflare.deleteDomain(id);
  return railwayDeleteDomain(id);
}

// Railway allows as few as 100 API requests/hour on the lowest tier. Impatient
// customers clicking "check" repeatedly would burn through that, so cache each
// domain's status briefly — DNS doesn't propagate faster than this anyway.
const DOMAIN_STATUS_TTL_MS = 60 * 1000;
const domainStatusCache = new Map();

function getCachedDomainStatus(domainId) {
  const hit = domainStatusCache.get(domainId);
  if (!hit) return null;
  if (Date.now() - hit.at > DOMAIN_STATUS_TTL_MS) {
    domainStatusCache.delete(domainId);
    return null;
  }
  return hit.value;
}

function clearCachedDomainStatus(domainId) {
  if (domainId) domainStatusCache.delete(domainId);
}

function setCachedDomainStatus(domainId, value) {
  domainStatusCache.set(domainId, { at: Date.now(), value });
  // Keep the map from growing without bound on a long-lived process
  if (domainStatusCache.size > 500) {
    const oldest = [...domainStatusCache.entries()].sort((a, b) => a[1].at - b[1].at)[0];
    if (oldest) domainStatusCache.delete(oldest[0]);
  }
}

// Turn Railway's DNS records into the shape the setup guide renders.
// Railway returns the routing record; the TXT verification record comes back
// separately in verificationToken, so we stitch them into one list.
function formatDnsRecords(rwDomain) {
  const st = rwDomain?.status || {};
  const records = (st.dnsRecords || []).map(r => ({
    type: r.recordType || 'CNAME',
    host: r.hostlabel || '@',
    value: r.requiredValue,
    current: r.currentValue || null,
    status: r.status || 'PENDING',
    purpose: 'routing',
  }));
  if (st.verificationToken) {
    // Railway returns the verification token without its own status field.
    // A certificate is only issued after the domain verifies, so treat ISSUED
    // as proof the TXT record landed — otherwise a working site would show
    // this record stuck on "waiting" forever.
    //
    // The TXT host is "_railway-verify." prefixed onto the same label as the
    // routing record (e.g. _railway-verify.shop for shop.example.com).
    // For wildcards the routing label is "*.sites" but the TXT drops the star:
    // "_railway-verify.sites", not "_railway-verify.*.sites".
    const routingHost = (records[0]?.host || '').replace(/^\*\./, '');
    const txtHost = routingHost && routingHost !== '@'
      ? `_railway-verify.${routingHost}`
      : '_railway-verify';
    records.push({
      type: 'TXT',
      host: txtHost,
      value: st.verificationToken,
      current: null,
      status: st.certificateStatus === 'ISSUED' ? 'VALID' : 'PENDING',
      purpose: 'verification',
    });
  }
  return records;
}

// ── EMAIL (password reset) ─────────────────────────────────────────────────────
// Reset links are useless without a way to send them, and a From address on a
// domain we don't control gets spam-filtered. Both must be set before the
// feature turns on, so it can't half-work.
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESET_FROM_EMAIL = process.env.RESET_FROM_EMAIL || '';
const EMAIL_READY = Boolean(RESEND_API_KEY && RESET_FROM_EMAIL);
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // one hour

async function sendEmail({ to, subject, html }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: RESET_FROM_EMAIL, to: [to], subject, html }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`Email provider returned ${res.status}: ${detail.slice(0, 200)}`);
  }
  return res.json();
}

// ── NEW SIGN UP ALERT ──────────────────────────────────────────────────────────
// Emails the owner each time an account is created. It never blocks or fails
// the sign up itself: if the email can't be sent, the customer still gets in
// and the problem is only logged.
const SIGNUP_NOTIFY_EMAIL = (process.env.SIGNUP_NOTIFY_EMAIL || 'sitesnap.admin@gmail.com').trim();

function buildSignupNotification({ name, email }) {
  name = String(name || '').trim().slice(0, 100);
  return {
    to: SIGNUP_NOTIFY_EMAIL,
    subject: 'You have 1 new SiteSnap sign up!',
    html: `<p>Someone just signed up to SiteSnap.</p>
<p><strong>Name:</strong> ${escHtml(name) || 'Not provided'}<br>
<strong>Email:</strong> ${escHtml(email)}</p>`,
  };
}

function notifyNewSignup(user) {
  if (!EMAIL_READY || !SIGNUP_NOTIFY_EMAIL) return Promise.resolve(false);
  return sendEmail(buildSignupNotification(user))
    .then(() => true)
    .catch(e => { console.error('signup notification error:', e.message); return false; });
}

// Alerts the owner about things that need a person, such as a payment dispute
function notifyAdmin(subject, text) {
  console.warn('ADMIN ALERT:', subject, '-', text);
  if (!EMAIL_READY || !SIGNUP_NOTIFY_EMAIL) return Promise.resolve(false);
  return sendEmail({ to: SIGNUP_NOTIFY_EMAIL, subject, html: `<p>${escHtml(text)}</p>` })
    .then(() => true)
    .catch(e => { console.error('admin alert email error:', e.message); return false; });
}

// The ledger of money actually received (and refunded). PayPal can send the
// same event more than once, so the external id makes each one count once.
async function recordPayment({ userId, provider, kind, amount, currency, externalId }) {
  const cents = Math.round(Number(amount) * 100);
  if (!externalId || !Number.isFinite(cents)) return;
  try {
    await dbRun(insertIgnore('payments', 'user_id, provider, kind, amount_cents, currency, external_id', '?, ?, ?, ?, ?, ?'),
      userId || null, provider, kind, cents, String(currency || 'USD'), String(externalId));
  } catch (e) {
    console.error('recordPayment error:', e.message);
  }
}

// Only the hash is stored, so a database leak can't be used to seize accounts.
const hashToken = t => crypto.createHash('sha256').update(String(t)).digest('hex');

// How many websites each plan may own. Editing a site is always allowed —
// this caps creation only. (After Pro ends, an account that stays over its limit past the
// 7 day deadline is restricted, see planlimits.js.)
const SITE_LIMITS = { free: 1, starter: 1, pro: Infinity };

// Pro ending: domains disconnect the same day, extra sites get 7 days (see planlimits.js)
const planLimits = require('./planlimits')({
  dbGet, dbAll, dbRun, siteLimits: SITE_LIMITS,
  deleteRailwayDomain: (id) => removeDomain(id),
  clearDomainCache: (id) => clearCachedDomainStatus(id),
});

// PayPal sends nothing when a cancelled customer's paid month runs out, so check every hour
// and end any Pro plan whose paid period is over (domains disconnect, extra sites get 7 days).
async function sweepExpiredPro() {
  try {
    const rows = await dbAll("SELECT id FROM users WHERE plan = 'pro' AND paypal_subscription_id IS NULL AND paypal_access_until IS NOT NULL AND paypal_access_until <= ?", new Date().toISOString());
    for (const r of rows) await paypal.expireIfDue(r.id);
  } catch (e) { console.error('Pro expiry check error:', e.message); }
}
// Only when actually serving (not when the test suite loads this file), and
// unref'd so the timers never keep a process alive on their own.
if (require.main === module) {
  setTimeout(sweepExpiredPro, 60 * 1000).unref();
  setInterval(sweepExpiredPro, 60 * 60 * 1000).unref();
}
async function blockIfRestricted(req, res, next) {
  try {
    const st = await planLimits.state(req.user.id);
    if (st.restricted) {
      return res.status(403).json({
        error: 'Your account is restricted because it has more sites than your plan allows. Delete the extra sites or reactivate Pro to continue.',
        restricted: true,
      });
    }
    next();
  } catch (e) { next(e); }
}

// ── PLANS ──────────────────────────────────────────────────────────────────────
const PLANS = {
  starter: { name: 'Starter', price: 2900, mode: 'payment',      label: '$29 one-time' },
  pro:     { name: 'Pro',     price: 1200, mode: 'subscription',  label: '$12/month'    },
};

// ── DIRECTORIES ────────────────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── DATABASE ───────────────────────────────────────────────────────────────────
// Two drivers behind one async API. Postgres is used whenever DATABASE_URL is
// present (Railway sets it automatically once a Postgres service is attached);
// otherwise we fall back to SQLite for local development.
//
// This matters because Railway's filesystem is ephemeral: with SQLite, every
// redeploy silently destroys every saved site. Postgres is a separate service,
// so the data survives deploys.
const DATABASE_URL = process.env.DATABASE_URL || '';
const USE_PG = Boolean(DATABASE_URL);

let pgPool = null;
let sqliteDb = null;

if (USE_PG) {
  const { Pool } = require('pg');
  pgPool = new Pool({
    connectionString: DATABASE_URL,
    max: 5,
    // Railway's internal network doesn't present a public CA
    ssl: /localhost|127\.0\.0\.1|railway\.internal/.test(DATABASE_URL)
      ? false
      : { rejectUnauthorized: false },
  });
  pgPool.on('error', e => console.error('Postgres pool error:', e.message));
} else {
  const Database = require('better-sqlite3');
  sqliteDb = new Database(path.join(__dirname, process.env.SQLITE_PATH || 'sitesnap.db'));
  sqliteDb.pragma('foreign_keys = OFF');
}

// Queries are written with `?` placeholders (SQLite style); Postgres wants $1..$n
function toPgPlaceholders(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

async function dbGet(sql, ...params) {
  if (USE_PG) return (await pgPool.query(toPgPlaceholders(sql), params)).rows[0];
  return sqliteDb.prepare(sql).get(...params);
}

async function dbAll(sql, ...params) {
  if (USE_PG) return (await pgPool.query(toPgPlaceholders(sql), params)).rows;
  return sqliteDb.prepare(sql).all(...params);
}

async function dbRun(sql, ...params) {
  if (USE_PG) {
    const r = await pgPool.query(toPgPlaceholders(sql), params);
    return { changes: r.rowCount, rows: r.rows };
  }
  const r = sqliteDb.prepare(sql).run(...params);
  return { changes: r.changes, rows: [] };
}

// Postgres reports unique violations by code; SQLite by message text
function isUniqueViolation(e) {
  return e?.code === '23505' || /UNIQUE/i.test(e?.message || '');
}

// "INSERT OR IGNORE" has no Postgres equivalent — it needs ON CONFLICT
function insertIgnore(table, cols, placeholders) {
  return USE_PG
    ? `INSERT INTO ${table} (${cols}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`
    : `INSERT OR IGNORE INTO ${table} (${cols}) VALUES (${placeholders})`;
}

async function initDb() {
  if (USE_PG) {
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan TEXT DEFAULT 'free',
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )`);
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS sites (
        id SERIAL PRIMARY KEY,
        uuid TEXT UNIQUE NOT NULL,
        user_id INTEGER,
        data TEXT NOT NULL,
        subdomain TEXT UNIQUE,
        custom_domain TEXT UNIQUE,
        railway_domain_id TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )`);
    for (const sql of [
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free'",
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_subscription_id TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_order_id TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_access_until TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS over_limit_deadline TEXT',
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS subdomain TEXT',
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS custom_domain TEXT',
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS railway_domain_id TEXT',
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified INTEGER',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token_hash TEXT',
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0',
      `CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        provider TEXT NOT NULL,
        kind TEXT NOT NULL,
        amount_cents INTEGER NOT NULL,
        currency TEXT NOT NULL,
        external_id TEXT UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )`,
    ]) { try { await pgPool.query(sql); } catch (e) { console.warn('migration skipped:', e.message); } }
    console.log('✓ Using Postgres — site data survives redeploys');
    return;
  }

  sqliteDb.exec(`
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
  [
    "ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'",
    'ALTER TABLE users ADD COLUMN stripe_customer_id TEXT',
    'ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT',
    'ALTER TABLE users ADD COLUMN paypal_subscription_id TEXT',
    'ALTER TABLE users ADD COLUMN paypal_order_id TEXT',
    'ALTER TABLE users ADD COLUMN paypal_access_until TEXT',
    'ALTER TABLE users ADD COLUMN over_limit_deadline TEXT',
    'ALTER TABLE sites ADD COLUMN subdomain TEXT',
    'ALTER TABLE sites ADD COLUMN custom_domain TEXT',
    'ALTER TABLE sites ADD COLUMN railway_domain_id TEXT',
    'ALTER TABLE sites ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP',
    'ALTER TABLE users ADD COLUMN reset_token_hash TEXT',
    'ALTER TABLE users ADD COLUMN reset_expires INTEGER',
    'ALTER TABLE users ADD COLUMN name TEXT',
    'ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0',
    'ALTER TABLE users ADD COLUMN email_verified INTEGER',
    'ALTER TABLE users ADD COLUMN verify_token_hash TEXT',
    'ALTER TABLE sites ADD COLUMN views INTEGER DEFAULT 0',
    `CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      provider TEXT NOT NULL,
      kind TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      currency TEXT NOT NULL,
      external_id TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
  ].forEach(sql => { try { sqliteDb.exec(sql); } catch (_) {} });
  console.warn('⚠️  Using SQLite — on an ephemeral host, saved sites are LOST on every redeploy.');
  console.warn('   Attach a Postgres service so DATABASE_URL is set.');
}

// ── FILE UPLOAD ────────────────────────────────────────────────────────────────
// Only real photos are accepted. The browser's claimed type is not trusted:
// the first bytes of the file are checked, and the saved name always gets the
// extension of the type actually found. SVG is refused because it can carry
// script. Without these checks an .html file labelled "image/png" was saved
// and served back from the app's own domain.
const IMAGE_TYPES = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/gif': '.gif',
  'image/webp': '.webp',
};

function sniffImageType(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'image/jpeg';
  if (buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'image/png';
  if (buf.slice(0, 6).toString('ascii') === 'GIF87a' || buf.slice(0, 6).toString('ascii') === 'GIF89a') return 'image/gif';
  if (buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  return null;
}

const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  // No extension until the contents have been checked (see /api/upload)
  filename: (req, file, cb) => cb(null, `tmp-${uuidv4()}`),
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (IMAGE_TYPES[file.mimetype]) return cb(null, true);
    cb(new Error('Please upload a JPG, PNG, WebP or GIF image.'));
  },
});

// People build their site before creating an account, so uploading can't
// require a login — but anonymous uploads get a much smaller allowance.
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: (req) => (hasValidToken(req) ? 200 : 30),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many uploads. Please wait a while and try again, or sign in.' },
});

function hasValidToken(req) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return false;
  try { jwt.verify(token, JWT_SECRET); return true; } catch { return false; }
}

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
// Stripe webhook needs raw body — mount BEFORE express.json()
// The Stripe webhook only exists while Stripe is the payment provider. With
// PayPal active it is dead code, and an exposed route that can change plans is
// a liability.
if (!paypal.enabled) {
  app.post('/api/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);
}
app.post('/api/paypal/webhook', express.raw({ type: 'application/json' }), paypal.handleWebhook);

app.use(express.json({ limit: '2mb' }));
app.use('/uploads', express.static(UPLOADS_DIR, {
  // Uploaded files are only ever images; a sandboxed, script-free policy means
  // that even a file that slipped through could never run code on this domain.
  setHeaders: (res) => res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; sandbox"),
}));

// ── DOMAIN ROUTING (check custom domains & subdomains first) ───────────────────
// Hosts that belong to SiteSnap itself. A customer must never be able to claim
// one of these as their "custom domain" or subdomain: if they could, every page
// and API call on that host would return their site and take the app offline.
function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
}
const OWN_HOSTS = new Set([
  APP_DOMAIN, hostOf(BASE_URL), CNAME_TARGET, process.env.RAILWAY_PUBLIC_DOMAIN,
  cloudflare.cnameTarget, 'localhost', '127.0.0.1', '::1',
].filter(Boolean).map(h => String(h).toLowerCase()));

function isReservedHost(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (OWN_HOSTS.has(h)) return true;
  for (const own of OWN_HOSTS) if (h.endsWith('.' + own)) return true;
  return /(^|\.)(railway\.app|up\.railway\.app|railway\.internal|localhost)$/.test(h);
}

// Labels that would look official on our own domain (admin.site-snap.app…)
const RESERVED_SUBDOMAINS = new Set([
  'www', 'app', 'api', 'admin', 'administrator', 'mail', 'email', 'smtp', 'ftp',
  'support', 'help', 'billing', 'pay', 'payments', 'secure', 'login', 'signin',
  'account', 'accounts', 'dashboard', 'status', 'blog', 'docs', 'dev', 'staging',
  'test', 'customers', 'cdn', 'static', 'assets', 'ns1', 'ns2', 'sitesnap', 'site-snap',
]);

app.use(async (req, res, next) => {
  try {
    // Traffic for a customer's own domain arrives through our Cloudflare Worker,
    // which reports the original domain in a header (ignored unless it carries
    // the shared secret).
    const host = (cloudflare.originalHost(req.headers) || req.hostname || '').toLowerCase();

    // Custom domain: only for hosts that are not our own
    if (host && !isReservedHost(host)) {
      const site = await dbGet('SELECT uuid, data FROM sites WHERE custom_domain = ?', host);
      if (site) {
        const data = JSON.parse(site.data);
        return sendSite(res, await buildWebsite(data, site.uuid, `https://${host}`));
      }
    }

    // Subdomain: exactly one label in front of our own domain (yourbrand.site-snap.app),
    // or brand.localhost while developing
    const subMatch = host.endsWith('.' + APP_DOMAIN)
      ? host.slice(0, -(APP_DOMAIN.length + 1))
      : (host.endsWith('.localhost') ? host.slice(0, -'.localhost'.length) : '');
    if (subMatch && !subMatch.includes('.') && !RESERVED_SUBDOMAINS.has(subMatch)) {
      const site = await dbGet('SELECT uuid, data FROM sites WHERE subdomain = ?', subMatch);
      if (site) {
        const data = JSON.parse(site.data);
        return sendSite(res, await buildWebsite(data, site.uuid, BASE_URL));
      }
    }

    next();
  } catch (e) {
    next(e);
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  try {
    // On an ephemeral host the user row can vanish — restore it from the JWT so
    // plan lookups keep working. (Harmless once Postgres makes data durable.)
    const exists = await dbGet('SELECT id, plan, paypal_access_until, paypal_subscription_id, token_version FROM users WHERE id = ?', req.user.id);
    // A password change bumps token_version, which signs out every other device
    if (exists && Number(req.user.tv || 0) !== Number(exists.token_version || 0)) {
      return res.status(401).json({ error: 'Your session has ended. Please sign in again.' });
    }
    // A cancelled PayPal Pro customer keeps Pro until the month they paid for ends, then drops back
    if (exists && exists.paypal_access_until && !exists.paypal_subscription_id) await paypal.expireIfDue(req.user.id);
    if (!exists && USE_PG) {
      // With Postgres a missing user really was deleted — don't rebuild it from a token
      return res.status(401).json({ error: 'Your account no longer exists. Please sign up again.' });
    }
    if (!exists) {
      await dbRun(
        insertIgnore('users', 'id, email, password_hash, plan', "?, ?, 'restored', ?"),
        req.user.id, req.user.email, req.user.plan || 'free'
      );
      // Inserting an explicit id leaves Postgres' sequence behind, which would
      // collide on the next natural signup — push it past the highest id.
      if (USE_PG) {
        await dbRun(
          "SELECT setval(pg_get_serial_sequence('users','id'), GREATEST((SELECT MAX(id) FROM users), 1))"
        );
      }
    } else if (!USE_PG && req.user.plan && req.user.plan !== 'free' && exists.plan === 'free' && !exists.paypal_access_until) {
      // Only on the SQLite fallback, where a redeploy can wipe the database.
      // With Postgres the database is the truth: trusting the plan inside an
      // old login token would hand back Pro after a cancellation or refund.
      // JWT carries a paid plan but DB shows free (post-redeploy wipe) — restore it
      await dbRun('UPDATE users SET plan = ? WHERE id = ?', req.user.plan, req.user.id);
    }
    next();
  } catch (e) {
    next(e);
  }
}

// Every login token goes through here. "tv" is the account's token_version:
// changing the password bumps it, so tokens issued before the change stop working.
function issueToken({ id, email, plan, tv }) {
  return jwt.sign({ id, email, plan: plan || 'free', tv: Number(tv || 0) }, JWT_SECRET, { expiresIn: '30d' });
}

const MIN_PASSWORD = 8;
function passwordProblem(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD) return `Password must be at least ${MIN_PASSWORD} characters`;
  if (password.length > 200) return 'That password is too long';
  return null;
}

// ── EMAIL CONFIRMATION ─────────────────────────────────────────────────────────
// email_verified: 1 confirmed, 0 waiting, NULL for accounts made before this
// existed (treated as confirmed so nobody old gets nagged). It never blocks
// using the app; it only shows a reminder and keeps reset emails accurate.
async function sendVerificationEmail(userId, email) {
  if (!EMAIL_READY) return false;
  const token = crypto.randomBytes(32).toString('hex');
  await dbRun('UPDATE users SET email_verified = 0, verify_token_hash = ? WHERE id = ?', hashToken(token), userId);
  const link = `${BASE_URL}/verify-email?token=${token}`;
  try {
    await sendEmail({
      to: email,
      subject: 'Confirm your email for SiteSnap',
      html: `<p>Welcome to SiteSnap!</p>
             <p>Please confirm this is your email address so you can always get back into your account:</p>
             <p><a href="${escHtml(link)}">Confirm my email</a></p>
             <p>If you didn't create a SiteSnap account, you can ignore this email.</p>`,
    });
    return true;
  } catch (e) {
    console.error('verification email error:', e.message);
    return false;
  }
}

// Accounts rebuilt from a JWT have no password — a JWT never carries one — so
// they get a placeholder that bcrypt can never match. Detect that state instead
// of leaving the owner permanently unable to sign in.
function isUsablePasswordHash(hash) {
  return /^\$2[aby]\$/.test(String(hash || ''));
}

function requirePlan(plan) {
  const order = ['free', 'starter', 'pro'];
  return async (req, res, next) => {
    try {
      const user = await dbGet('SELECT plan FROM users WHERE id = ?', req.user.id);
      if (order.indexOf(user?.plan || 'free') >= order.indexOf(plan)) return next();
      res.status(403).json({ error: `This feature requires the ${plan} plan.`, required: plan });
    } catch (e) {
      next(e);
    }
  };
}

// ── AUTH ROUTES ────────────────────────────────────────────────────────────────
app.post('/api/auth/register', registerLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || email.length > 254) {
    return res.status(400).json({ error: 'That doesn\'t look like a valid email address' });
  }
  const pwProblem = passwordProblem(password);
  if (pwProblem) return res.status(400).json({ error: pwProblem });
  try {
    const hash = await bcrypt.hash(password, 10);
    // RETURNING works in both Postgres and modern SQLite, so the new id comes
    // back the same way regardless of driver.
    const row = await dbGet(
      'INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?) RETURNING id',
      email.toLowerCase().trim(), hash, String((req.body || {}).name || '').trim().slice(0, 100) || null
    );
    const cleanEmail = email.toLowerCase().trim();
    const token = issueToken({ id: row.id, email: cleanEmail, plan: 'free', tv: 0 });
    res.json({ token, email: cleanEmail, plan: 'free' });
    // Sent after the reply, so a slow email provider never slows down sign up.
    notifyNewSignup({ name: req.body.name, email: cleanEmail });
    sendVerificationEmail(row.id, cleanEmail).catch(() => {});
  } catch (e) {
    if (isUniqueViolation(e)) return res.status(409).json({ error: 'That email is already registered' });
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
    return res.status(400).json({ error: 'Please enter your email and password' });
  }
  const user = await dbGet('SELECT * FROM users WHERE email = ?', email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  // Recreated-from-token accounts genuinely have no password. Saying "invalid
  // password" would be misleading and unfixable — tell them what to do instead.
  if (!isUsablePasswordHash(user.password_hash)) {
    return res.status(409).json({
      error: 'This account needs a new password. Open SiteSnap in the browser where you were last signed in, then use "Set a password".',
      code: 'PASSWORD_NOT_SET',
    });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
  const token = issueToken({ id: user.id, email: user.email, plan: user.plan, tv: user.token_version });
  res.json({ token, email: user.email, plan: user.plan || 'free' });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await dbGet('SELECT id, email, name, plan, stripe_customer_id, paypal_subscription_id, paypal_order_id, paypal_access_until, created_at, password_hash, email_verified FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password_hash, stripe_customer_id, paypal_subscription_id, paypal_order_id, paypal_access_until, email_verified, ...safe } = user;
  // Used by the "Change plan" screen: is Pro renewing, has it been cancelled (and until when), does the customer own Starter
  const planEndsAt = !paypal_subscription_id && paypal_access_until && Date.parse(paypal_access_until) > Date.now()
    ? new Date(paypal_access_until).toISOString() : null;
  const lim = await planLimits.state(req.user.id);
  res.json({
    ...safe,
    siteCount: lim.owned,
    siteLimit: lim.siteLimit,
    customDomains: lim.customDomains,
    sitesOverLimitBy: lim.excess,
    overLimitDeadline: lim.overLimitDeadline,
    restricted: lim.restricted,
    hasPaymentMethod: Boolean(stripe_customer_id || paypal_subscription_id),
    needsPassword: !isUsablePasswordHash(password_hash),
    provider: (paypal_subscription_id || paypal_order_id || paypal_access_until) ? 'paypal' : (stripe_customer_id ? 'stripe' : null),
    autoRenews: Boolean(paypal_subscription_id) || (safe.plan === 'pro' && Boolean(stripe_customer_id)),
    planEndsAt,
    ownsStarter: Boolean(paypal_order_id) || safe.plan === 'starter',
    // NULL = account from before email confirmation existed
    emailVerified: email_verified == null || Number(email_verified) === 1,
    emailConfirmationOn: EMAIL_READY,
  });
});

const verifyResendLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false });
app.post('/api/auth/resend-verification', verifyResendLimiter, requireAuth, async (req, res) => {
  if (!EMAIL_READY) return res.status(503).json({ error: 'Email isn\'t switched on yet.' });
  const user = await dbGet('SELECT email, email_verified FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.email_verified == null || Number(user.email_verified) === 1) return res.json({ ok: true, alreadyVerified: true });
  const sent = await sendVerificationEmail(req.user.id, user.email);
  if (!sent) return res.status(502).json({ error: 'Could not send the email just now. Please try again shortly.' });
  res.json({ ok: true });
});

app.get('/verify-email', async (req, res) => {
  const token = String(req.query.token || '');
  let ok = false;
  if (token) {
    const user = await dbGet('SELECT id FROM users WHERE verify_token_hash = ?', hashToken(token));
    if (user) {
      await dbRun('UPDATE users SET email_verified = 1, verify_token_hash = NULL WHERE id = ?', user.id);
      ok = true;
    }
  }
  res.status(ok ? 200 : 400).send(simplePageHtml(
    ok ? 'Email confirmed' : 'Link not valid',
    ok ? '✅' : '⚠️',
    ok ? 'Thanks! Your email address is confirmed.' : 'This confirmation link is invalid or was already used. Sign in and use “Resend email” to get a new one.',
    'Go to SiteSnap'
  ));
});

// A small branded page used for confirmations, billing results and errors
function simplePageHtml(title, icon, message, buttonLabel = 'Back to SiteSnap', extraHead = '') {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escHtml(title)} — SiteSnap</title>${extraHead}
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Inter',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#F0EBFF,#EEF2FF);padding:16px}
.box{text-align:center;background:#fff;border-radius:24px;padding:48px 32px;box-shadow:0 12px 48px rgba(108,71,255,.15);max-width:440px;width:100%}
.icon{font-size:48px;margin-bottom:16px}h1{font-size:24px;font-weight:800;color:#1A1A2E;margin-bottom:10px}
p{font-size:15px;color:#4B5563;line-height:1.55;margin-bottom:24px}
a.btn{display:inline-block;padding:12px 28px;background:#6C47FF;color:#fff;border-radius:10px;font-weight:700;text-decoration:none;font-size:15px}</style>
</head><body><main class="box"><div class="icon" aria-hidden="true">${icon}</div><h1>${escHtml(title)}</h1>
<p>${escHtml(message)}</p><a class="btn" href="/">${escHtml(buttonLabel)}</a></main></body></html>`;
}

// ── ACCOUNT: update profile (name / email) ─────────────────────────────────────
app.put('/api/account/profile', requireAuth, async (req, res) => {
  const name = String((req.body || {}).name ?? '').trim().slice(0, 100);
  const email = String((req.body || {}).email ?? '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Email is required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'That doesn\'t look like a valid email address' });
  }
  try {
    const before = await dbGet('SELECT email, plan, token_version FROM users WHERE id = ?', req.user.id);
    await dbRun('UPDATE users SET name = ?, email = ? WHERE id = ?', name, email, req.user.id);
    // Email is part of the JWT payload (used for admin checks and Stripe
    // customer lookups elsewhere), so a changed email needs a fresh token —
    // otherwise the old address would keep acting as the identity until the
    // 30-day token expires.
    const newToken = issueToken({ id: req.user.id, email, plan: before?.plan, tv: before?.token_version });
    res.json({ ok: true, name, email, token: newToken });
    // A new address needs confirming again
    if (before && before.email !== email) sendVerificationEmail(req.user.id, email).catch(() => {});
  } catch (e) {
    if (isUniqueViolation(e)) return res.status(409).json({ error: 'That email is already in use by another account' });
    console.error('update profile error:', e.message);
    res.status(500).json({ error: 'Could not update profile' });
  }
});

// ── ACCOUNT: permanent deletion ─────────────────────────────────────────────────
// Cancels any live Stripe subscription first (so the person is never charged
// again after asking to leave), then removes their sites and user row. Stripe
// customer records are left intact — Stripe itself recommends against hard-
// deleting customers with billing history — but nothing in our own database
// survives this call.
app.delete('/api/account', requireAuth, async (req, res) => {
  try {
    const user = await dbGet('SELECT stripe_subscription_id, paypal_subscription_id FROM users WHERE id = ?', req.user.id);
    if (user?.paypal_subscription_id) {
      try { await paypal.cancelSubscription(user.paypal_subscription_id, 'Account deleted'); }
      catch (e) { console.warn('account delete: PayPal cancel failed (continuing):', e.message); }
    }
    if (user?.stripe_subscription_id) {
      try { await stripe.subscriptions.cancel(user.stripe_subscription_id); }
      catch (e) { console.warn('account delete: subscription cancel failed (continuing):', e.message); }
    }
    // Release connected domains so they stop pointing at us and free the quota
    const domains = await dbAll('SELECT railway_domain_id FROM sites WHERE user_id = ? AND railway_domain_id IS NOT NULL', req.user.id);
    for (const d of domains) {
      try { await removeDomain(d.railway_domain_id); } catch (e) { console.warn('account delete: domain removal failed (continuing):', e.message); }
    }
    await dbRun('DELETE FROM sites WHERE user_id = ?', req.user.id);
    await dbRun('DELETE FROM users WHERE id = ?', req.user.id);
    res.json({ ok: true });
  } catch (e) {
    console.error('delete account error:', e.message);
    res.status(500).json({ error: 'Could not delete account. Please try again.' });
  }
});

// ── DEPLOYMENT DIAGNOSTICS ─────────────────────────────────────────────────────
// Reports which Railway project/service is serving this app and whether storage
// is durable. Read-only, no secrets: token presence is reported as a boolean.
app.get('/api/_diag', async (req, res) => {
  // Admin only. Every rejection returns a plain 404 rather than 401/403 so the
  // endpoint doesn't advertise its own existence to anyone probing for it.
  if (!ADMIN_EMAIL) return res.status(404).send(notFoundHtml());
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(404).send(notFoundHtml());
  try {
    const claims = jwt.verify(token, JWT_SECRET);
    if ((claims.email || '').toLowerCase() !== ADMIN_EMAIL) {
      return res.status(404).send(notFoundHtml());
    }
  } catch {
    return res.status(404).send(notFoundHtml());
  }

  const volumePath = process.env.RAILWAY_VOLUME_MOUNT_PATH || null;

  // Postgres returns COUNT as a string, SQLite as a number — normalise both
  let siteCount = null;
  try {
    const row = await dbGet('SELECT COUNT(*) AS c FROM sites');
    siteCount = row?.c == null ? null : Number(row.c);
  } catch { siteCount = null; }

  res.json({
    railway: {
      projectName: process.env.RAILWAY_PROJECT_NAME || null,
      projectId: RAILWAY_PROJECT_ID || null,
      environmentName: process.env.RAILWAY_ENVIRONMENT_NAME || null,
      environmentId: RAILWAY_ENVIRONMENT_ID || null,
      serviceName: process.env.RAILWAY_SERVICE_NAME || null,
      serviceId: RAILWAY_SERVICE_ID || null,
      publicDomain: process.env.RAILWAY_PUBLIC_DOMAIN || null,
      gitRepo: process.env.RAILWAY_GIT_REPO_OWNER
        ? `${process.env.RAILWAY_GIT_REPO_OWNER}/${process.env.RAILWAY_GIT_REPO_NAME}`
        : null,
    },
    storage: {
      // The critical one: without a volume or Postgres, every deploy wipes all sites
      volumeAttached: Boolean(volumePath),
      volumeMountPath: volumePath,
      postgresConfigured: Boolean(process.env.DATABASE_URL),
      durable: Boolean(volumePath || process.env.DATABASE_URL),
      driver: USE_PG ? 'postgres' : 'sqlite',
      siteCount,
    },
    features: {
      railwayDomainApi: RAILWAY_READY,
      railwayTokenSet: Boolean(RAILWAY_API_TOKEN),
      stripeConfigured: Boolean(process.env.STRIPE_SECRET_KEY),
      cloudinaryConfigured: Boolean(process.env.CLOUDINARY_CLOUD_NAME),
    },
    cnameTarget: CNAME_TARGET,
  });
});

// ── SET PASSWORD ───────────────────────────────────────────────────────────────
// Recovery for accounts rebuilt from a token, and ordinary password changes.
// Requires a valid session, so possession of the JWT is the proof of identity.
app.post('/api/auth/set-password', requireAuth, async (req, res) => {
  const { password } = req.body || {};
  const pwProblem = passwordProblem(password);
  if (pwProblem) return res.status(400).json({ error: pwProblem });
  try {
    const hash = await bcrypt.hash(String(password), 10);
    // Bumping token_version signs out every other device; this one gets a fresh token
    await dbRun('UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 0) + 1 WHERE id = ?', hash, req.user.id);
    const u = await dbGet('SELECT email, plan, token_version FROM users WHERE id = ?', req.user.id);
    res.json({ ok: true, token: issueToken({ id: req.user.id, email: u.email, plan: u.plan, tv: u.token_version }) });
  } catch (e) {
    console.error('set-password error:', e.message);
    res.status(500).json({ error: 'Could not update password' });
  }
});

// ── PASSWORD RESET ─────────────────────────────────────────────────────────────
app.post('/api/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
  const email = String((req.body || {}).email || '').toLowerCase().trim();

  if (!EMAIL_READY) {
    // Not an enumeration leak: this answer doesn't depend on the address.
    return res.status(503).json({
      error: 'Password reset isn\'t switched on yet. Please contact support to regain access.',
      code: 'RESET_UNAVAILABLE',
    });
  }
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const user = await dbGet('SELECT id, email FROM users WHERE email = ?', email);
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      await dbRun('UPDATE users SET reset_token_hash = ?, reset_expires = ? WHERE id = ?',
        hashToken(token), Date.now() + RESET_TOKEN_TTL_MS, user.id);
      const link = `${BASE_URL}/reset-password?token=${token}`;
      await sendEmail({
        to: user.email,
        subject: 'Reset your SiteSnap password',
        html: `<p>We received a request to reset your SiteSnap password.</p>
               <p><a href="${escHtml(link)}">Choose a new password</a></p>
               <p>This link works once and expires in an hour. If you didn't ask for it, you can ignore this email — nothing will change.</p>`,
      });
    }
    // Same response whether or not the address exists, so this can't be used
    // to discover who has an account.
    res.json({ ok: true, message: 'If that email has an account, a reset link is on its way.' });
  } catch (e) {
    console.error('forgot-password error:', e.message);
    res.status(500).json({ error: 'Could not send the reset email. Please try again shortly.' });
  }
});

app.post('/api/auth/reset-password', forgotPasswordLimiter, async (req, res) => {
  const { token, password } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Reset link is missing its token' });
  const pwProblem = passwordProblem(password);
  if (pwProblem) return res.status(400).json({ error: pwProblem });
  try {
    const user = await dbGet('SELECT id, reset_expires FROM users WHERE reset_token_hash = ?', hashToken(token));
    if (!user) return res.status(400).json({ error: 'This reset link is invalid or has already been used.' });
    if (!user.reset_expires || Number(user.reset_expires) < Date.now()) {
      return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' });
    }
    const hash = await bcrypt.hash(String(password), 10);
    // Clearing the token makes the link single-use
    // Also signs out every device, in case someone else had access. Clicking the
    // emailed link proves the address, so it counts as a confirmation too.
    await dbRun('UPDATE users SET password_hash = ?, reset_token_hash = NULL, reset_expires = NULL, token_version = COALESCE(token_version, 0) + 1, email_verified = 1 WHERE id = ?',
      hash, user.id);
    res.json({ ok: true });
  } catch (e) {
    console.error('reset-password error:', e.message);
    res.status(500).json({ error: 'Could not reset the password' });
  }
});

// ── PUBLIC CONFIG ──────────────────────────────────────────────────────────────
// Lets the frontend hide features that can't currently work, so we never
// advertise something a paying customer would then be unable to use.
app.get('/api/config', (req, res) => {
  res.json({
    subdomainsEnabled: SUBDOMAINS_ENABLED,
    subdomainSuffix: SUBDOMAINS_ENABLED ? APP_DOMAIN : null,
    customDomainsEnabled: true,
    passwordResetEnabled: EMAIL_READY,
  });
});

// ── SYNC PLAN (re-verify with Stripe after DB wipe) ────────────────────────────
app.post('/api/sync-plan', requireAuth, async (req, res) => {
  try {
    const email = req.user.email;
    await paypal.expireIfDue(req.user.id);
    const paypalUser = await dbGet('SELECT plan, paypal_subscription_id, paypal_order_id, paypal_access_until FROM users WHERE id = ?', req.user.id);
    if (paypalUser && (paypalUser.paypal_subscription_id || paypalUser.paypal_order_id || paypalUser.paypal_access_until)) {
      const keepPlan = paypalUser.plan || 'free';
      const keepToken = issueToken({ id: req.user.id, email: req.user.email, plan: keepPlan, tv: req.user.tv });
      return res.json({ plan: keepPlan, token: keepToken });
    }
    if (!STRIPE_ENABLED) {
      // PayPal is the payment provider: our database is already the truth
      const row = await dbGet('SELECT plan FROM users WHERE id = ?', req.user.id);
      const plan = (row && row.plan) || 'free';
      return res.json({ plan, token: issueToken({ id: req.user.id, email: req.user.email, plan, tv: req.user.tv }) });
    }
    let plan = 'free';
    let customerId = null;
    let subscriptionId = null;

    const customers = await stripe.customers.list({ email, limit: 1 });
    if (customers.data.length > 0) {
      customerId = customers.data[0].id;
      // Active subscription → pro
      const subs = await stripe.subscriptions.list({ customer: customerId, status: 'active', limit: 5 });
      if (subs.data.length > 0) {
        plan = 'pro';
        subscriptionId = subs.data[0].id;
      } else {
        // Completed one-time checkout → starter
        const sessions = await stripe.checkout.sessions.list({ customer: customerId, limit: 20 });
        const paidStarter = sessions.data.find(s =>
          s.payment_status === 'paid' && s.mode === 'payment' && s.metadata?.plan === 'starter'
        );
        if (paidStarter) plan = 'starter';
      }
    }

    if (subscriptionId && customerId) {
      await dbRun('UPDATE users SET plan = ?, stripe_customer_id = COALESCE(stripe_customer_id, ?), stripe_subscription_id = ? WHERE id = ?', plan, customerId, subscriptionId, req.user.id);
    } else if (customerId) {
      await dbRun('UPDATE users SET plan = ?, stripe_customer_id = COALESCE(stripe_customer_id, ?) WHERE id = ?', plan, customerId, req.user.id);
    } else {
      await dbRun('UPDATE users SET plan = ? WHERE id = ?', plan, req.user.id);
    }

    // Issue a new JWT with plan baked in so future redeployments preserve it
    const newToken = issueToken({ id: req.user.id, email: req.user.email, plan, tv: req.user.tv });
    res.json({ plan, token: newToken });
  } catch (e) {
    console.error('sync-plan error:', e.message);
    res.status(500).json({ error: 'Could not check your plan just now. Please try again.' });
  }
});

// ── UPLOAD ─────────────────────────────────────────────────────────────────────
app.post('/api/upload', uploadLimiter, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (!err) return next();
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'That image is too large. The limit is 15MB.' : (err.message || 'Upload failed');
    res.status(400).json({ error: msg });
  });
}, async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  // Check what the file really is from its first bytes
  let realType = null;
  try {
    const fh = await fs.promises.open(req.file.path, 'r');
    const { buffer } = await fh.read(Buffer.alloc(12), 0, 12, 0);
    await fh.close();
    realType = sniffImageType(buffer);
  } catch (_) { realType = null; }
  if (!realType) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'That file is not a valid JPG, PNG, WebP or GIF image.' });
  }

  if (cloudinary) {
    try {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'sitesnap',
        resource_type: 'image',
        transformation: [{ width: 1600, crop: 'limit', quality: 'auto', fetch_format: 'auto' }]
      });
      fs.unlink(req.file.path, () => {});
      return res.json({ url: result.secure_url });
    } catch (e) {
      console.error('Cloudinary upload error:', e.message);
      fs.unlink(req.file.path, () => {});
      // In production the local disk is wiped on every deploy, so a local copy
      // would quietly break the customer's site later. Better to say so now.
      if (process.env.NODE_ENV === 'production') {
        return res.status(502).json({ error: 'We could not save that image just now. Please try again.' });
      }
      return res.status(502).json({ error: 'Image storage failed: ' + e.message });
    }
  }

  // Local disk (development only, or when Cloudinary isn't set up)
  const finalName = path.basename(req.file.path).replace(/^tmp-/, '') + IMAGE_TYPES[realType];
  await fs.promises.rename(req.file.path, path.join(UPLOADS_DIR, finalName));
  res.json({ url: `${BASE_URL}/uploads/${finalName}` });
});

// ── SITES ──────────────────────────────────────────────────────────────────────
// Sites hold text and image links only (images are uploaded separately), so
// anything far bigger than a real site is refused rather than stored.
const MAX_SITE_BYTES = 300 * 1024;
function siteDataProblem(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return 'Site data is required';
  if (Buffer.byteLength(JSON.stringify(data)) > MAX_SITE_BYTES) return 'This site has too much content to save. Please shorten some text or remove some photos.';
  return null;
}

app.post('/api/sites', requireAuth, blockIfRestricted, async (req, res) => {
  const { data } = req.body || {};
  const dataProblem = siteDataProblem(data);
  if (dataProblem) return res.status(400).json({ error: dataProblem });
  const user = await dbGet('SELECT plan FROM users WHERE id = ?', req.user.id);
  const plan = user?.plan || 'free';

  // Site allowance per plan. Starter is a one-time payment, so leaving it
  // unlimited would let $29 buy what the recurring Pro plan is meant to sell.
  const limit = SITE_LIMITS[plan] ?? SITE_LIMITS.free;
  if (limit !== Infinity) {
    const row = await dbGet('SELECT COUNT(*) AS c FROM sites WHERE user_id = ?', req.user.id);
    const owned = Number(row?.c || 0);
    if (owned >= limit) {
      return res.status(403).json({
        error: plan === 'pro'
          ? 'Site limit reached.'
          : `Your ${plan} plan includes ${limit} website. Upgrade to Pro to build more.`,
        limitReached: true, limit, owned, plan,
      });
    }
  }

  const uuid = uuidv4();
  await dbRun('INSERT INTO sites (uuid, user_id, data) VALUES (?, ?, ?)', uuid, req.user.id, JSON.stringify(data));
  res.json({ uuid, url: `${BASE_URL}/preview/${uuid}`, plan });
});

// ── UPDATE SITE ────────────────────────────────────────────────────────────────
app.put('/api/sites/:uuid', requireAuth, blockIfRestricted, async (req, res) => {
  const { data } = req.body || {};
  const dataProblem = siteDataProblem(data);
  if (dataProblem) return res.status(400).json({ error: dataProblem });
  const site = await dbGet('SELECT user_id FROM sites WHERE uuid = ?', req.params.uuid);
  if (!site) return res.status(404).json({ error: 'Site not found' });
  if (site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });
  // CURRENT_TIMESTAMP is ANSI SQL — works unchanged on both the Postgres and
  // SQLite drivers, so this needs no dialect branching like toPgPlaceholders.
  await dbRun('UPDATE sites SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE uuid = ?', JSON.stringify(data), req.params.uuid);
  res.json({ uuid: req.params.uuid, url: `${BASE_URL}/preview/${req.params.uuid}` });
});

app.get('/api/sites', requireAuth, async (req, res) => {
  const rows = await dbAll('SELECT uuid, subdomain, custom_domain, created_at, updated_at, data FROM sites WHERE user_id = ? ORDER BY created_at DESC', req.user.id);
  res.json(rows.map(r => {
    const d = JSON.parse(r.data);
    return {
      uuid: r.uuid, subdomain: r.subdomain, customDomain: r.custom_domain,
      created_at: r.created_at, updated_at: r.updated_at || r.created_at,
      bizName: d.bizName, industry: d.industry, location: d.location, designStyle: d.designStyle,
      // Dashboard site cards use the site's own palette for their header strip —
      // it's the one part of the dashboard that's automatically personal.
      colorPrimary: d.colorPrimary, colorAccent: d.colorAccent,
    };
  }));
});

app.get('/api/sites/:uuid', async (req, res) => {
  const row = await dbGet('SELECT data FROM sites WHERE uuid = ?', req.params.uuid);
  if (!row) return res.status(404).json({ error: 'Site not found' });
  res.json(JSON.parse(row.data));
});

app.delete('/api/sites/:uuid', requireAuth, async (req, res) => {
  const row = await dbGet('SELECT user_id, railway_domain_id FROM sites WHERE uuid = ?', req.params.uuid);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });
  // Release the connected domain so it stops pointing at us and frees the quota
  if (row.railway_domain_id) {
    try { await removeDomain(row.railway_domain_id); } catch (e) { console.warn('site delete: domain removal failed (continuing):', e.message); }
  }
  await dbRun('DELETE FROM sites WHERE uuid = ?', req.params.uuid);
  res.json({ ok: true });
});

// ── SUBDOMAIN (Starter+) ───────────────────────────────────────────────────────
app.post('/api/sites/:uuid/subdomain', requireAuth, requirePlan('starter'), async (req, res) => {
  if (!SUBDOMAINS_ENABLED) {
    return res.status(503).json({
      error: 'Subdomains aren\'t available yet. Your custom domain option still works.',
    });
  }
  const { subdomain } = req.body || {};
  if (!subdomain) return res.status(400).json({ error: 'Subdomain is required' });
  const clean = String(subdomain).toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 30);
  if (!clean || /^-|-$/.test(clean)) return res.status(400).json({ error: 'Invalid subdomain' });
  if (RESERVED_SUBDOMAINS.has(clean)) return res.status(400).json({ error: 'That name is reserved. Please choose another.' });

  const site = await dbGet('SELECT user_id FROM sites WHERE uuid = ?', req.params.uuid);
  if (!site || site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });

  try {
    await dbRun('UPDATE sites SET subdomain = ? WHERE uuid = ?', clean, req.params.uuid);
    res.json({ subdomain: clean, url: `https://${clean}.${APP_DOMAIN}` });
  } catch (e) {
    if (isUniqueViolation(e)) return res.status(409).json({ error: 'That subdomain is already taken' });
    res.status(500).json({ error: 'Could not set subdomain' });
  }
});

// ── CUSTOM DOMAIN (Pro) ────────────────────────────────────────────────────────
app.post('/api/sites/:uuid/domain', requireAuth, requirePlan('pro'), async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain is required' });
  const clean = String(domain).toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/$/, '');

  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(clean)) {
    return res.status(400).json({ error: 'That doesn\'t look like a valid domain. Example: www.yourbrand.com' });
  }

  if (isReservedHost(clean)) {
    return res.status(400).json({ error: 'That address belongs to SiteSnap and can\'t be used as a custom domain. Please use your own domain, for example www.yourbrand.com' });
  }

  const site = await dbGet('SELECT user_id, custom_domain, railway_domain_id FROM sites WHERE uuid = ?', req.params.uuid);
  if (!site || site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });

  // Root domains can't use CNAME — flagged so the guide can warn about ALIAS/ANAME
  const isRoot = clean.split('.').length === 2;

  // No Railway credentials configured — save locally and show manual instructions.
  // The domain won't actually route until someone adds it in the Railway dashboard.
  if (!RAILWAY_READY && !cloudflare.ready) {
    try {
      await dbRun('UPDATE sites SET custom_domain = ? WHERE uuid = ?', clean, req.params.uuid);
    } catch (e) {
      if (isUniqueViolation(e)) return res.status(409).json({ error: 'That domain is already connected to another site' });
      return res.status(500).json({ error: 'Could not save domain' });
    }
    // We deliberately do NOT invent DNS values here. Railway mints a unique
    // CNAME target per domain (e.g. 33xjvv2c.up.railway.app) plus a matching
    // TXT verification token — neither can be derived from the app's own URL.
    // Guessing produces records that look plausible, fail silently, and cost
    // the customer hours. Better to say we don't know yet.
    return res.json({
      domain: clean,
      isRoot,
      autoProvisioned: false,
      records: [],
      needsManualSetup: true,
      message: 'Your domain is saved. We\'ll email you the two DNS records to add shortly.',
    });
  }

  const oldDomainId = site.railway_domain_id;
  const sameDomain = Boolean(oldDomainId) && site.custom_domain === clean;
  try {
    // Saving the same domain again: Railway will not accept a duplicate, so the
    // old registration has to go first. For a different domain we add the new
    // one first and only remove the old one once that has worked, so a refusal
    // from Railway never leaves the customer with no domain at all.
    if (sameDomain) {
      try { await removeDomain(oldDomainId); } catch (_) {}
      clearCachedDomainStatus(oldDomainId);
    }

    const reg = await registerDomain(clean);
    // A freshly registered domain must never report a previous domain's status
    clearCachedDomainStatus(reg.id);

    await dbRun('UPDATE sites SET custom_domain = ?, railway_domain_id = ? WHERE uuid = ?', clean, reg.id, req.params.uuid);

    if (oldDomainId && !sameDomain) {
      try { await removeDomain(oldDomainId); } catch (e) { console.warn('Could not remove old domain:', e.message); }
      clearCachedDomainStatus(oldDomainId);
    }

    res.json({
      domain: clean,
      isRoot,
      autoProvisioned: true,
      records: reg.records,
    });
  } catch (e) {
    if (isUniqueViolation(e)) {
      return res.status(409).json({ error: 'That domain is already connected to another site' });
    }
    console.error('Railway domain error:', e.message);
    // The re-save path removed the old registration before failing, so make
    // sure the database does not keep pointing at something that is gone.
    if (sameDomain) {
      try { await dbRun('UPDATE sites SET railway_domain_id = NULL WHERE uuid = ?', req.params.uuid); } catch (_) {}
    }
    // Railway's own wording ("upgrade to add more") would confuse a customer who
    // is already on Pro, so show a friendly message and keep the detail for us.
    if (/custom domain limit|upgrade to add more|custom hostname.*(limit|quota)|quota.*custom hostname/i.test(e.message || '')) {
      if (Sentry) Sentry.captureException(e);
      return res.status(503).json({ error: 'We cannot connect new domains at this moment. Your site and your plan are safe. Please try again soon, or email ' + LEGAL_CONTACT_EMAIL + ' and we will get it connected for you.' });
    }
    res.status(502).json({ error: e.message || 'Could not register the domain. Please try again.' });
  }
});

// Caddy on-demand TLS: called by Caddy before issuing a cert for a custom domain
app.get('/api/domain/verify', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).end();
  const site = await dbGet('SELECT id FROM sites WHERE custom_domain = ?', domain);
  site ? res.status(200).end() : res.status(404).end();
});

// DNS check: resolve domain CNAME and report if it points to sitesnap
app.get('/api/domain/dns-check', requireAuth, async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  try {
    // Prefer Railway's own view — it's authoritative about whether the domain
    // is verified and whether the certificate has been issued.
    const site = await dbGet('SELECT railway_domain_id, user_id FROM sites WHERE custom_domain = ?', String(domain).toLowerCase());
    // Only report on domains connected to one of your own sites
    if (!site || site.user_id !== req.user.id) return res.status(404).json({ error: 'That domain is not connected to any of your sites' });
    // Cloudflare registrations carry a "cf:" id
    if (cloudflare.ready && cloudflare.isCloudflareId(site?.railway_domain_id)) {
      const cached = getCachedDomainStatus(site.railway_domain_id);
      const cf = cached || await cloudflare.domainStatus(site.railway_domain_id, domain);
      if (!cached) setCachedDomainStatus(site.railway_domain_id, cf);
      const routingValid = cf.records.every(r => r.status === 'VALID');
      return res.json({
        domain,
        source: 'cloudflare',
        records: cf.records,
        certificateStatus: cf.certificateStatus,
        pointed: routingValid,
        live: cf.certificateStatus === 'ISSUED' && routingValid,
        cached: Boolean(cached),
      });
    }

    if (RAILWAY_READY && site?.railway_domain_id && !cloudflare.isCloudflareId(site.railway_domain_id)) {
      const cached = getCachedDomainStatus(site.railway_domain_id);
      const rw = cached || await railwayDomainStatus(site.railway_domain_id);
      if (!cached) setCachedDomainStatus(site.railway_domain_id, rw);

      const records = formatDnsRecords(rw);
      const certStatus = rw?.status?.certificateStatus || 'PENDING';
      // Routing records are the ones Railway reports a real status for.
      const routing = records.filter(r => r.purpose === 'routing');
      const routingValid = routing.length > 0 && routing.every(r => r.status === 'VALID');
      return res.json({
        domain,
        source: 'railway',
        records,
        certificateStatus: certStatus,
        pointed: routingValid,
        // An issued certificate is the definitive "this domain works" signal
        live: certStatus === 'ISSUED',
        cached: Boolean(cached),
      });
    }

    // Fallback: plain DNS lookup when Railway isn't wired up
    let cnames = [];
    let aRecords = [];
    try { cnames = await dns.resolveCname(domain); } catch(_) {}
    try { aRecords = await dns.resolve4(domain); } catch(_) {}
    const pointed = cnames.some(c =>
      c.includes(APP_DOMAIN) || c.includes('railway.app') || c.includes(CNAME_TARGET)
    );
    const hasRecords = cnames.length > 0 || aRecords.length > 0;
    res.json({ domain, source: 'dns', cnames, aRecords, pointed, hasRecords, target: CNAME_TARGET });
  } catch (e) {
    res.status(500).json({ error: 'DNS lookup failed', detail: e.message });
  }
});

// ── STRIPE CHECKOUT ────────────────────────────────────────────────────────────
app.post('/api/checkout/:plan', requireAuth, async (req, res) => {
  const planKey = req.params.plan;
  if (!PLANS[planKey]) return res.status(400).json({ error: 'Unknown plan' });

  const user = await dbGet('SELECT * FROM users WHERE id = ?', req.user.id);
  const plan = PLANS[planKey];

  if (paypal.enabled) {
    if (planKey === 'pro' && user.paypal_subscription_id) return res.status(400).json({ error: 'You already have an active Pro subscription.' });
    if (planKey === 'starter' && (user.plan === 'starter' || user.paypal_order_id)) return res.status(400).json({ error: 'You already own Starter.' });
    try {
      const url = await paypal.startCheckout({ planKey, user, baseUrl: BASE_URL });
      return res.json({ url });
    } catch (e) {
      console.error('PayPal checkout error:', e.message);
      return res.status(500).json({ error: 'Could not start PayPal checkout. Please try again.' });
    }
  }

  if (!STRIPE_ENABLED) return res.status(503).json({ error: 'Payments are not available right now. Please try again later.' });
  try {
    // Get or create Stripe customer
    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, metadata: { userId: String(user.id) } });
      customerId = customer.id;
      await dbRun('UPDATE users SET stripe_customer_id = ? WHERE id = ?', customerId, user.id);
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

// Cancel Pro from the "Change plan" screen (PayPal). Pro stays until the paid month ends.
app.post('/api/billing/cancel', requireAuth, async (req, res) => {
  const user = await dbGet('SELECT paypal_subscription_id FROM users WHERE id = ?', req.user.id);
  if (!user?.paypal_subscription_id) return res.status(400).json({ error: 'There is no active subscription to cancel.' });
  try {
    const planEndsAt = await paypal.cancelForUser(req.user.id, user.paypal_subscription_id);
    res.json({ ok: true, planEndsAt });
  } catch (e) {
    console.error('PayPal cancel error:', e.message);
    res.status(500).json({ error: 'Could not cancel just now. Please try again, or manage it in PayPal.' });
  }
});

// Billing portal (manage subscription)
app.post('/api/billing/portal', requireAuth, async (req, res) => {
  const user = await dbGet('SELECT stripe_customer_id, paypal_subscription_id, paypal_access_until FROM users WHERE id = ?', req.user.id);
  if (user?.paypal_subscription_id) return res.json({ url: paypal.manageUrl() });
  if (!user?.stripe_customer_id) {
    const until = user?.paypal_access_until ? new Date(user.paypal_access_until) : null;
    if (until && until.getTime() > Date.now()) {
      const when = until.toLocaleDateString('en-US', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
      return res.status(400).json({ error: 'No billing account found', message: 'Your subscription is cancelled. You keep Pro until ' + when + '.' });
    }
    return res.status(400).json({ error: 'No billing account found', message: 'There is no active subscription to manage.' });
  }
  if (!STRIPE_ENABLED) return res.status(400).json({ error: 'No billing account found', message: 'There is no active subscription to manage.' });
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
    // Never accept an unsigned event: without the secret anyone could post a
    // fake "payment completed" and upgrade any account for free.
    if (!secret) {
      console.error('Stripe webhook received but STRIPE_WEBHOOK_SECRET is not set; rejecting.');
      return res.status(503).send('Webhook not configured');
    }
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
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
        await dbRun('UPDATE users SET plan = ? WHERE id = ?', plan, userId);
        if (session.subscription) {
          await dbRun('UPDATE users SET stripe_subscription_id = ? WHERE id = ?', session.subscription, userId);
        }
        console.log(`✓ User ${userId} upgraded to ${plan}`);
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const endedUser = await dbGet('SELECT id FROM users WHERE stripe_subscription_id = ?', sub.id);
      await dbRun("UPDATE users SET plan = 'free', stripe_subscription_id = NULL WHERE stripe_subscription_id = ?", sub.id);
      if (endedUser) await planLimits.onProEnded(endedUser.id);
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

// ── RESET PASSWORD PAGE ────────────────────────────────────────────────────────
// Standalone page the email link opens. Kept separate from the wizard so it
// works even for someone who can't sign in.
app.get('/reset-password', (req, res) => {
  const token = String(req.query.token || '');
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Choose a new password — SiteSnap</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Inter',sans-serif;background:#F7F7FB;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.card{background:#fff;border-radius:20px;padding:40px;max-width:420px;width:100%;box-shadow:0 10px 40px rgba(108,71,255,.12)}
h1{font-size:22px;font-weight:800;color:#1A1A2E;margin-bottom:8px}
p.sub{font-size:14px;color:#6B7280;line-height:1.6;margin-bottom:24px}
label{display:block;font-size:13px;font-weight:600;color:#374151;margin-bottom:6px}
.pw-wrap{position:relative}
input{width:100%;padding:13px 14px;border:1.5px solid #E5E7EB;border-radius:10px;font-size:15px;font-family:inherit}
.pw-wrap input{padding-right:44px}
input:focus{outline:none;border-color:#6C47FF}
.pw-toggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:32px;height:32px;display:flex;align-items:center;justify-content:center;background:none;border:none;cursor:pointer;color:#9CA3AF;border-radius:8px;padding:0}
.pw-toggle:hover{color:#374151;background:rgba(0,0,0,.04)}
.pw-toggle svg{width:18px;height:18px}
button{width:100%;margin-top:16px;padding:14px;background:#6C47FF;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;font-family:inherit}
button:disabled{opacity:.6;cursor:default}
.msg{margin-top:14px;font-size:13px;line-height:1.5}
.ok{color:#059669}.bad{color:#DC2626}
a{color:#6C47FF;font-weight:600;text-decoration:none}</style></head><body>
<div class="card">
  <h1>Choose a new password</h1>
  <p class="sub">Pick something you'll remember. This link works once.</p>
  <label for="pw">New password</label>
  <div class="pw-wrap">
    <input type="password" id="pw" placeholder="At least 8 characters" autocomplete="new-password">
    <button type="button" class="pw-toggle" aria-label="Show password" onclick="togglePw()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg></button>
  </div>
  <button id="go" onclick="submitReset()">Save new password</button>
  <div class="msg" id="msg"></div>
</div>
<script>
const TOKEN = ${JSON.stringify(token)};
const EYE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
const EYE_OFF = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a18.68 18.68 0 0 1 4.22-5.94"></path><path d="M9.9 4.24A10.4 10.4 0 0 1 12 4c7 0 11 8 11 8a18.68 18.68 0 0 1-2.16 3.19"></path><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';
function togglePw(){
  const input = document.getElementById('pw');
  const btn = document.querySelector('.pw-toggle');
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  btn.innerHTML = isHidden ? EYE_OFF : EYE;
  btn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
}
async function submitReset(){
  const pw = document.getElementById('pw').value;
  const msg = document.getElementById('msg');
  const btn = document.getElementById('go');
  if (pw.length < 8){ msg.className='msg bad'; msg.textContent='Please use at least 8 characters.'; return; }
  btn.disabled = true; msg.className='msg'; msg.textContent='Saving…';
  try{
    const r = await fetch('/api/auth/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ token: TOKEN, password: pw })});
    const d = await r.json();
    if(!r.ok) throw new Error(d.error || 'Something went wrong');
    msg.className='msg ok';
    msg.innerHTML='✓ Password updated. <a href="/">Sign in now →</a>';
    btn.style.display='none';
  }catch(e){
    msg.className='msg bad'; msg.textContent = e.message; btn.disabled=false;
  }
}
document.getElementById('pw').addEventListener('keydown', e => { if(e.key==='Enter') submitReset(); });
</script></body></html>`);
});

// ── ADMIN DASHBOARD ─────────────────────────────────────────────────────────────
// A single shared password (set via ADMIN_PASSWORD) gates a read-only overview
// of signups, plans, and saved sites — so the owner can check on the business
// without touching the database or an API client.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Admin login required' });
  try {
    const claims = jwt.verify(token, JWT_SECRET);
    if (!claims.admin) throw new Error('not an admin token');
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired admin session' });
  }
}

app.post('/api/admin/login', adminLoginLimiter, (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: 'Admin dashboard is not configured yet (ADMIN_PASSWORD not set).' });
  const { password } = req.body || {};
  const given = crypto.createHash('sha256').update(String(password || '')).digest();
  const wanted = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
  if (!crypto.timingSafeEqual(given, wanted)) return res.status(401).json({ error: 'Incorrect password' });
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

app.get('/api/admin/overview', requireAdmin, async (req, res) => {
  try {
    const byPlan = await dbAll("SELECT plan, COUNT(*) as count FROM users GROUP BY plan");
    const counts = { free: 0, starter: 0, pro: 0 };
    byPlan.forEach(r => { counts[r.plan || 'free'] = Number(r.count); });
    const totalUsers = counts.free + counts.starter + counts.pro;

    const totalSitesRow = await dbGet('SELECT COUNT(*) as count FROM sites');
    const totalSites = Number(totalSitesRow?.count || 0);

    // Estimated, current-state revenue — Starter is one-time so this counts
    // everyone currently marked starter; Pro is recurring so this is live MRR.
    // There's no separate purchase ledger, so past upgrades that later
    // downgraded/cancelled won't show here — it's a snapshot, not history.
    const mrr = counts.pro * ((PLANS.pro?.price || 1200) / 100);
    const starterRevenue = counts.starter * ((PLANS.starter?.price || 2900) / 100);

    // Money actually received, from the payments ledger (refunds are negative)
    const sinceSql = USE_PG ? "NOW() - INTERVAL '30 days'" : "datetime('now','-30 days')";
    const allTime = await dbGet('SELECT COALESCE(SUM(amount_cents), 0) AS c FROM payments');
    const last30 = await dbGet(`SELECT COALESCE(SUM(amount_cents), 0) AS c FROM payments WHERE created_at >= ${sinceSql}`);
    const recentPayments = await dbAll(
      'SELECT p.kind, p.amount_cents, p.currency, p.created_at, u.email FROM payments p LEFT JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 20'
    );

    const sinceClause = USE_PG ? "NOW() - INTERVAL '30 days'" : "datetime('now','-30 days')";
    const signupRows = await dbAll(
      `SELECT DATE(created_at) as day, COUNT(*) as count FROM users WHERE created_at >= ${sinceClause} GROUP BY DATE(created_at) ORDER BY day`
    );

    res.json({
      totalUsers,
      byPlan: counts,
      totalSites,
      mrr,
      starterRevenue,
      revenueAllTime: Number(allTime?.c || 0) / 100,
      revenueLast30Days: Number(last30?.c || 0) / 100,
      recentPayments: recentPayments.map(r => ({ kind: r.kind, amount: Number(r.amount_cents) / 100, currency: r.currency, at: r.created_at, email: r.email || null })),
      signupsLast30Days: signupRows.map(r => ({ day: r.day, count: Number(r.count) })),
    });
  } catch (e) {
    console.error('admin/overview error:', e.message);
    res.status(500).json({ error: 'Could not load overview' });
  }
});

app.get('/api/admin/customers', requireAdmin, async (req, res) => {
  try {
    const search = (req.query.search || '').trim().toLowerCase();
    const users = search
      ? await dbAll('SELECT id, email, name, plan, stripe_customer_id, created_at FROM users WHERE LOWER(email) LIKE ? ORDER BY created_at DESC', `%${search}%`)
      : await dbAll('SELECT id, email, name, plan, stripe_customer_id, created_at FROM users ORDER BY created_at DESC');

    const sites = await dbAll('SELECT uuid, user_id, subdomain, custom_domain, created_at, data FROM sites ORDER BY created_at DESC');
    const sitesByUser = {};
    for (const s of sites) {
      let bizName = '(untitled)';
      try { bizName = JSON.parse(s.data).bizName || bizName; } catch (_) {}
      (sitesByUser[s.user_id] ||= []).push({
        uuid: s.uuid,
        bizName,
        url: `${BASE_URL}/preview/${s.uuid}`,
        customDomain: s.custom_domain || null,
        createdAt: s.created_at,
      });
    }

    res.json(users.map(u => ({
      id: u.id,
      email: u.email,
      name: u.name || null,
      plan: u.plan || 'free',
      hasBilling: Boolean(u.stripe_customer_id),
      createdAt: u.created_at,
      sites: sitesByUser[u.id] || [],
    })));
  } catch (e) {
    console.error('admin/customers error:', e.message);
    res.status(500).json({ error: 'Could not load customers' });
  }
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── PREVIEW ROUTE ──────────────────────────────────────────────────────────────
app.get('/preview/:uuid', async (req, res) => {
  const row = await dbGet('SELECT data FROM sites WHERE uuid = ?', req.params.uuid);
  if (!row) return res.status(404).send(notFoundHtml());
  sendSite(res, await buildWebsite(JSON.parse(row.data), req.params.uuid, BASE_URL));
});

// ── BILLING PAGES ──────────────────────────────────────────────────────────────
// Don't rely on the webhook alone to flip the plan — it's usually fast, but if
// it lands late (or Stripe's endpoint config is off) the customer lands here
// on a still-"free" account. We hold the Checkout Session id, so confirm it
// ourselves and write the plan directly; the webhook remains the source of
// truth for later events (renewals, cancellations) but is no longer a single
// point of failure for the very first upgrade.
app.get('/billing/success', async (req, res) => {
  const wanted = PLANS[req.query.plan] ? req.query.plan : null;
  let confirmed = null; // { plan } once we know the payment really went through
  if (paypal.enabled && req.query.provider === 'paypal') confirmed = await paypal.confirmReturn(req.query);
  const sessionId = req.query.session_id;
  if (sessionId && STRIPE_ENABLED) {
    try {
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const userId = parseInt(session.metadata?.userId);
      const sessionPlan = session.metadata?.plan;
      if (session.payment_status === 'paid' && userId && PLANS[sessionPlan]) {
        await dbRun('UPDATE users SET plan = ? WHERE id = ?', sessionPlan, userId);
        if (session.subscription) {
          await dbRun('UPDATE users SET stripe_subscription_id = ? WHERE id = ?', session.subscription, userId);
        }
        confirmed = { plan: sessionPlan };
        console.log(`✓ User ${userId} upgraded to ${sessionPlan} (confirmed via success redirect)`);
      }
    } catch (e) {
      console.error('billing/success session verification error:', e.message);
      // Fall through — the webhook may still land and fix this up.
    }
  }
  if (confirmed) {
    const label = PLANS[confirmed.plan]?.name || 'your new plan';
    return res.send(simplePageHtml(`Welcome to ${label}!`, '🎉',
      'Your payment is confirmed and your account has been upgraded. Taking you back to the app…',
      'Go to my account', '<meta http-equiv="refresh" content="5; url=/">'));
  }
  // Not confirmed yet: PayPal can take a minute to tell us. Never claim success early.
  const label = wanted ? PLANS[wanted].name : 'your plan';
  res.send(simplePageHtml('Confirming your payment…', '⏳',
    `Thanks! We're waiting for PayPal to confirm your ${label} payment. This usually takes under a minute. Your account updates on its own, so you can head back now. If it hasn't changed within an hour, email ${LEGAL_CONTACT_EMAIL}.`,
    'Back to my account', '<meta http-equiv="refresh" content="20">'));
});

app.get('/billing/cancel', (req, res) => {
  res.send(simplePageHtml('Checkout cancelled', '👋', 'No worries, you weren\'t charged. Taking you back…', 'Back to SiteSnap',
    '<meta http-equiv="refresh" content="3; url=/">'));
});

// ── LEGAL PAGES ─────────────────────────────────────────────────────────────────
const LEGAL_CONTACT_EMAIL = 'sitesnap.admin@gmail.com';
const LEGAL_UPDATED = 'August 8, 2026';

function legalPageHtml(title, bodyHtml) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${title} — SiteSnap</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;}
body{font-family:'Inter',sans-serif;color:#1A1A2E;background:#F9FAFB;margin:0;line-height:1.6;}
.wrap{max-width:720px;margin:0 auto;padding:48px 24px 80px;}
a.back{color:#6C47FF;text-decoration:none;font-weight:600;font-size:14px;}
h1{font-size:30px;font-weight:800;margin:24px 0 4px;}
.updated{color:#6B7280;font-size:13px;margin-bottom:32px;}
h2{font-size:18px;font-weight:700;margin:32px 0 10px;}
p,li{color:#374151;font-size:15px;margin-bottom:12px;}
ul{padding-left:22px;margin-bottom:12px;}
.note{background:#EEF2FF;border:1px solid #E0E7FF;border-radius:10px;padding:14px 18px;font-size:13px;color:#4338CA;margin:28px 0;}
</style></head><body><div class="wrap">
<a class="back" href="/">← Back to SiteSnap</a>
<h1>${title}</h1>
<div class="updated">Last updated: ${LEGAL_UPDATED}</div>
${bodyHtml}
</div></body></html>`;
}

app.get('/terms', (req, res) => {
  res.send(legalPageHtml('Terms of Service', `
<p>These Terms of Service ("Terms") govern your use of SiteSnap (the "Service"), operated by SiteSnap ("we", "us"). By creating an account or using the Service, you agree to these Terms.</p>

<h2>1. The Service</h2>
<p>SiteSnap lets you generate and publish a website for your business by answering a series of questions. We host the pages you create and, on paid plans, provision a custom domain for you.</p>

<h2>2. Your account</h2>
<p>You're responsible for keeping your login credentials secure and for all activity under your account. You must be able to enter a legally binding contract to use the Service.</p>

<h2>3. Plans and billing</h2>
<ul>
<li>Free plan: limited to 1 published site.</li>
<li>Starter: one-time payment, removes the SiteSnap badge and adds a subdomain, limited to 1 site.</li>
<li>Pro: monthly subscription, adds support for your own custom domain and unlimited sites.</li>
</ul>
<p>Paid plans are billed through PayPal. Pro renews monthly until cancelled. You can cancel from the Your plan screen in your account, and Pro stays active until the end of the month you have paid for. Fees already charged are non-refundable except where required by law.</p>

<h2>4. Your content</h2>
<p>You keep ownership of the text, images, and other content you upload or enter. You're responsible for having the rights to anything you upload, and for making sure your published site doesn't violate anyone else's rights or the law. We can remove content or suspend a site that we reasonably believe breaks these Terms or the law.</p>

<h2>5. Acceptable use</h2>
<p>Don't use the Service to publish illegal content, malware, or material that infringes someone else's intellectual property, and don't try to abuse, overload, or gain unauthorized access to the Service.</p>

<h2>6. Custom domains</h2>
<p>When you connect your own domain, you're responsible for your domain registration and DNS settings. We provision the domain and SSL certificate through our hosting provider; availability can depend on that provider's own limits.</p>

<h2>7. Service availability</h2>
<p>We aim to keep the Service running reliably but don't guarantee uninterrupted uptime. We may change or discontinue features with notice where reasonably possible.</p>

<h2>8. Termination</h2>
<p>You can delete your account at any time from My Account, which permanently deletes your sites and cancels any active subscription. We may suspend or terminate accounts that violate these Terms.</p>

<h2>9. Disclaimer and liability</h2>
<p>The Service is provided "as is" without warranties of any kind. To the extent permitted by law, SiteSnap isn't liable for indirect, incidental, or consequential damages arising from your use of the Service.</p>

<h2>10. Changes to these Terms</h2>
<p>We may update these Terms from time to time. Continued use of the Service after changes take effect means you accept the updated Terms.</p>

<h2>11. Contact</h2>
<p>Questions about these Terms? Email <a href="mailto:${LEGAL_CONTACT_EMAIL}">${LEGAL_CONTACT_EMAIL}</a>.</p>

<div class="note">This is a general template, not a substitute for legal advice tailored to your business. Consider having it reviewed by a lawyer before relying on it, especially once you have paying customers at scale.</div>
`));
});

app.get('/privacy', (req, res) => {
  res.send(legalPageHtml('Privacy Policy', `
<p>This Privacy Policy explains what information SiteSnap collects, how we use it, and who we share it with.</p>

<h2>1. Information we collect</h2>
<ul>
<li><strong>Account information:</strong> your email address and password (stored as a secure hash, never in plain text).</li>
<li><strong>Site content:</strong> the business details, text, and images you enter to build your website.</li>
<li><strong>Payment information:</strong> handled entirely by PayPal, so we never see or store your card details ourselves.</li>
<li><strong>Basic technical data:</strong> standard server logs (like IP address and request timestamps) generated by normal operation of the Service.</li>
</ul>

<h2>2. How we use it</h2>
<ul>
<li>To create and operate your account and publish your site.</li>
<li>To process payments and manage subscriptions, through PayPal.</li>
<li>To send account-related emails, such as password resets.</li>
<li>To keep the Service secure and prevent abuse.</li>
</ul>
<p>We don't sell your personal information, and we don't use your site content for advertising.</p>

<h2>3. Who we share it with</h2>
<p>We share information only with the service providers that power SiteSnap, each acting on our behalf:</p>
<ul>
<li><strong>PayPal</strong>: payment processing and billing.</li>
<li><strong>Cloudinary</strong> — stores images you upload to your site.</li>
<li><strong>Resend</strong> — delivers transactional emails like password resets.</li>
<li><strong>Railway</strong> — hosts the application, database, and custom domain/SSL provisioning.</li>
</ul>
<p>We don't share your information with anyone else except where required by law.</p>

<h2>4. Your published site is public</h2>
<p>Anything you choose to put on a published website — business details, images, contact info — is publicly visible to anyone who visits that site, by design.</p>

<h2>5. Data retention and deletion</h2>
<p>We keep your account and site data for as long as your account is active. You can permanently delete your account, all your saved sites, and cancel any active subscription at any time from My Account. This action can't be undone.</p>

<h2>6. Security</h2>
<p>Passwords are stored using one-way hashing. Traffic to the Service is encrypted in transit. No system is perfectly secure, but we take reasonable steps to protect your information.</p>

<h2>7. Your choices</h2>
<p>You can update your account details, delete individual sites, or delete your entire account at any time from My Account, without needing to contact us.</p>

<h2>8. Changes to this policy</h2>
<p>We may update this Privacy Policy from time to time. Continued use of the Service after changes take effect means you accept the updated policy.</p>

<h2>9. Contact</h2>
<p>Questions about this policy or your data? Email <a href="mailto:${LEGAL_CONTACT_EMAIL}">${LEGAL_CONTACT_EMAIL}</a>.</p>

<div class="note">This is a general template, not a substitute for legal advice tailored to your business or jurisdiction (e.g. GDPR/CCPA obligations). Consider having it reviewed by a lawyer before relying on it, especially once you have paying customers at scale.</div>
`));
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
async function buildWebsite(s, uuid, baseUrl) {
  const name = s.bizName || 'Your Business';
  const tagline = s.tagline || `Serving ${s.industry || 'clients'} with passion and purpose`;
  const audience = s.audience || 'people who value quality';
  const problem = s.problem || `We make it easy to get exactly what you need.`;
  const diff = s.differentiator || `We bring a unique approach that sets us apart.`;
  const cta = s.ctaType || 'Get Started';
  const loc = s.location ? ` · ${s.location}` : '';
  const f = getTheme(s);

  // Testimonials: supports multiple reviews (s.testimonials[]), falling back
  // to the older single testimonialQuote/testimonialAuthor pair for sites
  // saved before this existed. Never invent a review — the old build shipped
  // a fabricated quote from "A Happy Client" on every site, which is the
  // customer's legal exposure, not ours to create. Each entry only renders
  // once they've written a real quote for it.
  const rawTestimonials = (s.testimonials && s.testimonials.length)
    ? s.testimonials
    : [{ quote: s.testimonialQuote, author: s.testimonialAuthor }];
  const testimonials = rawTestimonials
    .slice(0, 9)
    .map(t => ({ quote: ((t && t.quote) || '').trim(), author: ((t && t.author) || '').trim() || 'Client' }))
    .filter(t => t.quote);

  // Which sections to render. Anything unset defaults to visible so existing
  // sites are unchanged — except the testimonial, which is opt-in.
  // FAQs and gallery images: same rule as testimonials — an entry only renders
  // once it actually has content, so a half-filled row never ships as an empty
  // question or a broken image.
  const faqs = (Array.isArray(s.faqs) ? s.faqs : [])
    .slice(0, 20)
    .map(f => ({ q: ((f && f.q) || '').trim(), a: ((f && f.a) || '').trim() }))
    .filter(f => f.q && f.a);
  const gallery = (Array.isArray(s.gallery) ? s.gallery : [])
    .slice(0, 30)
    .map(g => ({ url: safeImageUrl(g && g.url), caption: ((g && g.caption) || '').trim() }))
    .filter(g => g.url);

  const sec = s.sections || {};
  const show = {
    about: sec.about !== false,
    services: sec.services !== false,
    testimonial: sec.testimonial === true && testimonials.length > 0,
    gallery: sec.gallery === true && gallery.length > 0,
    faq: sec.faq === true && faqs.length > 0,
    cta: sec.cta !== false,
  };

  // Resolved background config per section (null = keep the theme's flat colour)
  const bg = {
    hero: bgConfig(s, 'hero'),
    testimonial: bgConfig(s, 'testimonial'),
    gallery: bgConfig(s, 'gallery'),
    faq: bgConfig(s, 'faq'),
    cta: bgConfig(s, 'cta'),
  };

  // Feature cards: owner-editable, falling back to the generic copy.
  // Icon can be a custom-uploaded image (iconUrl) or the theme's default emoji.
  const defaultFeat = [
    { icon: f.feat1, title: 'Quality First',  text: 'Everything we do is crafted with care and relentless attention to detail.' },
    { icon: f.feat2, title: 'Personal Touch', text: "You're not a ticket number — we tailor our approach to your unique situation." },
    { icon: f.feat3, title: 'Real Results',   text: 'Our clients see measurable, meaningful outcomes every single time.' },
  ];
  const feat = defaultFeat.map((d, i) => {
    const c = (s.features && s.features[i]) || {};
    return {
      icon: c.icon || d.icon,
      iconUrl: safeImageUrl(c.iconUrl),
      title: (c.title || '').trim() || d.title,
      text: (c.text || '').trim() || d.text,
    };
  });

  // A button pointing at a section the owner switched off would be a dead
  // anchor, so retarget it to a section that still exists (or drop the link).
  const sectionVisible = {
    about: show.about, services: show.services, contact: show.cta,
    gallery: show.gallery, faq: show.faq,
  };
  const safeCta = (key, fallbackLabel, fallbackSection) => {
    const a = Object.assign({}, ctaFor(s, key, fallbackLabel, fallbackSection));
    if ((a.type || 'section') === 'section') {
      const target = String(a.value || 'contact').replace(/^#/, '');
      if (!sectionVisible[target]) {
        const alt = ['contact', 'about', 'services'].find(k => sectionVisible[k]);
        if (alt) a.value = alt; else a.type = 'none';
      }
    }
    return a;
  };

  // Nav links must not point at sections that were switched off
  const navLinksHtml = [
    show.about ? '<a href="#about">About</a>' : '',
    show.services ? '<a href="#services">Services</a>' : '',
    show.gallery ? '<a href="#gallery">Gallery</a>' : '',
    show.faq ? '<a href="#faq">FAQ</a>' : '',
    show.cta ? '<a href="#contact">Contact</a>' : '',
  ].join('');

  // Check if this site has badge removed (Starter+ user)
  const siteRow = await dbGet('SELECT user_id FROM sites WHERE uuid = ?', uuid);
  let showBadge = true;
  if (siteRow?.user_id) {
    const user = await dbGet('SELECT plan FROM users WHERE id = ?', siteRow.user_id);
    showBadge = !user || user.plan === 'free';
  }

  // Image addresses come straight from the saved site data, so they must be
  // checked and escaped like any other text: an unescaped quote here would let
  // someone inject script into a page served from the app's own domain.
  const logoUrl = safeImageUrl(s.logoUrl);
  const heroUrl = safeImageUrl(s.heroUrl);
  const aboutUrl = safeImageUrl(s.aboutUrl);

  const logoHtml = logoUrl
    ? `<img src="${escHtml(logoUrl)}" alt=""${escHtml(name)}" style="max-height:52px;max-width:160px;object-fit:contain;">`
    : `<div style="font-size:20px;font-weight:900;letter-spacing:-0.5px;color:${f.navText}">${escHtml(name)}</div>`;

  const heroImg = heroUrl
    ? `<img src="${escHtml(heroUrl)}" alt="${escHtml(name)}" style="width:100%;height:100%;object-fit:cover;border-radius:${f.imgRadius};">`
    : `<span style="font-size:64px;">${f.heroEmoji}</span>`;

  const aboutImg = aboutUrl
    ? `<img src="${escHtml(aboutUrl)}" alt="About ${escHtml(name)}" style="width:100%;height:100%;object-fit:cover;border-radius:${f.imgRadius};">`
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
.nav-cta{display:inline-block;text-decoration:none;padding:10px 24px;background:${f.btnBg};color:${f.ctaText};border-radius:${f.btnRadius};font-size:14px;font-weight:700;cursor:pointer;border:none;}
.hero{padding:${f.heroPadding};background:${f.heroBg};display:grid;grid-template-columns:1fr ${f.heroImgCol};gap:64px;align-items:center;${f.heroExtra}}
${bg.hero ? `.hero{${bgStyle(bg.hero, 'left')}}
.hero h1{color:${bgTextVars(bg.hero).heading};text-shadow:${bgTextVars(bg.hero).shadow};}
.hero-sub{color:${bgTextVars(bg.hero).body};text-shadow:${bgTextVars(bg.hero).shadow};}
.hero-eyebrow{color:${bgTextVars(bg.hero).heading};opacity:0.85;text-shadow:${bgTextVars(bg.hero).shadow};}
/* Photo already fills the hero — the inset image would just fight it */
.hero{grid-template-columns:1fr;}
.hero .hero-img-wrap{display:none;}` : ''}
.hero-img-wrap{border-radius:${f.imgRadius};overflow:hidden;aspect-ratio:4/3;background:${f.heroImgBg};display:flex;align-items:center;justify-content:center;${f.heroImgExtra}}
.hero h1{font-family:${f.headFont};font-size:clamp(32px,5vw,58px);font-weight:${f.heroWeight};line-height:1.1;color:${f.heroText};margin-bottom:20px;letter-spacing:${f.heroTracking};}
.hero h1 em{color:${f.accent};font-style:normal;}
.hero-eyebrow{font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:${f.accent};margin-bottom:16px;}
.hero-sub{font-size:17px;color:${f.heroSubText};max-width:480px;margin-bottom:36px;line-height:1.6;}
.hero-btns{display:flex;gap:16px;flex-wrap:wrap;}
.btn-p{text-decoration:none;padding:16px 36px;background:${f.btnBg};color:${f.ctaText};border-radius:${f.btnRadius};font-size:16px;font-weight:700;border:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px;transition:transform 0.15s;}
.btn-p:hover{transform:translateY(-2px);}
.btn-s{display:inline-block;text-decoration:none;padding:16px 32px;background:transparent;color:${f.heroText};border-radius:${f.btnRadius};font-size:16px;font-weight:600;border:2px solid ${f.heroBorder};cursor:pointer;}
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
.testimonials-grid{display:grid;gap:28px;max-width:1000px;margin:0 auto;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));}
.testimonials-grid.count-1{grid-template-columns:1fr;max-width:640px;}
.testimonial-card{padding:40px 32px;background:${f.testimonialCardBg};border-radius:${f.cardRadius};border:${f.testimonialBorder};text-align:center;}
@media(max-width:700px){.testimonials-grid{grid-template-columns:1fr;}}
.quote-mark{font-size:64px;color:${f.accent};line-height:0.8;margin-bottom:24px;font-family:Georgia,serif;}
.quote-text{font-size:20px;color:${f.headingColor};font-style:italic;line-height:1.5;margin-bottom:24px;font-family:${f.headFont};}
.quote-author{font-size:14px;font-weight:600;color:${f.subTextColor};}
.cta-section{background:${f.ctaSectionBg};text-align:center;padding:96px 48px;${f.ctaExtra}}
.cta-section h2{font-family:${f.headFont};font-size:clamp(32px,5vw,48px);font-weight:${f.heroWeight};color:${f.ctaSectionText};margin-bottom:16px;letter-spacing:${f.heroTracking};}
.cta-section p{font-size:18px;color:${f.ctaSectionSub};margin-bottom:40px;max-width:500px;margin-left:auto;margin-right:auto;}
${bg.cta ? `.cta-section{${bgStyle(bg.cta)}}
.cta-section h2{color:${bgTextVars(bg.cta).heading};text-shadow:${bgTextVars(bg.cta).shadow};}
.cta-section p{color:${bgTextVars(bg.cta).body};text-shadow:${bgTextVars(bg.cta).shadow};}` : ''}
${bg.testimonial ? `.testimonial-section{${bgStyle(bg.testimonial)}}
.testimonial-section .eyebrow{color:${bgTextVars(bg.testimonial).heading};opacity:0.85;text-shadow:${bgTextVars(bg.testimonial).shadow};}
.testimonial-section .testimonial-card{background:${bgTextVars(bg.testimonial).card};border:${bgTextVars(bg.testimonial).cardBorder};backdrop-filter:blur(6px);}
.testimonial-section .quote-text{color:${bgTextVars(bg.testimonial).heading};}
.testimonial-section .quote-author{color:${bgTextVars(bg.testimonial).body};}
.testimonial-section .quote-mark{color:${bgTextVars(bg.testimonial).heading};opacity:0.5;}` : ''}

/* ── GALLERY ─────────────────────────────────────── */
.gallery-section{background:${f.featureBg};}
${bg.gallery ? `.gallery-section{${bgStyle(bg.gallery)}}
.gallery-section .eyebrow{color:${bgTextVars(bg.gallery).heading};opacity:0.85;text-shadow:${bgTextVars(bg.gallery).shadow};}
.gallery-section .section-title{color:${bgTextVars(bg.gallery).heading};text-shadow:${bgTextVars(bg.gallery).shadow};}
.gallery-section .section-sub{color:${bgTextVars(bg.gallery).body};text-shadow:${bgTextVars(bg.gallery).shadow};}
.gallery-cap{color:${bgTextVars(bg.gallery).body};text-shadow:${bgTextVars(bg.gallery).shadow};}` : ''}
.gallery-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;max-width:1080px;margin:0 auto;}
@media(max-width:860px){.gallery-grid{grid-template-columns:repeat(2,1fr);}}
@media(max-width:520px){.gallery-grid{grid-template-columns:1fr;}}
.gallery-item{margin:0;position:relative;overflow:hidden;border-radius:${f.imgRadius};cursor:zoom-in;background:${f.cardBg};}
.gallery-item img{display:block;width:100%;aspect-ratio:4/3;object-fit:cover;transition:transform 0.45s ease;}
.gallery-item:hover img{transform:scale(1.05);}
.gallery-cap{font-size:13px;color:${f.subTextColor};padding:10px 2px 0;line-height:1.4;}
/* Lightbox: plain CSS :target so it works with JS disabled too */
.lb{position:fixed;inset:0;background:rgba(8,8,10,0.94);display:none;align-items:center;justify-content:center;z-index:999;padding:24px;}
.lb:target{display:flex;}
.lb img{max-width:100%;max-height:86vh;object-fit:contain;border-radius:8px;}
.lb-close{position:absolute;top:20px;right:26px;color:#fff;font-size:34px;text-decoration:none;line-height:1;opacity:0.75;}
.lb-close:hover{opacity:1;}

/* ── FAQ ─────────────────────────────────────────── */
.faq-section{background:${f.aboutBg};}
${bg.faq ? `.faq-section{${bgStyle(bg.faq)}}
.faq-section .eyebrow{color:${bgTextVars(bg.faq).heading};opacity:0.85;text-shadow:${bgTextVars(bg.faq).shadow};}
.faq-section .section-title{color:${bgTextVars(bg.faq).heading};text-shadow:${bgTextVars(bg.faq).shadow};}
.faq-section .section-sub{color:${bgTextVars(bg.faq).body};text-shadow:${bgTextVars(bg.faq).shadow};}
.faq-item{background:${bgTextVars(bg.faq).card};border:${bgTextVars(bg.faq).cardBorder};backdrop-filter:blur(6px);}
.faq-q{color:${bgTextVars(bg.faq).heading};}
.faq-a{color:${bgTextVars(bg.faq).body};}
.faq-item summary::after{color:${bgTextVars(bg.faq).heading};}` : ''}
.faq-list{max-width:760px;margin:0 auto;display:flex;flex-direction:column;gap:12px;}
.faq-item{background:${f.cardBg};border:${f.cardBorder};border-radius:${f.cardRadius};overflow:hidden;}
.faq-item summary{list-style:none;cursor:pointer;padding:20px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;}
.faq-item summary::-webkit-details-marker{display:none;}
.faq-item summary::after{content:'+';font-size:24px;line-height:1;flex-shrink:0;color:${f.accent};transition:transform 0.25s ease;}
.faq-item[open] summary::after{content:'−';}
.faq-q{font-family:${f.headFont};font-size:17px;font-weight:700;color:${f.headingColor};line-height:1.4;}
.faq-a{font-size:15px;color:${f.subTextColor};line-height:1.65;padding:0 24px 20px;}
footer{background:${f.footerBg};border-top:${f.footerBorder};padding:40px 48px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;}
.footer-name{font-size:18px;font-weight:800;color:${f.footerText};}
.footer-copy{font-size:13px;color:${f.footerText};opacity:0.5;}
.footer-links{display:flex;gap:24px;font-size:13px;color:${f.footerText};opacity:0.6;}
@media(max-width:700px){.hero,.about-grid{grid-template-columns:1fr;}.hero-img-wrap{display:none;}.features-grid{grid-template-columns:1fr;}nav,section,footer{padding-left:24px;padding-right:24px;}.trust-bar{gap:20px;}.faq-item summary{padding:16px 18px;}.faq-a{padding:0 18px 16px;}nav{padding:12px 16px;flex-wrap:nowrap;}.nav-links{display:none;}.nav-cta{padding:8px 16px;font-size:13px;white-space:nowrap;}footer{flex-direction:column;align-items:flex-start;gap:10px;}}
@media(max-width:420px){nav{padding:10px 14px;}.nav-cta{padding:7px 12px;font-size:12px;}}
</style></head><body>
<nav>
  ${logoHtml}
  <div class="nav-links">${navLinksHtml}</div>
  ${renderCta(safeCta('nav',cta,'contact'), cta, 'nav-cta')}
</nav>
<div class="hero">
  <div>
    <div class="hero-eyebrow">${escHtml(s.industry || 'Premium Service')}${escHtml(loc)}</div>
    <h1>${(s.heroHeadline || '').trim() ? escHtml(s.heroHeadline) : heroHeadline(name, s.industry)}</h1>
    <p class="hero-sub">${escHtml(tagline)}</p>
    <div class="hero-btns">${renderCta(safeCta('heroMain',cta+' →','contact'), cta+' →', 'btn-p')}${renderCta(safeCta('heroAlt','Learn More','about'), 'Learn More', 'btn-s')}</div>
  </div>
  <div class="hero-img-wrap">${heroImg}</div>
</div>
${s.showTrustBar !== false ? `<div class="trust-bar">
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust1 || 'Trusted by clients worldwide')}</div>
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust2 || '5-star rated')}</div>
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust3 || '100% satisfaction')}</div>
  <div class="trust-item"><div class="trust-dot"></div>${escHtml(s.trust4 || s.location || 'Available online')}</div>
</div>` : ''}
${show.about ? `<section class="about" id="about">
  <div class="about-grid">
    <div class="about-img">${aboutImg}</div>
    <div>
      <div class="eyebrow">${escHtml(s.aboutEyebrow || 'Our Story')}</div>
      <div class="section-title">${escHtml(s.aboutTitle || ('We exist for ' + audience.split(' ').slice(0,6).join(' ') + '…'))}</div>
      <p>${escHtml(problem)}</p>
      <p>${escHtml(diff)}</p>
      ${renderCta(safeCta('about',cta+' →','contact'), cta+' →', 'btn-p', 'margin-top:16px;')}
    </div>
  </div>
</section>` : ''}
${show.services ? `<section class="features" id="services">
  <div style="text-align:center;max-width:600px;margin:0 auto 52px;">
    <div class="eyebrow">${escHtml(s.servicesEyebrow || 'Why Choose Us')}</div>
    <div class="section-title">${escHtml(s.servicesTitle || ('What makes ' + name + ' different'))}</div>
    <div class="section-sub">${escHtml(s.servicesSub || "We don't just talk the talk — here's what you can expect every single time.")}</div>
  </div>
  <div class="features-grid">
    ${feat.map(c => `<div class="feature-card"><div class="feature-icon">${c.iconUrl ? `<img src="${escHtml(c.iconUrl)}" alt="" style="width:36px;height:36px;object-fit:contain;border-radius:8px;">` : escHtml(c.icon)}</div><div class="feature-title">${escHtml(c.title)}</div><div class="feature-text">${escHtml(c.text)}</div></div>`).join('')}
  </div>
</section>` : ''}
${show.testimonial ? `<section class="testimonial-section">
  <div class="eyebrow" style="text-align:center;margin-bottom:32px;">${escHtml(s.testimonialEyebrow || 'What Clients Say')}</div>
  <div class="testimonials-grid count-${testimonials.length}">
    ${testimonials.map(t => `<div class="testimonial-card">
      <div class="quote-mark">"</div>
      <div class="quote-text">${escHtml(t.quote)}</div>
      <div class="quote-author">— ${escHtml(t.author)}</div>
    </div>`).join('')}
  </div>
</section>` : ''}
${show.gallery ? `<section class="gallery-section" id="gallery">
  <div style="text-align:center;max-width:600px;margin:0 auto 52px;">
    <div class="eyebrow">${escHtml(s.galleryEyebrow || 'Gallery')}</div>
    <div class="section-title">${escHtml(s.galleryTitle || 'A look at our work')}</div>
    <div class="section-sub" style="margin-bottom:0;">${escHtml(s.gallerySub || 'A few recent favourites.')}</div>
  </div>
  <div class="gallery-grid">
    ${gallery.map((g, i) => `<figure class="gallery-item">
      <a href="#lb-${i}" aria-label="Enlarge image ${i + 1}"><img src="${escHtml(g.url)}" alt="${escHtml(g.caption || (name + ' gallery image ' + (i + 1)))}" loading="lazy"></a>
      ${g.caption ? `<figcaption class="gallery-cap">${escHtml(g.caption)}</figcaption>` : ''}
    </figure>`).join('')}
  </div>
</section>
${gallery.map((g, i) => `<div class="lb" id="lb-${i}"><a class="lb-close" href="#gallery" aria-label="Close">&times;</a><img src="${escHtml(g.url)}" alt="${escHtml(g.caption || '')}"></div>`).join('')}` : ''}
${show.faq ? `<section class="faq-section" id="faq">
  <div style="text-align:center;max-width:600px;margin:0 auto 44px;">
    <div class="eyebrow">${escHtml(s.faqEyebrow || 'FAQ')}</div>
    <div class="section-title">${escHtml(s.faqTitle || 'Questions, answered')}</div>
    <div class="section-sub" style="margin-bottom:0;">${escHtml(s.faqSub || 'The things people usually want to know before getting started.')}</div>
  </div>
  <div class="faq-list">
    ${faqs.map((q, i) => `<details class="faq-item"${i === 0 ? ' open' : ''}>
      <summary><span class="faq-q">${escHtml(q.q)}</span></summary>
      <div class="faq-a">${escHtml(q.a)}</div>
    </details>`).join('')}
  </div>
</section>` : ''}
${show.cta ? `<section class="cta-section" id="contact">
  <h2>${escHtml(s.ctaHeadline || 'Ready to get started?')}</h2>
  <p>${escHtml(s.ctaSubtext || ('Join the people already working with ' + name + '. Your journey begins with one simple step.'))}</p>
  ${renderCta(safeCta('final',cta+' →','contact'), cta+' →', 'btn-p', `background:${f.ctaSectionBtn};color:${f.ctaSectionBtnText};font-size:17px;padding:18px 44px;`)}
</section>` : ''}
<footer>
  <div class="footer-name">${escHtml(name)}</div>
  <div class="footer-links">${show.cta ? '<a href="#contact">Contact</a>' : ''}</div>
  <div class="footer-copy">© ${new Date().getFullYear()} ${escHtml(name)}. All rights reserved.</div>
</footer>
${badge}
</body></html>`;
}

// ── HELPERS ────────────────────────────────────────────────────────────────────
// Customer sites are plain HTML and CSS with no scripts at all, so the policy
// can forbid script outright. Even if some field were ever left unescaped,
// injected code still could not run.
const SITE_CSP = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com data:",
  "img-src * data: blob:",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');

function sendSite(res, html) {
  res.setHeader('Content-Security-Policy', SITE_CSP);
  res.send(html);
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// Only #rgb / #rrggbb colours are accepted; anything else falls back.
function safeColor(value, fallback) {
  const v = String(value || '').trim();
  return /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i.test(v) ? v : fallback;
}

// Image addresses must be http(s) or a path on this server. Blocks
// javascript:, data: and anything containing characters that could break out
// of an HTML attribute or a CSS url().
function safeImageUrl(value) {
  const v = String(value || '').trim();
  if (!v || v.length > 2048) return '';
  if (/["'<>\\\s()`]/.test(v)) return '';
  if (/^https?:\/\//i.test(v)) return v;
  if (v.startsWith('//')) return ''; // protocol-relative: would load from any host
  if (/^[a-z][a-z0-9+.-]*:/i.test(v)) return ''; // javascript:, data:, etc.
  return v; // same-site path like /uploads/x.jpg
}

// ── SECTION BACKGROUNDS (solid colour, or photo + colour overlay) ──────────────
// A section can keep its theme's flat colour, or use an uploaded photo behind a
// tinted overlay drawn from the owner's palette. Text colour is then derived
// from the overlay so the copy stays readable instead of vanishing into the
// photo — the owner picks a look, we guarantee it's legible.
function hexToRgb(hex) {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(String(hex || '').trim());
  if (!m) return { r: 0, g: 0, b: 0 };
  return { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) };
}
function rgba(hex, alpha) {
  const { r, g, b } = hexToRgb(hex);
  return `rgba(${r},${g},${b},${Math.max(0, Math.min(1, alpha))})`;
}
function bgConfig(s, key) {
  const cfg = (s && s.sectionBg && s.sectionBg[key]) || {};
  const url = safeImageUrl(cfg.url);
  if (cfg.mode !== 'image' || !url) return null;
  // Strength is the overlay opacity. Clamp to a band that always leaves the
  // photo visible but never lets contrast collapse entirely.
  const strength = Math.max(20, Math.min(95, Number(cfg.strength ?? 65))) / 100;
  return { url, color: safeColor(cfg.overlay, '#000000'), strength };
}
// Is the tinted result dark enough that text should go light?
function bgIsDark(cfg) {
  const { r, g, b } = hexToRgb(cfg.color);
  const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  // Photo underneath is an unknown; assume mid-tone so partial overlays still
  // resolve sensibly.
  return (lum * cfg.strength + 0.45 * (1 - cfg.strength)) < 0.55;
}
// `scrim: 'left'` fades the tint across the section so a side-by-side hero keeps
// its copy readable while the photo still breathes on the far edge.
function bgStyle(cfg, scrim) {
  const strong = rgba(cfg.color, cfg.strength);
  const weak = rgba(cfg.color, Math.max(0.08, cfg.strength - 0.45));
  const layer = scrim === 'left'
    ? `linear-gradient(100deg,${strong} 0%,${strong} 46%,${weak} 100%)`
    : `linear-gradient(${strong},${strong})`;
  return `background-image:${layer},url('${encodeURI(cfg.url).replace(/'/g, "%27")}');background-size:cover;background-position:center;background-repeat:no-repeat;`;
}
// Colour overrides applied to a section that's sitting on a photo.
//
// At low tint strength the photo dominates, and we can't know whether the part
// of it behind any given line of text is light or dark — so picking a text
// colour alone doesn't guarantee readability. Below a comfortable threshold we
// also emit a soft shadow in the opposing direction, which keeps copy legible
// over a busy or unpredictable image without muddying a strong tint.
function bgTextVars(cfg) {
  const dark = bgIsDark(cfg);
  const needsShadow = cfg.strength < 0.55;
  const shadow = !needsShadow ? 'none'
    : dark ? '0 1px 3px rgba(0,0,0,0.55)' : '0 1px 3px rgba(255,255,255,0.6)';
  return {
    heading: dark ? '#FFFFFF' : '#141414',
    body: dark ? 'rgba(255,255,255,0.90)' : 'rgba(20,20,20,0.82)',
    card: dark ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.82)',
    cardBorder: dark ? '1px solid rgba(255,255,255,0.16)' : '1px solid rgba(0,0,0,0.08)',
    shadow,
  };
}

// ── CTA BUTTONS ────────────────────────────────────────────────────────────────
// Turn a button's configured action into a real href. Previously every CTA was
// a bare <button> with no handler, so visitors clicking "Book a Call" got
// nothing — the entire conversion path on every generated site was dead.
function buttonHref(action) {
  if (!action) return null;
  const type = action.type || 'section';
  const raw = String(action.value ?? '').trim();

  if (type === 'none') return null;
  if (type === 'section') return '#' + (raw || 'contact').replace(/^#/, '');
  if (!raw) return null;

  if (type === 'email') {
    // People often type "mailto:name@x.com" thinking the prefix is required
    // (it isn't — the dropdown already says "Email"). Strip it so that
    // doesn't produce a broken "mailto:mailto:..." link.
    const email = raw.replace(/^mailto:/i, '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
    return 'mailto:' + email;
  }
  if (type === 'phone') {
    const digits = raw.replace(/[^\d+]/g, '');
    return digits ? 'tel:' + digits : null;
  }
  if (type === 'url') {
    // Reject anything that already declares its own scheme other than
    // http(s) — e.g. "javascript:alert(1)" or "data:text/html,...". Without
    // this check those values fell through to the https:// prefix below and
    // came out as "https://javascript:alert(1)": inert as a link, but not
    // the sanitisation the code intended, and confusing either way.
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^https?:\/\//i.test(raw)) return null;
    const url = /^https?:\/\//i.test(raw) ? raw : 'https://' + raw.replace(/^\/+/, '');
    return /^https?:\/\/[^\s/$.?#][^\s]*$/i.test(url) ? url : null;
  }
  return null;
}

// Renders an <a> when the button leads somewhere, and a disabled-looking
// <button> only when the owner explicitly chose "no link".
function renderCta(action, fallbackLabel, cls, extraStyle) {
  const label = escHtml((action && action.label) || fallbackLabel);
  const href = buttonHref(action);
  const style = extraStyle ? ` style="${extraStyle}"` : '';
  if (!href) return `<button class="${cls}"${style}>${label}</button>`;
  const external = /^https?:\/\//i.test(href);
  const rel = external ? ' target="_blank" rel="noopener noreferrer"' : '';
  return `<a class="${cls}" href="${escHtml(href)}"${rel}${style}>${label}</a>`;
}

// Existing sites predate per-button config — fall back to the old single
// ctaType label pointing at the contact section so nothing regresses.
function ctaFor(s, key, fallbackLabel, fallbackSection) {
  const configured = s && s.buttons && s.buttons[key];
  if (configured && (configured.label || configured.type)) return configured;
  return { label: fallbackLabel, type: 'section', value: fallbackSection || 'contact' };
}
function heroHeadline(name, industry) {
  const map = {'Photography':`Capturing your story,<br><em>beautifully.</em>`,'Beauty & Wellness':`Feel your best,<br><em>inside &amp; out.</em>`,'Food & Beverage':`Made with love,<br><em>served with pride.</em>`,'Fashion & Apparel':`Style that speaks<br><em>for itself.</em>`,'Health & Fitness':`Your strongest self<br><em>starts here.</em>`,'Home & Interior':`Spaces you'll<br><em>love to live in.</em>`,'Art & Creative':`Art that moves<br><em>the world.</em>`,'Coaching & Consulting':`Clarity, strategy,<br><em>results.</em>`,'Real Estate':`Find the home<br><em>you deserve.</em>`,'Technology':`Built for the<br><em>future, today.</em>`,'Retail / E-commerce':`Shop smarter,<br><em>live better.</em>`,'Non-profit':`Making a difference,<br><em>together.</em>`};
  return map[industry] || `${escHtml(name)}:<br><em>Where quality meets purpose.</em>`;
}
function getTheme(s) {
  // colorButton is a distinct choice from colorPrimary — set via its own swatch
  // in Step 2 ("Button color"). It falls back to Primary only when the person
  // never touched the button swatch, exactly like the client-side wizard
  // preview (getClientTheme's `btnBg`) already does. Buttons must read this,
  // not f.primary, or a customer's chosen button colour never reaches their
  // live site even though the in-progress preview showed it correctly.
  // Colours are written straight into the page's <style> block, so only a
  // plain hex value is ever allowed through — anything else could close the
  // style tag and inject script.
  const p = safeColor(s.colorPrimary, '#6C47FF'), a = safeColor(s.colorAccent, '#FF6B6B'), btn = safeColor(s.colorButton, p), font = s.fontStyle||'modern', style = s.designStyle||'light-airy';
  const fm = {modern:{headFont:"'Inter',sans-serif",fontUrl:"Inter:wght@400;700;800",bodyFont:"'Inter',sans-serif",heroWeight:800,heroTracking:'-1px'},elegant:{headFont:"'Playfair Display',serif",fontUrl:"Playfair+Display:wght@400;700",bodyFont:"'Inter',sans-serif",heroWeight:700,heroTracking:'-0.5px'},playful:{headFont:"'Inter',sans-serif",fontUrl:"Inter:wght@400;800;900",bodyFont:"'Inter',sans-serif",heroWeight:900,heroTracking:'-2px'}};
  const f = fm[font]||fm.modern;
  const base = {...f,primary:p,accent:a,btnBg:btn};
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

// ── SENTRY ERROR HANDLING (must be registered after all routes) ────────────────
if (Sentry) {
  Sentry.setupExpressErrorHandler(app);
}
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection:', reason);
  if (Sentry) Sentry.captureException(reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  if (Sentry) Sentry.captureException(err);
});

// ── START ──────────────────────────────────────────────────────────────────────
// Exported so the test suite can boot the app in-process (via supertest)
// without also binding a real port, and can call initDb() itself on a
// throwaway database instead of racing this module's own startup.
// buildWebsite and the background helpers are exported for the test suite —
// they're the logic behind what actually ships to a customer's visitors.
module.exports = {
  app, initDb, buttonHref, buildSignupNotification, safeColor, safeImageUrl, isReservedHost,
  buildWebsite, bgConfig, bgIsDark, bgTextVars, bgStyle, hexToRgb, rgba,
};

// Only auto-start when this file is run directly (`node server.js`) —
// requiring it as a module (as the tests do) must not also open a port.
if (require.main === module) {
  initDb()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`\n🚀 SiteSnap running at http://localhost:${PORT}`);
        if (!process.env.STRIPE_SECRET_KEY) console.warn('   ⚠️  STRIPE_SECRET_KEY not set — payments will not work');
      });
    })
    .catch(e => {
      // Starting without a working database would silently serve broken pages
      console.error('Could not initialise the database:', e.message);
      process.exit(1);
    });
}
