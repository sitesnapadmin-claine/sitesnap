const express = require('express');
const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const crypto = require('crypto');
const multer = require('multer');
// better-sqlite3 is a native module and only needed for the SQLite fallback —
// required lazily so a Postgres deploy never depends on it compiling.
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
// Where customers point their CNAME records. Must be the host that actually
// serves the app (Railway/Render/etc), NOT the marketing domain.
// Railway injects RAILWAY_PUBLIC_DOMAIN, so this stays correct on its own even
// if the deployment moves — no hardcoded hostname to go stale.
const CNAME_TARGET =
  process.env.CNAME_TARGET ||
  process.env.RAILWAY_PUBLIC_DOMAIN ||
  'sitesnap-production-b50b.up.railway.app';
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

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

// Only the hash is stored, so a database leak can't be used to seize accounts.
const hashToken = t => crypto.createHash('sha256').update(String(t)).digest('hex');

// How many websites each plan may own. Editing a site is always allowed —
// this caps creation only.
const SITE_LIMITS = { free: 1, starter: 1, pro: Infinity };

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
  sqliteDb = new Database(path.join(__dirname, 'sitesnap.db'));
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
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS subdomain TEXT',
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS custom_domain TEXT',
      'ALTER TABLE sites ADD COLUMN IF NOT EXISTS railway_domain_id TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT',
      'ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires BIGINT',
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
    'ALTER TABLE sites ADD COLUMN subdomain TEXT',
    'ALTER TABLE sites ADD COLUMN custom_domain TEXT',
    'ALTER TABLE sites ADD COLUMN railway_domain_id TEXT',
    'ALTER TABLE users ADD COLUMN reset_token_hash TEXT',
    'ALTER TABLE users ADD COLUMN reset_expires INTEGER',
  ].forEach(sql => { try { sqliteDb.exec(sql); } catch (_) {} });
  console.warn('⚠️  Using SQLite — on an ephemeral host, saved sites are LOST on every redeploy.');
  console.warn('   Attach a Postgres service so DATABASE_URL is set.');
}

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
app.use(async (req, res, next) => {
  try {
    const host = req.hostname;

    // Custom domain: any host that isn't our app domain or localhost
    if (host && !host.endsWith(APP_DOMAIN) && host !== 'localhost' && host !== '127.0.0.1') {
      const site = await dbGet('SELECT uuid, data FROM sites WHERE custom_domain = ?', host);
      if (site) {
        const data = JSON.parse(site.data);
        return res.send(await buildWebsite(data, site.uuid, `https://${host}`));
      }
    }

    // Subdomain: yourbrand.sitesnap.app
    const parts = host.split('.');
    if (parts.length >= 3 || (host.endsWith('localhost') && parts.length >= 2)) {
      const sub = parts[0];
      if (sub && sub !== 'www' && sub !== 'app') {
        const site = await dbGet('SELECT uuid, data FROM sites WHERE subdomain = ?', sub);
        if (site) {
          const data = JSON.parse(site.data);
          return res.send(await buildWebsite(data, site.uuid, BASE_URL));
        }
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
    const exists = await dbGet('SELECT id, plan FROM users WHERE id = ?', req.user.id);
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
    } else if (req.user.plan && req.user.plan !== 'free' && exists.plan === 'free') {
      // JWT carries a paid plan but DB shows free (post-redeploy wipe) — restore it
      await dbRun('UPDATE users SET plan = ? WHERE id = ?', req.user.plan, req.user.id);
    }
    next();
  } catch (e) {
    next(e);
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
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    // RETURNING works in both Postgres and modern SQLite, so the new id comes
    // back the same way regardless of driver.
    const row = await dbGet(
      'INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id',
      email.toLowerCase().trim(), hash
    );
    const token = jwt.sign({ id: row.id, email: email.toLowerCase(), plan: 'free' }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email: email.toLowerCase(), plan: 'free' });
  } catch (e) {
    if (isUniqueViolation(e)) return res.status(409).json({ error: 'That email is already registered' });
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await dbGet('SELECT * FROM users WHERE email = ?', email?.toLowerCase().trim());
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
  const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan || 'free' }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email, plan: user.plan || 'free' });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await dbGet('SELECT id, email, plan, created_at, password_hash FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password_hash, ...safe } = user;
  res.json({ ...safe, needsPassword: !isUsablePasswordHash(password_hash) });
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
  if (!password || String(password).length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  try {
    const hash = await bcrypt.hash(String(password), 10);
    await dbRun('UPDATE users SET password_hash = ? WHERE id = ?', hash, req.user.id);
    res.json({ ok: true });
  } catch (e) {
    console.error('set-password error:', e.message);
    res.status(500).json({ error: 'Could not update password' });
  }
});

// ── PASSWORD RESET ─────────────────────────────────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
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

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Reset link is missing its token' });
  if (!password || String(password).length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  try {
    const user = await dbGet('SELECT id, reset_expires FROM users WHERE reset_token_hash = ?', hashToken(token));
    if (!user) return res.status(400).json({ error: 'This reset link is invalid or has already been used.' });
    if (!user.reset_expires || Number(user.reset_expires) < Date.now()) {
      return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' });
    }
    const hash = await bcrypt.hash(String(password), 10);
    // Clearing the token makes the link single-use
    await dbRun('UPDATE users SET password_hash = ?, reset_token_hash = NULL, reset_expires = NULL WHERE id = ?',
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
    const newToken = jwt.sign({ id: req.user.id, email: req.user.email, plan }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ plan, token: newToken });
  } catch (e) {
    console.error('sync-plan error:', e.message);
    res.status(500).json({ error: 'Could not sync plan: ' + e.message });
  }
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
app.post('/api/sites', requireAuth, async (req, res) => {
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'Site data is required' });
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
app.put('/api/sites/:uuid', requireAuth, async (req, res) => {
  const { data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'Site data is required' });
  const site = await dbGet('SELECT user_id FROM sites WHERE uuid = ?', req.params.uuid);
  if (!site) return res.status(404).json({ error: 'Site not found' });
  if (site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });
  await dbRun('UPDATE sites SET data = ? WHERE uuid = ?', JSON.stringify(data), req.params.uuid);
  res.json({ uuid: req.params.uuid, url: `${BASE_URL}/preview/${req.params.uuid}` });
});

app.get('/api/sites', requireAuth, async (req, res) => {
  const rows = await dbAll('SELECT uuid, subdomain, custom_domain, created_at, data FROM sites WHERE user_id = ? ORDER BY created_at DESC', req.user.id);
  res.json(rows.map(r => {
    const d = JSON.parse(r.data);
    return { uuid: r.uuid, subdomain: r.subdomain, customDomain: r.custom_domain, created_at: r.created_at, bizName: d.bizName, industry: d.industry, designStyle: d.designStyle };
  }));
});

app.get('/api/sites/:uuid', async (req, res) => {
  const row = await dbGet('SELECT data FROM sites WHERE uuid = ?', req.params.uuid);
  if (!row) return res.status(404).json({ error: 'Site not found' });
  res.json(JSON.parse(row.data));
});

app.delete('/api/sites/:uuid', requireAuth, async (req, res) => {
  const row = await dbGet('SELECT user_id FROM sites WHERE uuid = ?', req.params.uuid);
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });
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
  const clean = subdomain.toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 30);
  if (!clean) return res.status(400).json({ error: 'Invalid subdomain' });

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
  const clean = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/$/, '');

  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(clean)) {
    return res.status(400).json({ error: 'That doesn\'t look like a valid domain. Example: www.yourbrand.com' });
  }

  const site = await dbGet('SELECT user_id, railway_domain_id FROM sites WHERE uuid = ?', req.params.uuid);
  if (!site || site.user_id !== req.user.id) return res.status(403).json({ error: 'Not your site' });

  // Root domains can't use CNAME — flagged so the guide can warn about ALIAS/ANAME
  const isRoot = clean.split('.').length === 2;

  // No Railway credentials configured — save locally and show manual instructions.
  // The domain won't actually route until someone adds it in the Railway dashboard.
  if (!RAILWAY_READY) {
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

  try {
    // Replace any domain previously registered for this site so we don't
    // leave orphaned domains sitting in the Railway project.
    if (site.railway_domain_id) {
      try { await railwayDeleteDomain(site.railway_domain_id); } catch (_) {}
      clearCachedDomainStatus(site.railway_domain_id);
    }

    const rw = await railwayAddDomain(clean);
    // A freshly registered domain must never report a previous domain's status
    clearCachedDomainStatus(rw.id);

    await dbRun('UPDATE sites SET custom_domain = ?, railway_domain_id = ? WHERE uuid = ?', clean, rw.id, req.params.uuid);

    res.json({
      domain: clean,
      isRoot,
      autoProvisioned: true,
      records: formatDnsRecords(rw),
    });
  } catch (e) {
    if (isUniqueViolation(e)) {
      return res.status(409).json({ error: 'That domain is already connected to another site' });
    }
    console.error('Railway domain error:', e.message);
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
    const site = await dbGet('SELECT railway_domain_id FROM sites WHERE custom_domain = ?', domain);
    if (RAILWAY_READY && site?.railway_domain_id) {
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

// Billing portal (manage subscription)
app.post('/api/billing/portal', requireAuth, async (req, res) => {
  const user = await dbGet('SELECT stripe_customer_id FROM users WHERE id = ?', req.user.id);
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
      await dbRun("UPDATE users SET plan = 'free', stripe_subscription_id = NULL WHERE stripe_subscription_id = ?", sub.id);
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
input{width:100%;padding:13px 14px;border:1.5px solid #E5E7EB;border-radius:10px;font-size:15px;font-family:inherit}
input:focus{outline:none;border-color:#6C47FF}
button{width:100%;margin-top:16px;padding:14px;background:#6C47FF;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;font-family:inherit}
button:disabled{opacity:.6;cursor:default}
.msg{margin-top:14px;font-size:13px;line-height:1.5}
.ok{color:#059669}.bad{color:#DC2626}
a{color:#6C47FF;font-weight:600;text-decoration:none}</style></head><body>
<div class="card">
  <h1>Choose a new password</h1>
  <p class="sub">Pick something you'll remember. This link works once.</p>
  <label for="pw">New password</label>
  <input type="password" id="pw" placeholder="At least 6 characters" autocomplete="new-password">
  <button id="go" onclick="submitReset()">Save new password</button>
  <div class="msg" id="msg"></div>
</div>
<script>
const TOKEN = ${JSON.stringify(token)};
async function submitReset(){
  const pw = document.getElementById('pw').value;
  const msg = document.getElementById('msg');
  const btn = document.getElementById('go');
  if (pw.length < 6){ msg.className='msg bad'; msg.textContent='Please use at least 6 characters.'; return; }
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

// ── PREVIEW ROUTE ──────────────────────────────────────────────────────────────
app.get('/preview/:uuid', async (req, res) => {
  const row = await dbGet('SELECT data FROM sites WHERE uuid = ?', req.params.uuid);
  if (!row) return res.status(404).send(notFoundHtml());
  res.send(await buildWebsite(JSON.parse(row.data), req.params.uuid, BASE_URL));
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
    .slice(0, 3)
    .map(t => ({ quote: ((t && t.quote) || '').trim(), author: ((t && t.author) || '').trim() || 'Client' }))
    .filter(t => t.quote);

  // Which sections to render. Anything unset defaults to visible so existing
  // sites are unchanged — except the testimonial, which is opt-in.
  const sec = s.sections || {};
  const show = {
    about: sec.about !== false,
    services: sec.services !== false,
    testimonial: sec.testimonial === true && testimonials.length > 0,
    cta: sec.cta !== false,
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
      iconUrl: (c.iconUrl || '').trim(),
      title: (c.title || '').trim() || d.title,
      text: (c.text || '').trim() || d.text,
    };
  });

  // A button pointing at a section the owner switched off would be a dead
  // anchor, so retarget it to a section that still exists (or drop the link).
  const sectionVisible = { about: show.about, services: show.services, contact: show.cta };
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
    show.cta ? '<a href="#contact">Contact</a>' : '',
  ].join('');

  // Check if this site has badge removed (Starter+ user)
  const siteRow = await dbGet('SELECT user_id FROM sites WHERE uuid = ?', uuid);
  let showBadge = true;
  if (siteRow?.user_id) {
    const user = await dbGet('SELECT plan FROM users WHERE id = ?', siteRow.user_id);
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
.nav-cta{display:inline-block;text-decoration:none;padding:10px 24px;background:${f.primary};color:${f.ctaText};border-radius:${f.btnRadius};font-size:14px;font-weight:700;cursor:pointer;border:none;}
.hero{padding:${f.heroPadding};background:${f.heroBg};display:grid;grid-template-columns:1fr ${f.heroImgCol};gap:64px;align-items:center;${f.heroExtra}}
.hero-img-wrap{border-radius:${f.imgRadius};overflow:hidden;aspect-ratio:4/3;background:${f.heroImgBg};display:flex;align-items:center;justify-content:center;${f.heroImgExtra}}
.hero h1{font-family:${f.headFont};font-size:clamp(32px,5vw,58px);font-weight:${f.heroWeight};line-height:1.1;color:${f.heroText};margin-bottom:20px;letter-spacing:${f.heroTracking};}
.hero h1 em{color:${f.accent};font-style:normal;}
.hero-eyebrow{font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:${f.accent};margin-bottom:16px;}
.hero-sub{font-size:17px;color:${f.heroSubText};max-width:480px;margin-bottom:36px;line-height:1.6;}
.hero-btns{display:flex;gap:16px;flex-wrap:wrap;}
.btn-p{text-decoration:none;padding:16px 36px;background:${f.primary};color:${f.ctaText};border-radius:${f.btnRadius};font-size:16px;font-weight:700;border:none;cursor:pointer;display:inline-flex;align-items:center;gap:8px;transition:transform 0.15s;}
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
.testimonials-grid{display:grid;gap:28px;max-width:1000px;margin:0 auto;}
.testimonials-grid.count-1{grid-template-columns:1fr;max-width:640px;}
.testimonials-grid.count-2{grid-template-columns:repeat(2,1fr);}
.testimonials-grid.count-3{grid-template-columns:repeat(3,1fr);}
.testimonial-card{padding:40px 32px;background:${f.testimonialCardBg};border-radius:${f.cardRadius};border:${f.testimonialBorder};text-align:center;}
@media(max-width:700px){.testimonials-grid.count-2,.testimonials-grid.count-3{grid-template-columns:1fr;}}
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
function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw)) return null;
    return 'mailto:' + raw;
  }
  if (type === 'phone') {
    const digits = raw.replace(/[^\d+]/g, '');
    return digits ? 'tel:' + digits : null;
  }
  if (type === 'url') {
    // Anything not plainly http(s) gets prefixed, which also neutralises
    // javascript: and data: payloads rather than emitting them as-is.
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
