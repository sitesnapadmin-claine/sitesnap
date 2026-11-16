// Regression tests for the security fixes from the 16 Nov 2026 launch audit.
// Each test is a real attack that worked before the fix.
process.env.SQLITE_PATH = 'test-security.db';
process.env.APP_DOMAIN = 'site-snap.app';
process.env.RAILWAY_PUBLIC_DOMAIN = 'sitesnap-production-b50b.up.railway.app';
delete process.env.STRIPE_WEBHOOK_SECRET;

const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

const request = require('supertest');
const { app, initDb, buildWebsite, safeColor, safeImageUrl, isReservedHost } = require('../server.js');

let token;
let userId;

beforeAll(async () => {
  await initDb();
  const res = await request(app).post('/api/auth/register')
    .send({ name: 'Eve', email: 'eve@example.com', password: 'secret12' });
  token = res.body.token;
  userId = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).id;
});

afterAll(() => {
  fs.rmSync(dbFile, { force: true });
});

const auth = () => ({ Authorization: `Bearer ${token}` });

describe('generated sites cannot carry script', () => {
  const evil = {
    bizName: 'Bakery',
    logoUrl: 'x" onerror="alert(1)',
    heroUrl: 'javascript:alert(1)',
    aboutUrl: "https://ok.example/a.jpg' onload='alert(1)",
    colorPrimary: 'red;}</style><script>alert(1)</script><style>',
    colorAccent: '#ff0000',
    colorButton: 'expression(alert(1))',
    gallery: [{ url: 'x" onerror="alert(2)' }],
    features: [{ iconUrl: '"><script>alert(3)</script>' }],
    sectionBg: { hero: { mode: 'image', url: "a.jpg');}</style><script>alert(4)</script>", overlay: '</style><script>alert(5)</script>' } },
  };

  test('no injected markup reaches the page', async () => {
    const html = await buildWebsite(evil, 'no-such-uuid', 'https://www.site-snap.app');
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/onerror=|onload=/i);
    expect(html).not.toMatch(/javascript:/i);
    expect(html).toContain('#ff0000'); // a valid colour still works
  });

  test('preview responses forbid script with a CSP', async () => {
    const save = await request(app).post('/api/sites').set(auth()).send({ data: { bizName: 'Safe Co' } });
    const res = await request(app).get(`/preview/${save.body.uuid}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-security-policy']).toMatch(/script-src 'none'/);
    await request(app).delete(`/api/sites/${save.body.uuid}`).set(auth());
  });

  test('safeColor and safeImageUrl', () => {
    expect(safeColor('#6C47FF', 'x')).toBe('#6C47FF');
    expect(safeColor('#abc', 'x')).toBe('#abc');
    expect(safeColor('red', '#000000')).toBe('#000000');
    expect(safeImageUrl('https://res.cloudinary.com/a/b.jpg')).toBe('https://res.cloudinary.com/a/b.jpg');
    expect(safeImageUrl('/uploads/a.png')).toBe('/uploads/a.png');
    expect(safeImageUrl('//evil.com/a.png')).toBe('');
    expect(safeImageUrl('data:image/svg+xml,<svg onload=alert(1)>')).toBe('');
    expect(safeImageUrl('x" onerror="y')).toBe('');
  });
});

describe('uploads only accept real images', () => {
  const PNG = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    Buffer.alloc(64),
  ]);

  test('an HTML file labelled as PNG is refused', async () => {
    const res = await request(app).post('/api/upload')
      .attach('file', Buffer.from('<script>alert(document.domain)</script>'), { filename: 'evil.html', contentType: 'image/png' });
    expect(res.status).toBe(400);
  });

  test('SVG is refused', async () => {
    const res = await request(app).post('/api/upload')
      .attach('file', Buffer.from('<svg onload="alert(1)"/>'), { filename: 'a.svg', contentType: 'image/svg+xml' });
    expect(res.status).toBe(400);
  });

  test('a real PNG is accepted and saved with a .png name whatever it was called', async () => {
    const res = await request(app).post('/api/upload')
      .attach('file', PNG, { filename: 'photo.html', contentType: 'image/png' });
    expect(res.status).toBe(200);
    expect(res.body.url).toMatch(/\.png$/);
    const file = path.join(__dirname, '..', 'uploads', path.basename(res.body.url));
    const served = await request(app).get('/uploads/' + path.basename(res.body.url));
    expect(served.headers['content-type']).toMatch(/image\/png/);
    expect(served.headers['x-content-type-options']).toBe('nosniff');
    fs.rmSync(file, { force: true });
  });
});

describe('customer domains cannot take over SiteSnap hosts', () => {
  beforeAll(async () => {
    // Make the test account Pro straight in the database
    const Database = require('better-sqlite3');
    const db = new Database(dbFile);
    db.prepare("UPDATE users SET plan = 'pro' WHERE id = ?").run(userId);
    db.close();
  });

  test.each([
    'sitesnap-production-b50b.up.railway.app',
    'anything.up.railway.app',
    'site-snap.app',
    'www.site-snap.app',
    'customers.site-snap.app',
    'localhost',
  ])('refuses %s', async (domain) => {
    const save = await request(app).post('/api/sites').set(auth()).send({ data: { bizName: 'Hijack' } });
    const res = await request(app).post(`/api/sites/${save.body.uuid}/domain`).set(auth()).send({ domain });
    expect(res.status).toBe(400);
    await request(app).delete(`/api/sites/${save.body.uuid}`).set(auth());
  });

  test('a genuine customer domain is still accepted', async () => {
    const save = await request(app).post('/api/sites').set(auth()).send({ data: { bizName: 'Real' } });
    const res = await request(app).post(`/api/sites/${save.body.uuid}/domain`).set(auth()).send({ domain: 'www.realbakery.com' });
    expect(res.status).toBe(200);
    await request(app).delete(`/api/sites/${save.body.uuid}`).set(auth());
  });

  test('reserved subdomains are refused', async () => {
    expect(isReservedHost('admin.site-snap.app')).toBe(true);
    expect(isReservedHost('www.joesbakery.com')).toBe(false);
  });
});

describe('payments and sessions', () => {
  test('an unsigned Stripe webhook cannot upgrade anyone', async () => {
    const res = await request(app).post('/api/webhook')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ type: 'checkout.session.completed', data: { object: { metadata: { userId: String(userId), plan: 'pro' } } } }));
    expect(res.status).not.toBe(200);
  });

  test('login with a missing password answers instead of hanging', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'eve@example.com' });
    expect(res.status).toBe(400);
  });

  test('login with a non-string email answers instead of hanging', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 123, password: 'x' });
    expect(res.status).toBe(400);
  });

  test('registration rejects an invalid email', async () => {
    const res = await request(app).post('/api/auth/register').send({ email: 'notanemail', password: 'secret12' });
    expect(res.status).toBe(400);
  });

  test('the name given at sign up is saved', async () => {
    const me = await request(app).get('/api/me').set(auth());
    expect(me.body.name).toBe('Eve');
  });

  test('DNS status is only shown for your own domains', async () => {
    const res = await request(app).get('/api/domain/dns-check?domain=google.com').set(auth());
    expect(res.status).toBe(404);
  });

  test('responses carry security headers and no X-Powered-By', async () => {
    const res = await request(app).get('/api/config');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
  });
});
