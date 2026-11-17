// Tests for the pre-launch work from the 16 Nov 2026 audit: sessions, email
// confirmation, contact forms, honest site content, SEO, billing pages.
process.env.SQLITE_PATH = 'test-prelaunch.db';
process.env.RESEND_API_KEY = 'test-key';
process.env.RESET_FROM_EMAIL = 'SiteSnap <hello@site-snap.app>';
process.env.ADMIN_PASSWORD = 'admin-test-password';
delete process.env.SIGNUP_NOTIFY_EMAIL;

const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

const request = require('supertest');
const { app, initDb, buildWebsite, normalizeContact } = require('../server.js');

const realFetch = global.fetch;
let sent = [];
const settle = () => new Promise(r => setTimeout(r, 50));
const BROWSER = 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/130 Safari/537.36';

let token;
const auth = (t = token) => ({ Authorization: `Bearer ${t}` });

beforeAll(async () => {
  global.fetch = jest.fn(async (url, opts) => {
    sent.push({ url, body: JSON.parse(opts.body) });
    return { ok: true, json: async () => ({ id: 'email_1' }) };
  });
  await initDb();
  const res = await request(app).post('/api/auth/register')
    .send({ name: 'Owner', email: 'owner@example.com', password: 'longenough1' });
  token = res.body.token;
  await settle();
});
afterAll(() => {
  global.fetch = realFetch;
  fs.rmSync(dbFile, { force: true });
});
beforeEach(() => { sent = []; });

describe('accounts', () => {
  test('passwords need at least 8 characters', async () => {
    const res = await request(app).post('/api/auth/register').send({ email: 'short@example.com', password: 'seven77' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/8 characters/);
  });

  test('a new account is asked to confirm its email, and the link confirms it', async () => {
    const reg = await request(app).post('/api/auth/register').send({ email: 'confirm@example.com', password: 'longenough1' });
    await settle();
    const mail = sent.find(m => m.body.to[0] === 'confirm@example.com');
    expect(mail.body.subject).toBe('Confirm your email for SiteSnap');
    const link = mail.body.html.match(/\/verify-email\?token=([a-f0-9]+)/);
    expect(link).toBeTruthy();

    let me = await request(app).get('/api/me').set(auth(reg.body.token));
    expect(me.body.emailVerified).toBe(false);

    const page = await request(app).get(`/verify-email?token=${link[1]}`);
    expect(page.status).toBe(200);
    expect(page.text).toContain('Email confirmed');
    me = await request(app).get('/api/me').set(auth(reg.body.token));
    expect(me.body.emailVerified).toBe(true);

    const again = await request(app).get(`/verify-email?token=${link[1]}`);
    expect(again.status).toBe(400);
  });

  test('changing the password signs out other devices but keeps this one signed in', async () => {
    const reg = await request(app).post('/api/auth/register').send({ email: 'devices@example.com', password: 'longenough1' });
    const oldToken = reg.body.token;
    const change = await request(app).post('/api/auth/set-password').set(auth(oldToken)).send({ password: 'brandnewpass' });
    expect(change.status).toBe(200);
    expect(change.body.token).toBeTruthy();
    expect((await request(app).get('/api/me').set(auth(oldToken))).status).toBe(401);
    expect((await request(app).get('/api/me').set(auth(change.body.token))).status).toBe(200);
    const login = await request(app).post('/api/auth/login').send({ email: 'devices@example.com', password: 'brandnewpass' });
    expect((await request(app).get('/api/me').set(auth(login.body.token))).status).toBe(200);
  });

  test('oversized site saves are refused', async () => {
    const res = await request(app).post('/api/sites').set(auth()).send({ data: { bizName: 'Big', tagline: 'x'.repeat(400 * 1024) } });
    expect(res.status).toBe(400);
  });
});

describe('customer sites', () => {
  test('no made-up trust claims; only what the owner wrote', async () => {
    const plain = await buildWebsite({ bizName: 'Bakery' }, 'none', 'https://www.site-snap.app');
    expect(plain).not.toMatch(/5-star rated|100% satisfaction|Trusted by clients/);
    const own = await buildWebsite({ bizName: 'Bakery', trust1: 'Family-run since 2012' }, 'none', 'https://www.site-snap.app');
    expect(own).toContain('Family-run since 2012');
  });

  test('default colours come from the chosen theme, not SiteSnap purple', async () => {
    const html = await buildWebsite({ bizName: 'Garden Co', designStyle: 'earthy' }, 'none', 'https://www.site-snap.app');
    const css = html.slice(html.indexOf('<style>'), html.indexOf('</style>')); // the badge is SiteSnap's own colour
    expect(css).not.toMatch(/#6C47FF/i);
    expect(css).toContain('#5A7A3A');
  });

  test('contact details render as working links, unsafe links are dropped', async () => {
    const html = await buildWebsite({
      bizName: 'Plumber',
      contact: { phone: '0113 496 0000', email: 'hi@plumber.example', address: '1 High St, Leeds', hours: 'Mon–Fri 9–5', instagram: 'instagram.com/plumber', facebook: 'javascript:alert(1)' },
    }, 'none', 'https://www.site-snap.app');
    expect(html).toContain('href="tel:01134960000"');
    expect(html).toContain('href="mailto:hi@plumber.example"');
    expect(html).toContain('google.com/maps/search');
    expect(html).toContain('https://instagram.com/plumber');
    expect(html).not.toContain('javascript:');
    expect(html).toContain('id="contact"');
  });

  test('normalizeContact rejects bad emails and phone numbers without digits', () => {
    const c = normalizeContact({ email: 'not an email', phone: 'call us' });
    expect(c.email).toBe('');
    expect(c.phone).toBe('');
    expect(c.hasDetails).toBe(false);
  });

  test('pages carry social cards, a canonical link and a phone menu', async () => {
    const html = await buildWebsite({ bizName: 'Cafe', heroUrl: 'https://res.cloudinary.com/x/hero.jpg' }, 'abc', 'https://www.site-snap.app');
    expect(html).toContain('property="og:title"');
    expect(html).toContain('og:image" content="https://res.cloudinary.com/x/hero.jpg"');
    expect(html).toContain('rel="canonical"');
    expect(html).toContain('class="nav-burger"');
    expect(html).not.toContain('alt=""Cafe"');
  });
});

describe('contact form and visit counts', () => {
  let uuid;
  beforeAll(async () => {
    const save = await request(app).post('/api/sites').set(auth())
      .send({ data: { bizName: 'Form Co', contact: { form: true, phone: '0113 496 0000' } } });
    uuid = save.body.uuid;
  });

  test('the published page shows the form', async () => {
    const page = await request(app).get(`/preview/${uuid}`).set('User-Agent', BROWSER);
    expect(page.text).toContain(`/api/contact/${uuid}`);
    expect(page.headers['content-security-policy']).toMatch(/form-action http/);
  });

  test('a message is emailed to the owner with reply-to set to the visitor', async () => {
    const res = await request(app).post(`/api/contact/${uuid}`).type('form')
      .send({ name: 'Visitor', email: 'visitor@example.com', message: 'Do you deliver?' });
    expect(res.status).toBe(303);
    expect(res.headers.location).toMatch(new RegExp(`/preview/${uuid}#contact-sent$`));
    expect(sent).toHaveLength(1);
    expect(sent[0].body.to).toEqual(['owner@example.com']);
    expect(sent[0].body.reply_to).toBe('visitor@example.com');
    expect(sent[0].body.html).toContain('Do you deliver?');
  });

  test('bots that fill the hidden field get no email', async () => {
    const res = await request(app).post(`/api/contact/${uuid}`).type('form')
      .send({ name: 'Bot', email: 'bot@example.com', message: 'spam', website: 'http://spam.example' });
    expect(res.status).toBe(303);
    expect(sent).toHaveLength(0);
  });

  test('a missing message is refused', async () => {
    const res = await request(app).post(`/api/contact/${uuid}`).type('form')
      .send({ name: 'Visitor', email: 'visitor@example.com', message: '' });
    expect(res.headers.location).toMatch(/#contact-error$/);
  });

  test('visits are counted for people, not bots', async () => {
    const before = (await request(app).get('/api/sites').set(auth())).body.find(s => s.uuid === uuid).views;
    await request(app).get(`/preview/${uuid}`).set('User-Agent', BROWSER);
    await request(app).get(`/preview/${uuid}`).set('User-Agent', 'Googlebot/2.1');
    await settle();
    const after = (await request(app).get('/api/sites').set(auth())).body.find(s => s.uuid === uuid).views;
    expect(after).toBe(before + 1);
  });
});

describe('app pages', () => {
  test('robots.txt and sitemap.xml exist', async () => {
    const robots = await request(app).get('/robots.txt');
    expect(robots.text).toContain('Sitemap:');
    expect(robots.text).toContain('Disallow: /api/');
    const map = await request(app).get('/sitemap.xml');
    expect(map.text).toContain('<urlset');
  });

  test('unknown pages get a branded 404, unknown API calls get JSON', async () => {
    const page = await request(app).get('/no-such-page');
    expect(page.status).toBe(404);
    expect(page.text).toContain('Page not found');
    const api = await request(app).get('/api/no-such-thing');
    expect(api.status).toBe(404);
    expect(api.body.error).toBe('Not found');
  });

  test('the success page never claims a payment it has not confirmed', async () => {
    const res = await request(app).get('/billing/success?plan=pro');
    expect(res.text).toContain('Confirming your payment');
    expect(res.text).not.toContain('Plan activated');
    expect(res.text).toContain('width=device-width');
  });

  test('admin revenue comes from the payments ledger', async () => {
    const Database = require('better-sqlite3');
    const db = new Database(dbFile);
    db.prepare("INSERT INTO payments (user_id, provider, kind, amount_cents, currency, external_id) VALUES (1, 'paypal', 'starter', 2900, 'USD', 'CAP-1')").run();
    db.prepare("INSERT INTO payments (user_id, provider, kind, amount_cents, currency, external_id) VALUES (1, 'paypal', 'pro', 1200, 'USD', 'SALE-1')").run();
    db.prepare("INSERT INTO payments (user_id, provider, kind, amount_cents, currency, external_id) VALUES (NULL, 'paypal', 'refund', -1200, 'USD', 'REF-1')").run();
    db.close();
    const login = await request(app).post('/api/admin/login').send({ password: 'admin-test-password' });
    expect(login.status).toBe(200);
    const wrong = await request(app).post('/api/admin/login').send({ password: 'nope' });
    expect(wrong.status).toBe(401);
    const o = await request(app).get('/api/admin/overview').set(auth(login.body.token));
    expect(o.body.revenueAllTime).toBe(29);
    expect(o.body.recentPayments).toHaveLength(3);
  });
});
