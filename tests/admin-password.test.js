// Admin password: emailed reset link and change-password from the dashboard.
process.env.SQLITE_PATH = 'test-admin-password.db';
process.env.RESEND_API_KEY = 'test-key';
process.env.RESET_FROM_EMAIL = 'SiteSnap <hello@site-snap.app>';
process.env.ADMIN_PASSWORD = 'env-admin-password';
process.env.ADMIN_EMAIL = 'owner@example.com';

const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

const request = require('supertest');
const { app, initDb } = require('../server.js');

const realFetch = global.fetch;
let sent = [];
const bearer = t => ({ Authorization: `Bearer ${t}` });
const login = password => request(app).post('/api/admin/login').send({ password });

async function requestResetLink() {
  sent = [];
  const res = await request(app).post('/api/admin/forgot-password').send({ email: 'attacker@evil.test' });
  expect(res.status).toBe(200);
  return { res, mail: sent[0], token: sent[0].body.html.match(/\/admin\/reset-password\?token=([a-f0-9]+)/)[1] };
}

beforeAll(async () => {
  global.fetch = jest.fn(async (url, opts) => {
    sent.push({ url, body: JSON.parse(opts.body) });
    return { ok: true, json: async () => ({ id: 'email_1' }) };
  });
  await initDb();
});
afterAll(() => {
  global.fetch = realFetch;
  fs.rmSync(dbFile, { force: true });
});

test('the reset link only goes to the owner address, whatever is sent in the request', async () => {
  const { res, mail } = await requestResetLink();
  expect(mail.body.to).toEqual(['owner@example.com']);
  expect(mail.body.subject).toBe('Reset your SiteSnap admin password');
  expect(res.body.message).toContain('o•••@example.com');
  expect(res.body.message).not.toContain('owner@example.com');
});

test('the reset page loads and is not indexed', async () => {
  const page = await request(app).get('/admin/reset-password?token=abc');
  expect(page.status).toBe(200);
  expect(page.text).toContain('Choose a new admin password');
  expect(page.text).toContain('noindex');
});

test('a reset link sets a new password once, and the old one stops working', async () => {
  const before = await login('env-admin-password');
  expect(before.status).toBe(200);

  const { token } = await requestResetLink();
  const short = await request(app).post('/api/admin/reset-password').send({ token, password: 'short' });
  expect(short.status).toBe(400);
  expect(short.body.error).toMatch(/12 characters/);

  const bad = await request(app).post('/api/admin/reset-password').send({ token: 'f'.repeat(64), password: 'a-brand-new-password' });
  expect(bad.status).toBe(400);

  const ok = await request(app).post('/api/admin/reset-password').send({ token, password: 'a-brand-new-password' });
  expect(ok.status).toBe(200);
  expect((await request(app).get('/api/admin/overview').set(bearer(ok.body.token))).status).toBe(200);

  // Single use
  const again = await request(app).post('/api/admin/reset-password').send({ token, password: 'another-new-password' });
  expect(again.status).toBe(400);

  // The new password wins over ADMIN_PASSWORD, and older sessions are signed out
  expect((await login('env-admin-password')).status).toBe(401);
  expect((await login('a-brand-new-password')).status).toBe(200);
  expect((await request(app).get('/api/admin/overview').set(bearer(before.body.token))).status).toBe(401);
});

test('a newer reset link replaces an older one', async () => {
  const first = await requestResetLink();
  const second = await requestResetLink();
  const old = await request(app).post('/api/admin/reset-password').send({ token: first.token, password: 'from-the-old-link-1' });
  expect(old.status).toBe(400);
  const ok = await request(app).post('/api/admin/reset-password').send({ token: second.token, password: 'a-brand-new-password' });
  expect(ok.status).toBe(200);
});

test('change password needs the current one and signs out other sessions', async () => {
  const a = (await login('a-brand-new-password')).body.token;
  const b = (await login('a-brand-new-password')).body.token;

  expect((await request(app).post('/api/admin/change-password').send({ currentPassword: 'a-brand-new-password', newPassword: 'changed-password-123' })).status).toBe(401);

  const wrong = await request(app).post('/api/admin/change-password').set(bearer(a))
    .send({ currentPassword: 'not-the-password', newPassword: 'changed-password-123' });
  expect(wrong.status).toBe(401);

  const ok = await request(app).post('/api/admin/change-password').set(bearer(a))
    .send({ currentPassword: 'a-brand-new-password', newPassword: 'changed-password-123' });
  expect(ok.status).toBe(200);

  expect((await request(app).get('/api/admin/overview').set(bearer(ok.body.token))).status).toBe(200);
  expect((await request(app).get('/api/admin/overview').set(bearer(b))).status).toBe(401);
  expect((await login('changed-password-123')).status).toBe(200);
});
