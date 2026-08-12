// Coverage the existing auth.test.js was missing: it only proved that the
// password set at registration works. It never proved that a password
// CHANGE (via "Update Password" in Account settings, or a full forgot/reset
// email loop) actually takes effect — i.e. that the old password stops
// working and the new one starts working. That's exactly the "are updated
// passwords actually working?" question this file answers.
//
// EMAIL_READY is computed once at server.js module-load time from
// RESEND_API_KEY + RESET_FROM_EMAIL, so both must be set BEFORE requiring
// the module. We also stub global.fetch (Node's built-in fetch, which is
// what sendEmail() calls) so no real network request goes out — we just
// capture the reset link that would have been emailed.
process.env.SQLITE_PATH = 'test-password-lifecycle.db';
process.env.RESEND_API_KEY = 'test-resend-key';
process.env.RESET_FROM_EMAIL = 'reset@example.com';

const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

let capturedEmail = null;
global.fetch = jest.fn(async (url, opts) => {
  capturedEmail = JSON.parse(opts.body);
  return { ok: true, json: async () => ({ id: 'test-email-id' }) };
});

const request = require('supertest');
const { app, initDb } = require('../server.js');

beforeAll(async () => {
  await initDb();
});

afterAll(() => {
  fs.rmSync(dbFile, { force: true });
});

describe('changing your password (Account settings "Update Password")', () => {
  const email = 'setpw@example.com';
  let token;

  beforeAll(async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email, password: 'original1' });
    token = res.body.token;
  });

  test('the old password still works before any change', async () => {
    const res = await request(app).post('/api/auth/login').send({ email, password: 'original1' });
    expect(res.status).toBe(200);
  });

  test('set-password requires a signed-in session', async () => {
    const res = await request(app).post('/api/auth/set-password').send({ password: 'newpass1' });
    expect(res.status).toBe(401);
  });

  test('changing the password succeeds', async () => {
    const res = await request(app)
      .post('/api/auth/set-password')
      .set('Authorization', `Bearer ${token}`)
      .send({ password: 'newpass1' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('the OLD password no longer logs in', async () => {
    const res = await request(app).post('/api/auth/login').send({ email, password: 'original1' });
    expect(res.status).toBe(401);
  });

  test('the NEW password logs in', async () => {
    const res = await request(app).post('/api/auth/login').send({ email, password: 'newpass1' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
  });
});

// The forgot/reset endpoints share one rate limiter (max 6 requests/hour,
// combined). This suite is written to use exactly 6 total calls across
// both endpoints so it stays under that limit in one run.
describe('forgot password → email link → reset (full loop)', () => {
  const email = 'forgot@example.com';

  beforeAll(async () => {
    await request(app).post('/api/auth/register').send({ email, password: 'firstpass1' });
  });

  function tokenFromCapturedEmail() {
    const match = capturedEmail.html.match(/token=([a-f0-9]+)/);
    return match && match[1];
  }

  test('requesting a reset sends an email containing a working link, and never reveals whether the address exists', async () => {
    const res = await request(app).post('/api/auth/forgot-password').send({ email }); // forgot #1
    expect(res.status).toBe(200);
    expect(capturedEmail).toBeTruthy();
    expect(capturedEmail.to).toEqual([email]);
    expect(capturedEmail.html).toContain('/reset-password?token=');
    expect(res.body.message).toMatch(/if that email has an account/i);
  });

  test('the emailed token resets the password', async () => {
    const token = tokenFromCapturedEmail();
    expect(token).toBeTruthy();
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'brandnew1' }); // reset #1
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('the OLD password no longer logs in after a reset', async () => {
    const res = await request(app).post('/api/auth/login').send({ email, password: 'firstpass1' });
    expect(res.status).toBe(401);
  });

  test('the NEW password logs in after a reset', async () => {
    const res = await request(app).post('/api/auth/login').send({ email, password: 'brandnew1' });
    expect(res.status).toBe(200);
  });

  test('the reset link is single-use — the same token cannot be replayed', async () => {
    const token = tokenFromCapturedEmail();
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'anotherpass1' }); // reset #2
    expect(res.status).toBe(400);
  });

  test('a garbage token is rejected', async () => {
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token: 'not-a-real-token', password: 'whatever12' }); // reset #3
    expect(res.status).toBe(400);
  });

  test('an expired reset token is rejected', async () => {
    // Request one more fresh token, then fast-forward past its 1-hour TTL.
    const before = Date.now;
    await request(app).post('/api/auth/forgot-password').send({ email }); // forgot #2
    const token = tokenFromCapturedEmail();

    Date.now = () => before() + 61 * 60 * 1000; // +61 minutes
    const res = await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'toolate123' }); // reset #4
    Date.now = before;

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/expired/i);
  });
});
