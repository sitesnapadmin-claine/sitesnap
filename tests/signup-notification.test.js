process.env.SQLITE_PATH = 'test-signup-notification.db';
process.env.RESEND_API_KEY = 'test-key';
process.env.RESET_FROM_EMAIL = 'SiteSnap <noreply@site-snap.app>';
delete process.env.SIGNUP_NOTIFY_EMAIL;
const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

const request = require('supertest');
const { app, initDb, buildSignupNotification } = require('../server.js');

const realFetch = global.fetch;
let sent;

beforeAll(async () => { await initDb(); });
beforeEach(() => {
  sent = [];
  global.fetch = jest.fn(async (url, opts) => {
    sent.push({ url, body: JSON.parse(opts.body) });
    return { ok: true, json: async () => ({ id: 'email_1' }) };
  });
});
afterAll(() => {
  global.fetch = realFetch;
  fs.rmSync(dbFile, { force: true });
});

const settle = () => new Promise(r => setTimeout(r, 50));

describe('new sign up alert', () => {
  test('emails the owner when an account is created', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ email: 'New.Customer@Example.com', password: 'hunter22' });
    expect(res.status).toBe(200);
    await settle();
    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe('https://api.resend.com/emails');
    expect(sent[0].body.to).toEqual(['sitesnap.admin@gmail.com']);
    expect(sent[0].body.subject).toBe('You have 1 new SiteSnap sign up!');
    expect(sent[0].body.html).toContain('new.customer@example.com');
    expect(sent[0].body.html).toContain('Name:');
    expect(sent[0].body.html).toContain('Email:');
  });

  test('does not email for a duplicate or rejected sign up', async () => {
    await request(app).post('/api/auth/register')
      .send({ email: 'new.customer@example.com', password: 'hunter22' });
    await request(app).post('/api/auth/register')
      .send({ email: 'short@example.com', password: '123' });
    await settle();
    expect(sent).toHaveLength(0);
  });

  test('sign up still succeeds when the email provider fails', async () => {
    global.fetch = jest.fn(async () => ({ ok: false, status: 500, text: async () => 'down' }));
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = await request(app).post('/api/auth/register')
      .send({ email: 'another@example.com', password: 'hunter22' });
    await settle();
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    spy.mockRestore();
  });

  test('shows the name when given and escapes it', () => {
    const mail = buildSignupNotification({ name: '<b>Jo</b>', email: 'jo@example.com' });
    expect(mail.html).toContain('&lt;b&gt;Jo&lt;/b&gt;');
    expect(buildSignupNotification({ email: 'jo@example.com' }).html).toContain('Not provided');
  });

  test('includes the name sent by the sign up form', async () => {
    await request(app).post('/api/auth/register')
      .send({ name: 'Jane Smith', email: 'jane@example.com', password: 'hunter22' });
    await settle();
    expect(sent).toHaveLength(1);
    expect(sent[0].body.html).toContain('<strong>Name:</strong> Jane Smith');
  });

  test('caps a very long name at 100 characters', () => {
    const mail = buildSignupNotification({ name: 'x'.repeat(500), email: 'jo@example.com' });
    expect(mail.html).toContain('x'.repeat(100));
    expect(mail.html).not.toContain('x'.repeat(101));
  });
});
