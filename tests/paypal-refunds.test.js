// Refunds: recorded against the customer and the payment they refund, picked up
// from PayPal directly when the webhook notice never arrives, never counted twice.
process.env.SQLITE_PATH = 'test-paypal-refunds.db';
process.env.PAYMENT_PROVIDER = 'paypal';
process.env.PAYPAL_MODE = 'live';
process.env.PAYPAL_CLIENT_ID = 'test-client';
process.env.PAYPAL_CLIENT_SECRET = 'test-secret';
process.env.PAYPAL_WEBHOOK_ID = 'WH-TEST';
process.env.ADMIN_PASSWORD = 'admin-test-password';
delete process.env.RESEND_API_KEY;

const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

const request = require('supertest');
const { app, initDb } = require('../server.js');

const realFetch = global.fetch;
// What PayPal would answer, keyed by API path
const paypal = { captures: {}, orders: {}, sales: {}, subscriptions: {}, signatureOk: true };
const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body, text: async () => JSON.stringify(body) });

let admin;
const asAdmin = () => ({ Authorization: `Bearer ${admin}` });

function webhook(event_type, resource) {
  return request(app).post('/api/paypal/webhook')
    .set('Content-Type', 'application/json')
    .send(JSON.stringify({ id: `WH-${Math.random()}`, event_type, resource }));
}

async function newCustomer(email) {
  const reg = await request(app).post('/api/auth/register').send({ email, password: 'longenough1' });
  const me = await request(app).get('/api/me').set({ Authorization: `Bearer ${reg.body.token}` });
  return { id: me.body.id, token: reg.body.token };
}

async function buyStarter(user, capId, orderId) {
  paypal.captures[capId] = { id: capId, status: 'COMPLETED', custom_id: `${user.id}:starter`,
    amount: { value: '29.00', currency_code: 'USD' }, supplementary_data: { related_ids: { order_id: orderId } } };
  paypal.orders[orderId] = { id: orderId, purchase_units: [{ payments: { captures: [paypal.captures[capId]], refunds: [] } }] };
  const res = await webhook('PAYMENT.CAPTURE.COMPLETED', paypal.captures[capId]);
  expect(res.status).toBe(200);
}

// Refund it in "PayPal" without telling the app
function refundInPayPal(capId, orderId, refundId) {
  paypal.captures[capId].status = 'REFUNDED';
  paypal.orders[orderId].purchase_units[0].payments.refunds.push({ id: refundId, status: 'COMPLETED', amount: { value: '29.00', currency_code: 'USD' } });
}

const planOf = async user => (await request(app).get('/api/me').set({ Authorization: `Bearer ${user.token}` })).body.plan;
const overview = async () => (await request(app).get('/api/admin/overview').set(asAdmin())).body;

beforeAll(async () => {
  global.fetch = jest.fn(async (url, opts = {}) => {
    const u = new URL(url);
    const p = u.pathname;
    if (p === '/v1/oauth2/token') return json({ access_token: 'tok', expires_in: 3600 });
    if (p === '/v1/notifications/verify-webhook-signature') return json({ verification_status: paypal.signatureOk ? 'SUCCESS' : 'FAILURE' });
    let m;
    if ((m = p.match(/^\/v2\/payments\/captures\/(.+)$/))) return paypal.captures[m[1]] ? json(paypal.captures[m[1]]) : json({ message: 'not found' }, 404);
    if ((m = p.match(/^\/v2\/checkout\/orders\/(.+)$/))) return paypal.orders[m[1]] ? json(paypal.orders[m[1]]) : json({ message: 'not found' }, 404);
    if ((m = p.match(/^\/v1\/payments\/sale\/(.+)$/))) return paypal.sales[m[1]] ? json(paypal.sales[m[1]]) : json({ message: 'not found' }, 404);
    if ((m = p.match(/^\/v1\/billing\/subscriptions\/(.+)$/))) return json(paypal.subscriptions[m[1]] || {});
    return json({ ok: true });
  });
  await initDb();
  admin = (await request(app).post('/api/admin/login').send({ password: 'admin-test-password' })).body.token;
});
afterAll(() => {
  global.fetch = realFetch;
  fs.rmSync(dbFile, { force: true });
});

test('a Starter refund the webhook missed is found by the PayPal check', async () => {
  const user = await newCustomer('missed@example.com');
  await buyStarter(user, 'CAP1', 'ORD1');
  expect(await planOf(user)).toBe('starter');

  let o = await overview();
  expect(o.revenueLast30Days).toBe(29);
  expect(o.recentPayments[0]).toMatchObject({ kind: 'starter', refunded: null, email: 'missed@example.com' });

  refundInPayPal('CAP1', 'ORD1', 'REF1');
  const check = await request(app).post('/api/admin/check-refunds').set(asAdmin());
  expect(check.status).toBe(200);
  expect(check.body.found).toBe(1);

  expect(await planOf(user)).toBe('free');
  o = await overview();
  expect(o.revenueLast30Days).toBe(0);
  expect(o.refundsLast30Days).toBe(29);
  const refund = o.recentPayments.find(p => p.kind === 'refund');
  expect(refund).toMatchObject({ amount: -29, email: 'missed@example.com' });
  expect(o.recentPayments.find(p => p.kind === 'starter').refunded).toBe('full');
  expect(o.paypal.lastRefundCheck.found).toBe(1);

  // The late webhook for the same refund changes nothing
  await webhook('PAYMENT.CAPTURE.REFUNDED', { id: 'REF1', amount: { value: '29.00', currency_code: 'USD' }, links: [{ rel: 'up', href: 'https://api-m.paypal.com/v2/payments/captures/CAP1' }] });
  const again = await request(app).post('/api/admin/check-refunds').set(asAdmin());
  expect(again.body.found).toBe(0);
  o = await overview();
  expect(o.recentPayments.filter(p => p.kind === 'refund')).toHaveLength(1);
  expect(o.revenueAllTime).toBe(0);
});

test('a refund webhook records the customer and drops Starter', async () => {
  const user = await newCustomer('webhook@example.com');
  await buyStarter(user, 'CAP2', 'ORD2');
  refundInPayPal('CAP2', 'ORD2', 'REF2');
  const res = await webhook('PAYMENT.CAPTURE.REFUNDED', { id: 'REF2', amount: { value: '29.00', currency_code: 'USD' }, links: [{ rel: 'up', href: 'https://api-m.paypal.com/v2/payments/captures/CAP2' }] });
  expect(res.status).toBe(200);
  expect(await planOf(user)).toBe('free');
  const o = await overview();
  expect(o.recentPayments.find(p => p.kind === 'refund' && p.email === 'webhook@example.com')).toBeTruthy();
  expect(o.paypal.lastWebhook.type).toBe('PAYMENT.CAPTURE.REFUNDED');
});

test('a Pro refund found by the check is replaced, not doubled, by the webhook', async () => {
  const user = await newCustomer('pro@example.com');
  paypal.subscriptions['SUB1'] = { id: 'SUB1', custom_id: String(user.id), status: 'ACTIVE', billing_info: {} };
  paypal.sales['SALE1'] = { id: 'SALE1', state: 'completed', amount: { total: '12.00', currency: 'USD' } };
  await webhook('PAYMENT.SALE.COMPLETED', { id: 'SALE1', billing_agreement_id: 'SUB1', amount: { total: '12.00', currency: 'USD' } });

  paypal.sales['SALE1'].state = 'refunded';
  expect((await request(app).post('/api/admin/check-refunds').set(asAdmin())).body.found).toBe(1);
  await webhook('PAYMENT.SALE.REFUNDED', { id: 'REFS1', sale_id: 'SALE1', amount: { total: '12.00', currency: 'USD' } });

  const o = await overview();
  const proRefunds = o.recentPayments.filter(p => p.kind === 'refund' && p.email === 'pro@example.com');
  expect(proRefunds).toHaveLength(1);
  expect(proRefunds[0].amount).toBe(-12);
  expect(o.recentPayments.find(p => p.kind === 'pro').refunded).toBe('full');
});

test('rejected webhooks are shown so a setup problem is visible', async () => {
  paypal.signatureOk = false;
  const res = await webhook('PAYMENT.CAPTURE.REFUNDED', { id: 'FAKE' });
  paypal.signatureOk = true;
  expect(res.status).toBe(400);
  const o = await overview();
  expect(o.paypal.lastRejected.reason).toMatch(/signature/);
  expect(o.paypal).toMatchObject({ enabled: true, mode: 'live', webhookConfigured: true });
});

test('customers show how they pay and what they have paid', async () => {
  const res = await request(app).get('/api/admin/customers').set(asAdmin());
  const pro = res.body.find(c => c.email === 'pro@example.com');
  expect(pro.totalPaid).toBe(0);
  const missed = res.body.find(c => c.email === 'missed@example.com');
  expect(missed.billing).toBeNull(); // refunded, back on Free
  expect(missed.lastSeenAt).toBeTruthy();
});
