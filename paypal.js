// paypal.js
// PayPal payments for SiteSnap: Starter ($29 one time order) and Pro ($12 monthly subscription).
// Add this file next to server.js. It only switches on when PAYMENT_PROVIDER=paypal
// and the PayPal keys are set, so Stripe keeps working until you flip the setting.

const crypto = require('crypto');

module.exports = function createPayPal({ dbGet, dbRun, onProEnded }) {
  const MODE = (process.env.PAYPAL_MODE || 'sandbox').toLowerCase() === 'live' ? 'live' : 'sandbox';
  const API = MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const CLIENT_ID = process.env.PAYPAL_CLIENT_ID || '';
  const CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || '';
  const WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || '';
  const WANTS_PAYPAL = (process.env.PAYMENT_PROVIDER || 'stripe').toLowerCase() === 'paypal';
  const enabled = WANTS_PAYPAL && Boolean(CLIENT_ID && CLIENT_SECRET);

  if (WANTS_PAYPAL && !enabled) {
    console.warn('PAYMENT_PROVIDER is paypal but PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET is missing. Falling back to Stripe.');
  }
  if (enabled) console.log(`PayPal payments enabled (${MODE} mode)`);

  const STARTER_PRICE = '29.00';
  const RANK = { free: 0, starter: 1, pro: 2 };

  // ── Talking to PayPal ────────────────────────────────────────────────────────
  let tokenCache = { value: null, expires: 0 };

  async function accessToken() {
    if (tokenCache.value && Date.now() < tokenCache.expires - 60000) return tokenCache.value;
    const res = await fetch(`${API}/v1/oauth2/token`, {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });
    const json = await res.json().catch(() => null);
    if (!res.ok || !json?.access_token) throw new Error(`PayPal sign in failed (HTTP ${res.status})`);
    tokenCache = { value: json.access_token, expires: Date.now() + (json.expires_in || 300) * 1000 };
    return tokenCache.value;
  }

  async function api(method, path, body, extraHeaders = {}) {
    const token = await accessToken();
    const res = await fetch(`${API}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...extraHeaders },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (_) {}
    if (!res.ok) {
      const err = new Error(json?.details?.[0]?.issue || json?.message || `PayPal HTTP ${res.status}`);
      err.status = res.status;
      err.body = json;
      throw err;
    }
    return json;
  }

  // ── Pro plan id ──────────────────────────────────────────────────────────────
  // Live: set PAYPAL_PRO_PLAN_ID in Railway. Sandbox: if it is not set, a test plan
  // is created once and its id is printed in the logs so you can save it.
  let sandboxPlanId = null;

  function currentProPlanId() {
    return process.env.PAYPAL_PRO_PLAN_ID || sandboxPlanId;
  }

  async function proPlanId() {
    if (process.env.PAYPAL_PRO_PLAN_ID) return process.env.PAYPAL_PRO_PLAN_ID;
    if (MODE !== 'sandbox') throw new Error('PAYPAL_PRO_PLAN_ID is not set');
    if (sandboxPlanId) return sandboxPlanId;
    const product = await api('POST', '/v1/catalogs/products',
      { name: 'SiteSnap Pro', type: 'DIGITAL', category: 'SOFTWARE' },
      { 'PayPal-Request-Id': crypto.randomUUID() });
    const plan = await api('POST', '/v1/billing/plans', {
      product_id: product.id,
      name: 'SiteSnap Pro Monthly',
      status: 'ACTIVE',
      billing_cycles: [{
        frequency: { interval_unit: 'MONTH', interval_count: 1 },
        tenure_type: 'REGULAR',
        sequence: 1,
        total_cycles: 0,
        pricing_scheme: { fixed_price: { value: '12.00', currency_code: 'USD' } },
      }],
      payment_preferences: { auto_bill_outstanding: true, payment_failure_threshold: 1 },
    }, { 'PayPal-Request-Id': crypto.randomUUID() });
    sandboxPlanId = plan.id;
    console.log(`PayPal sandbox Pro plan created. Save this in Railway: PAYPAL_PRO_PLAN_ID=${plan.id}`);
    return plan.id;
  }

  // ── Plan changes in our own database ────────────────────────────────────────
  // Never lowers a plan here (a Pro customer who also buys Starter stays Pro).
  async function grant(userId, plan, { subscriptionId, orderId } = {}) {
    const row = await dbGet('SELECT plan FROM users WHERE id = ?', userId);
    if (!row) return false;
    if ((RANK[row.plan || 'free'] || 0) < RANK[plan]) {
      await dbRun('UPDATE users SET plan = ? WHERE id = ?', plan, userId);
    }
    if (subscriptionId) await dbRun('UPDATE users SET paypal_subscription_id = ? WHERE id = ?', subscriptionId, userId);
    if (orderId) await dbRun('UPDATE users SET paypal_order_id = ? WHERE id = ?', orderId, userId);
    console.log(`User ${userId} upgraded to ${plan} via PayPal`);
    return true;
  }

  // PayPal ends a subscription the moment it is cancelled, but the customer has paid for the
  // whole month. We remember when that paid period ends (paypal_access_until) and keep the Pro
  // plan until then. After that the plan drops back on its own (see expireIfDue).
  function accessEndFrom(sub) {
    const info = (sub && sub.billing_info) || {};
    if (info.next_billing_time && !Number.isNaN(Date.parse(info.next_billing_time))) {
      return new Date(info.next_billing_time).toISOString();
    }
    const last = info.last_payment && info.last_payment.time;
    if (last && !Number.isNaN(Date.parse(last))) {
      const d = new Date(last);
      d.setUTCMonth(d.getUTCMonth() + 1);
      return d.toISOString();
    }
    return null;
  }

  async function saveAccessUntil(subscriptionId, sub) {
    const until = accessEndFrom(sub);
    if (until) await dbRun('UPDATE users SET paypal_access_until = ? WHERE paypal_subscription_id = ?', until, subscriptionId);
  }

  function laterOf(a, b) {
    if (!a) return b || null;
    if (!b) return a;
    return Date.parse(a) >= Date.parse(b) ? a : b;
  }

  // Ends a subscription right away (payment suspended or plan expired). The date written to
  // paypal_access_until also stops an old login token from restoring the paid plan.
  async function endNow(subscriptionId) {
    const who = await dbGet('SELECT id FROM users WHERE paypal_subscription_id = ?', subscriptionId);
    await dbRun(
      "UPDATE users SET plan = CASE WHEN paypal_order_id IS NOT NULL THEN 'starter' ELSE 'free' END, paypal_subscription_id = NULL, paypal_access_until = ? WHERE paypal_subscription_id = ?",
      new Date().toISOString(), subscriptionId
    );
    if (who && onProEnded) await onProEnded(who.id);
  }

  // Drops a cancelled Pro customer back to Starter or Free once the month they paid for is over.
  // Cheap to call: it does nothing unless a cancelled subscription has really run out.
  async function expireIfDue(userId) {
    const row = await dbGet('SELECT plan, paypal_subscription_id, paypal_order_id, paypal_access_until FROM users WHERE id = ?', userId);
    if (!row || row.paypal_subscription_id || !row.paypal_access_until) return null;
    if (Date.parse(row.paypal_access_until) > Date.now()) return null;
    if (row.plan !== 'pro') return null;
    const next = row.paypal_order_id ? 'starter' : 'free';
    await dbRun('UPDATE users SET plan = ? WHERE id = ?', next, userId);
    if (onProEnded) await onProEnded(userId);
    console.log(`User ${userId} PayPal Pro period ended, plan set to ${next}`);
    return next;
  }

  // ── Starting a checkout ──────────────────────────────────────────────────────
  // Returns the PayPal address the customer should be sent to.
  async function startCheckout({ planKey, user, baseUrl }) {
    const returnUrl = `${baseUrl}/billing/success?provider=paypal&plan=${planKey}`;
    const cancelUrl = `${baseUrl}/billing/cancel`;

    if (planKey === 'starter') {
      const order = await api('POST', '/v2/checkout/orders', {
        intent: 'CAPTURE',
        purchase_units: [{
          custom_id: `${user.id}:starter`,
          description: 'SiteSnap Starter',
          amount: { currency_code: 'USD', value: STARTER_PRICE },
        }],
        payment_source: {
          paypal: {
            experience_context: {
              brand_name: 'SiteSnap',
              user_action: 'PAY_NOW',
              shipping_preference: 'NO_SHIPPING',
              return_url: returnUrl,
              cancel_url: cancelUrl,
            },
          },
        },
      }, { 'PayPal-Request-Id': crypto.randomUUID() });
      const link = (order.links || []).find(l => l.rel === 'payer-action' || l.rel === 'approve');
      if (!link) throw new Error('PayPal did not return an approval link');
      return link.href;
    }

    if (planKey === 'pro') {
      const subscriptionBody = {
        plan_id: await proPlanId(),
        custom_id: String(user.id),
        application_context: {
          brand_name: 'SiteSnap',
          user_action: 'SUBSCRIBE_NOW',
          shipping_preference: 'NO_SHIPPING',
          return_url: returnUrl,
          cancel_url: cancelUrl,
        },
      };
      // Re-activating Pro while the paid month is still running: the first payment waits until
      // that month is over, so the customer is not charged twice for the same days.
      const paidUntil = !user.paypal_subscription_id && user.paypal_access_until ? Date.parse(user.paypal_access_until) : NaN;
      if (paidUntil > Date.now() + 10 * 60 * 1000) {
        subscriptionBody.start_time = new Date(paidUntil).toISOString().replace(/\.\d{3}Z$/, 'Z');
      }
      const sub = await api('POST', '/v1/billing/subscriptions', subscriptionBody, { 'PayPal-Request-Id': crypto.randomUUID() });
      const link = (sub.links || []).find(l => l.rel === 'approve');
      if (!link) throw new Error('PayPal did not return an approval link');
      return link.href;
    }

    throw new Error('Unknown plan');
  }

  // ── Confirming payment when the customer returns to the site ────────────────
  async function confirmOrder(orderId) {
    let order;
    try {
      order = await api('POST', `/v2/checkout/orders/${encodeURIComponent(orderId)}/capture`, {},
        { 'PayPal-Request-Id': `capture-${orderId}` });
    } catch (_) {
      // Already captured, or not approved yet: look at the order as it stands
      order = await api('GET', `/v2/checkout/orders/${encodeURIComponent(orderId)}`);
    }
    if (order.status !== 'COMPLETED') return null;
    const unit = order.purchase_units?.[0];
    const cap = unit?.payments?.captures?.[0];
    const custom = unit?.custom_id || cap?.custom_id || '';
    const [uid, key] = String(custom).split(':');
    const userId = parseInt(uid, 10);
    if (!userId || key !== 'starter') return null;
    if (cap?.status !== 'COMPLETED' || cap?.amount?.value !== STARTER_PRICE || cap?.amount?.currency_code !== 'USD') return null;
    await grant(userId, 'starter', { orderId });
    return { userId, plan: 'starter' };
  }

  async function confirmSubscription(subscriptionId) {
    const sub = await api('GET', `/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}`);
    const planId = currentProPlanId();
    if (!planId || sub.plan_id !== planId) return null;
    const userId = parseInt(sub.custom_id, 10);
    if (!userId) return null;
    // Right after approval PayPal can take a moment to mark it ACTIVE.
    // If it is not active yet, the webhook will finish the upgrade.
    if (sub.status !== 'ACTIVE') return null;
    await grant(userId, 'pro', { subscriptionId });
    await saveAccessUntil(subscriptionId, sub);
    return { userId, plan: 'pro' };
  }

  // Called by the /billing/success page. Never throws.
  async function confirmReturn(query) {
    try {
      if (query.subscription_id) return await confirmSubscription(String(query.subscription_id));
      if (query.token) return await confirmOrder(String(query.token));
    } catch (e) {
      console.error('PayPal return confirmation error:', e.message);
    }
    return null;
  }

  // ── Webhook (PayPal tells us about payments and cancellations) ──────────────
  async function verifyWebhook(headers, rawBody) {
    if (!WEBHOOK_ID) return false;
    const result = await api('POST', '/v1/notifications/verify-webhook-signature', {
      auth_algo: headers['paypal-auth-algo'],
      cert_url: headers['paypal-cert-url'],
      transmission_id: headers['paypal-transmission-id'],
      transmission_sig: headers['paypal-transmission-sig'],
      transmission_time: headers['paypal-transmission-time'],
      webhook_id: WEBHOOK_ID,
      webhook_event: JSON.parse(rawBody.toString('utf8')),
    });
    return result.verification_status === 'SUCCESS';
  }

  async function handleWebhook(req, res) {
    let event;
    try {
      if (!(await verifyWebhook(req.headers, req.body))) return res.status(400).send('Invalid signature');
      event = JSON.parse(req.body.toString('utf8'));
    } catch (e) {
      console.error('PayPal webhook verification error:', e.message);
      return res.status(400).send('Bad webhook');
    }

    try {
      const r = event.resource || {};
      switch (event.event_type) {
        case 'BILLING.SUBSCRIPTION.ACTIVATED': {
          const userId = parseInt(r.custom_id, 10);
          if (userId && r.plan_id === currentProPlanId()) {
            await grant(userId, 'pro', { subscriptionId: r.id });
            await saveAccessUntil(r.id, r);
          }
          break;
        }
        case 'BILLING.SUBSCRIPTION.CANCELLED': {
          // The customer has paid for the current month, so keep their plan until it ends
          let until = accessEndFrom(r);
          try {
            const latest = await api('GET', `/v1/billing/subscriptions/${encodeURIComponent(r.id)}`);
            until = laterOf(accessEndFrom(latest), until);
          } catch (_) {}
          const row = await dbGet('SELECT id, paypal_access_until FROM users WHERE paypal_subscription_id = ?', r.id);
          const keepUntil = laterOf(until, row && row.paypal_access_until);
          if (row && keepUntil && Date.parse(keepUntil) > Date.now()) {
            await dbRun('UPDATE users SET paypal_subscription_id = NULL, paypal_access_until = ? WHERE id = ?', keepUntil, row.id);
            console.log(`PayPal subscription cancelled: ${r.id} (plan stays until ${keepUntil})`);
          } else {
            await endNow(r.id);
            console.log(`PayPal subscription ended: ${r.id}`);
          }
          break;
        }
        case 'BILLING.SUBSCRIPTION.EXPIRED':
        case 'BILLING.SUBSCRIPTION.SUSPENDED': {
          // Back to Starter if they bought it before, otherwise Free
          await endNow(r.id);
          console.log(`PayPal subscription ended: ${r.id}`);
          break;
        }
        case 'PAYMENT.SALE.COMPLETED': {
          // A monthly payment went through: move the paid until date forward
          if (r.billing_agreement_id) {
            const sub = await api('GET', `/v1/billing/subscriptions/${encodeURIComponent(r.billing_agreement_id)}`);
            await saveAccessUntil(r.billing_agreement_id, sub);
          }
          break;
        }
        case 'PAYMENT.CAPTURE.COMPLETED': {
          const [uid, key] = String(r.custom_id || '').split(':');
          const userId = parseInt(uid, 10);
          if (userId && key === 'starter' && r.amount?.value === STARTER_PRICE && r.amount?.currency_code === 'USD') {
            await grant(userId, 'starter', { orderId: r.supplementary_data?.related_ids?.order_id });
          }
          break;
        }
        case 'BILLING.SUBSCRIPTION.PAYMENT.FAILED':
          console.warn('PayPal payment failed for subscription:', r.id);
          break;
        default:
          break;
      }
    } catch (e) {
      console.error('PayPal webhook handling error:', e.message);
      return res.status(500).send('Error'); // PayPal will retry
    }
    res.json({ received: true });
  }

  // ── Cancelling and managing ──────────────────────────────────────────────────
  async function cancelSubscription(subscriptionId, reason = 'Cancelled by customer') {
    await api('POST', `/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}/cancel`, { reason });
  }

  // Customer cancels Pro from the plan screen. PayPal ends the subscription at once, so we note
  // the date the paid month runs until and keep Pro until then. Returns that date (or null).
  async function cancelForUser(userId, subscriptionId) {
    let until = null;
    try {
      const sub = await api('GET', '/v1/billing/subscriptions/' + encodeURIComponent(subscriptionId));
      until = accessEndFrom(sub);
    } catch (_) {}
    await cancelSubscription(subscriptionId);
    const row = await dbGet('SELECT paypal_access_until FROM users WHERE id = ?', userId);
    const keepUntil = laterOf(until, row && row.paypal_access_until);
    if (keepUntil && Date.parse(keepUntil) > Date.now()) {
      await dbRun('UPDATE users SET paypal_subscription_id = NULL, paypal_access_until = ? WHERE id = ?', keepUntil, userId);
      console.log('User ' + userId + ' cancelled PayPal Pro (plan stays until ' + keepUntil + ')');
      return keepUntil;
    }
    await endNow(subscriptionId);
    console.log('User ' + userId + ' cancelled PayPal Pro (ended now)');
    return null;
  }

  // PayPal has no billing portal like Stripe. Customers manage automatic payments here.
  function manageUrl() {
    return MODE === 'live'
      ? 'https://www.paypal.com/myaccount/autopay/'
      : 'https://www.sandbox.paypal.com/myaccount/autopay/';
  }

  return { enabled, mode: MODE, startCheckout, confirmReturn, handleWebhook, cancelSubscription, cancelForUser, manageUrl, expireIfDue };
};
