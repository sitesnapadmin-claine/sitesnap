// What happens to an account when Pro ends: custom domains are disconnected the same day,
// and an account with more sites than its plan allows gets 7 days to delete the extras.
// After that the account is restricted (no creating or editing sites, deleting still works).
// Nothing is ever deleted automatically.
const GRACE_DAYS = 7;

module.exports = function createPlanLimits({ dbGet, dbAll, dbRun, siteLimits, deleteRailwayDomain, clearDomainCache }) {
  async function disconnectDomains(userId) {
    const rows = await dbAll('SELECT uuid, custom_domain, railway_domain_id FROM sites WHERE user_id = ? AND custom_domain IS NOT NULL', userId);
    for (const r of rows) {
      if (r.railway_domain_id) {
        try { await deleteRailwayDomain(r.railway_domain_id); } catch (e) { console.warn('Could not remove domain from Railway:', e.message); }
        if (clearDomainCache) clearDomainCache(r.railway_domain_id);
      }
      await dbRun('UPDATE sites SET custom_domain = NULL, railway_domain_id = NULL WHERE uuid = ?', r.uuid);
      console.log('Custom domain disconnected (Pro ended): ' + r.custom_domain);
    }
    return rows.length;
  }

  // Call once when a customer's Pro plan has ended (the plan in the database is already lowered).
  async function onProEnded(userId) {
    try {
      const disconnected = await disconnectDomains(userId);
      const user = await dbGet('SELECT plan FROM users WHERE id = ?', userId);
      const limit = siteLimits[(user && user.plan) || 'free'];
      const row = await dbGet('SELECT COUNT(*) AS c FROM sites WHERE user_id = ?', userId);
      const owned = Number((row && row.c) || 0);
      if (limit !== Infinity && owned > limit) {
        const deadline = new Date(Date.now() + GRACE_DAYS * 864e5).toISOString();
        await dbRun('UPDATE users SET over_limit_deadline = ? WHERE id = ?', deadline, userId);
        console.log('User ' + userId + ' has ' + owned + ' sites on a ' + limit + ' site plan, deadline ' + deadline);
      }
      return { disconnected, owned };
    } catch (e) {
      console.error('onProEnded error:', e.message);
      return null;
    }
  }

  // Where the account stands: used by /api/me (for the red banner) and by the restriction check.
  async function state(userId) {
    const user = await dbGet('SELECT plan, over_limit_deadline FROM users WHERE id = ?', userId);
    const plan = (user && user.plan) || 'free';
    const limit = siteLimits[plan];
    const row = await dbGet('SELECT COUNT(*) AS c FROM sites WHERE user_id = ?', userId);
    const owned = Number((row && row.c) || 0);
    const dom = await dbGet('SELECT COUNT(*) AS c FROM sites WHERE user_id = ? AND custom_domain IS NOT NULL', userId);
    const deadline = user && user.over_limit_deadline;
    const over = plan !== 'pro' && limit !== Infinity && owned > limit && !!deadline;
    const restricted = over && Date.parse(deadline) <= Date.now();
    return {
      plan, owned, customDomains: Number((dom && dom.c) || 0),
      siteLimit: limit === Infinity ? null : limit,
      excess: over ? owned - limit : 0,
      overLimitDeadline: over ? deadline : null,
      restricted,
    };
  }

  return { onProEnded, disconnectDomains, state, GRACE_DAYS };
};
