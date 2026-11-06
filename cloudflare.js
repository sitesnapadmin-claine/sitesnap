'use strict';

// Cloudflare for SaaS custom hostnames.
//
// A customer points their own domain (a CNAME) at customers.site-snap.app.
// Cloudflare issues the certificate and sends the traffic to a small Worker,
// which forwards it to the app and passes the customer's domain along in the
// X-Original-Host header (see originalHost below).
//
// Registration ids are stored in the same column as Railway domain ids, with a
// "cf:" prefix so the two can never be confused.

const crypto = require('crypto');

const ID_PREFIX = 'cf:';

// Second level names that behave like a top level (shop.example.co.uk)
const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']);

// The part a customer types in the "Name" box at their DNS provider.
// www.example.com -> www, shop.example.com -> shop, example.com -> @
function hostLabel(domain) {
  const parts = String(domain).toLowerCase().split('.');
  const tld = parts[parts.length - 1];
  const second = parts[parts.length - 2];
  const registrableLength = tld.length === 2 && SECOND_LEVEL.has(second) ? 3 : 2;
  if (parts.length <= registrableLength) return '@';
  return parts.slice(0, parts.length - registrableLength).join('.');
}

module.exports = function createCloudflare(env = process.env, fetchFn = fetch) {
  const token = env.CLOUDFLARE_API_TOKEN || '';
  const zoneId = env.CLOUDFLARE_ZONE_ID || '';
  const edgeSecret = env.EDGE_SECRET || '';
  const cnameTarget = env.CF_CNAME_TARGET || 'customers.site-snap.app';
  const ready = Boolean(token && zoneId && edgeSecret);

  async function api(method, path, body) {
    const res = await fetchFn(`https://api.cloudflare.com/client/v4/zones/${zoneId}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 429) throw new Error('Cloudflare rate limit reached. Try again in a few seconds.');
    const json = await res.json().catch(() => null);
    if (!json) throw new Error(`Cloudflare returned a non-JSON response (HTTP ${res.status})`);
    if (!json.success) {
      const msg = (json.errors || []).map(e => e.message).join('; ') || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return json.result;
  }

  function toRecords(domain, hostname) {
    const status = hostname?.status;
    const sslStatus = hostname?.ssl?.status;
    const records = [{
      type: 'CNAME',
      host: hostLabel(domain),
      value: cnameTarget,
      current: null,
      status: status === 'active' ? 'VALID' : 'PENDING',
      purpose: 'routing',
    }];
    return { records, certificateStatus: sslStatus === 'active' ? 'ISSUED' : 'PENDING' };
  }

  async function addDomain(domain) {
    const created = await api('POST', '/custom_hostnames', {
      hostname: domain,
      ssl: { method: 'http', type: 'dv', settings: { min_tls_version: '1.2' } },
    });
    const { records } = toRecords(domain, created);
    return { id: ID_PREFIX + created.id, records };
  }

  async function domainStatus(prefixedId, domain) {
    const hostname = await api('GET', `/custom_hostnames/${prefixedId.slice(ID_PREFIX.length)}`);
    const { records, certificateStatus } = toRecords(domain, hostname);
    return { records, certificateStatus };
  }

  async function deleteDomain(prefixedId) {
    return api('DELETE', `/custom_hostnames/${prefixedId.slice(ID_PREFIX.length)}`);
  }

  // The customer's own domain, but only when the request really came through
  // our Worker. Anyone can send an X-Original-Host header to the app directly,
  // so it is ignored unless the secret header matches too.
  function originalHost(headers) {
    if (!edgeSecret) return null;
    const sent = String(headers['x-sitesnap-edge'] || '');
    const a = Buffer.from(sent);
    const b = Buffer.from(edgeSecret);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const host = String(headers['x-original-host'] || '').toLowerCase().trim().replace(/:\d+$/, '');
    return /^[a-z0-9.-]+$/.test(host) ? host : null;
  }

  return {
    ready,
    cnameTarget,
    isCloudflareId: id => typeof id === 'string' && id.startsWith(ID_PREFIX),
    addDomain,
    domainStatus,
    deleteDomain,
    originalHost,
    hostLabel,
  };
};

module.exports.hostLabel = hostLabel;
