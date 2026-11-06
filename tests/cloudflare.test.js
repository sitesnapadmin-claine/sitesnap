const createCloudflare = require('../cloudflare');
const { hostLabel } = createCloudflare;

describe('hostLabel', () => {
  test('www and subdomains give the label to type at the DNS provider', () => {
    expect(hostLabel('www.example.com')).toBe('www');
    expect(hostLabel('shop.eu.example.com')).toBe('shop.eu');
  });
  test('a root domain gives @', () => {
    expect(hostLabel('example.com')).toBe('@');
  });
  test('two part endings such as co.uk are handled', () => {
    expect(hostLabel('www.example.co.uk')).toBe('www');
    expect(hostLabel('example.co.uk')).toBe('@');
  });
});

describe('originalHost', () => {
  const cf = createCloudflare({ CLOUDFLARE_API_TOKEN: 't', CLOUDFLARE_ZONE_ID: 'z', EDGE_SECRET: 'sekret' });

  test('is used when the secret matches', () => {
    expect(cf.originalHost({ 'x-sitesnap-edge': 'sekret', 'x-original-host': 'WWW.Example.com' })).toBe('www.example.com');
  });
  test('is ignored without the secret or with a wrong one', () => {
    expect(cf.originalHost({ 'x-original-host': 'www.example.com' })).toBeNull();
    expect(cf.originalHost({ 'x-sitesnap-edge': 'nope!!', 'x-original-host': 'www.example.com' })).toBeNull();
  });
  test('is ignored when no secret is configured', () => {
    const open = createCloudflare({});
    expect(open.originalHost({ 'x-sitesnap-edge': '', 'x-original-host': 'www.example.com' })).toBeNull();
  });
  test('rejects odd values', () => {
    expect(cf.originalHost({ 'x-sitesnap-edge': 'sekret', 'x-original-host': 'a b/c' })).toBeNull();
  });
});

describe('Cloudflare API calls', () => {
  function mockFetch(result, success = true) {
    const calls = [];
    const fn = async (url, opts) => {
      calls.push({ url, opts });
      return { status: 200, json: async () => (success ? { success: true, result } : { success: false, errors: [{ message: 'Duplicate custom hostname found.' }] }) };
    };
    fn.calls = calls;
    return fn;
  }
  const env = { CLOUDFLARE_API_TOKEN: 'tok', CLOUDFLARE_ZONE_ID: 'zone1', EDGE_SECRET: 's' };

  test('addDomain registers the hostname and returns one CNAME record', async () => {
    const f = mockFetch({ id: 'abc', status: 'pending', ssl: { status: 'pending_validation' } });
    const cf = createCloudflare(env, f);
    const out = await cf.addDomain('www.example.com');
    expect(f.calls[0].url).toBe('https://api.cloudflare.com/client/v4/zones/zone1/custom_hostnames');
    expect(JSON.parse(f.calls[0].opts.body).hostname).toBe('www.example.com');
    expect(out.id).toBe('cf:abc');
    expect(out.records).toEqual([{ type: 'CNAME', host: 'www', value: 'customers.site-snap.app', current: null, status: 'PENDING', purpose: 'routing' }]);
  });

  test('domainStatus reports live when both are active', async () => {
    const f = mockFetch({ id: 'abc', status: 'active', ssl: { status: 'active' } });
    const cf = createCloudflare(env, f);
    const out = await cf.domainStatus('cf:abc', 'www.example.com');
    expect(f.calls[0].url).toContain('/custom_hostnames/abc');
    expect(out.certificateStatus).toBe('ISSUED');
    expect(out.records[0].status).toBe('VALID');
  });

  test('errors from Cloudflare become readable messages', async () => {
    const cf = createCloudflare(env, mockFetch(null, false));
    await expect(cf.addDomain('www.example.com')).rejects.toThrow('Duplicate custom hostname');
  });

  test('is not ready without all three settings', () => {
    expect(createCloudflare({ CLOUDFLARE_API_TOKEN: 'tok' }).ready).toBe(false);
    expect(createCloudflare(env).ready).toBe(true);
  });
});
