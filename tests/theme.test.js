// Regression test for a real bug: getTheme() only ever read colorPrimary,
// so a customer's dedicated "Button color" choice (colorButton — a separate
// swatch from Primary in Step 2) never reached the live site. The wizard's
// own preview used colorButton correctly the whole time, which is exactly
// why the mismatch went unnoticed until a customer saved and refreshed.
//
// These tests pin colorButton (falling back to colorPrimary only when unset)
// as the source of truth for every rendered button background.

process.env.SQLITE_PATH = 'test-theme.db';
const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true });

const { initDb, buildWebsite } = require('../server.js');

beforeAll(async () => {
  await initDb();
});

afterAll(() => {
  fs.rmSync(dbFile, { force: true });
});

function site(extra = {}) {
  return Object.assign({
    bizName: 'SwitchHitter',
    tagline: 'Box smarter',
    industry: 'Health & Fitness',
    designStyle: 'bold-modern',
    sections: { about: false, services: false, testimonial: false, gallery: false, faq: false, cta: true },
    cta: { heading: 'Ready to get started?' },
  }, extra);
}

const render = (s) => buildWebsite(s, 'test-uuid', 'https://site-snap.app');

describe('Button colour — dedicated swatch, not just Primary', () => {
  test('hero/services button (.btn-p) uses colorButton when set', async () => {
    const html = await render(site({ colorPrimary: '#111319', colorButton: '#E11D2E' }));
    const rule = html.match(/\.btn-p\{[^}]*\}/)[0];
    expect(rule).toContain('background:#E11D2E');
    expect(rule).not.toContain('background:#111319');
  });

  test('nav CTA button (.nav-cta) uses colorButton when set', async () => {
    const html = await render(site({ colorPrimary: '#111319', colorButton: '#E11D2E' }));
    const rule = html.match(/\.nav-cta\{[^}]*\}/)[0];
    expect(rule).toContain('background:#E11D2E');
    expect(rule).not.toContain('background:#111319');
  });

  test('falls back to colorPrimary when colorButton was never set', async () => {
    const html = await render(site({ colorPrimary: '#0057FF' }));
    const rule = html.match(/\.btn-p\{[^}]*\}/)[0];
    expect(rule).toContain('background:#0057FF');
  });

  test('falls back to the default primary when neither is set', async () => {
    const html = await render(site());
    const rule = html.match(/\.btn-p\{[^}]*\}/)[0];
    expect(rule).toContain('background:#6C47FF');
  });

  test('colorButton takes effect across every design style, not just one theme', async () => {
    for (const designStyle of ['light-airy', 'bold-modern', 'earthy', 'luxe', 'playful', 'professional']) {
      const html = await render(site({ designStyle, colorPrimary: '#000000', colorButton: '#22C55E' }));
      const rule = html.match(/\.btn-p\{[^}]*\}/)[0];
      expect(rule).toContain('background:#22C55E');
    }
  });
});
