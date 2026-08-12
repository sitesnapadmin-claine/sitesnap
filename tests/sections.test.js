// Tests for the FAQ + gallery sections and the per-section photo/overlay
// backgrounds. Two things are worth locking down here:
//
//   1. Half-filled rows must never publish. A question with no answer, or a
//      gallery slot with no upload, would ship as an empty accordion row or a
//      broken image on a real customer's site.
//   2. Text on a photo background must stay readable. The text colour is
//      derived from the overlay tint rather than hardcoded, so these tests pin
//      that decision — it's the difference between a legible hero and white
//      text on a white tint.

process.env.SQLITE_PATH = 'test-sections.db';
const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);
fs.rmSync(dbFile, { force: true }); // start clean even if a previous run crashed

const {
  initDb, buildWebsite, bgConfig, bgIsDark, bgTextVars, bgStyle, hexToRgb, rgba,
} = require('../server.js');

beforeAll(async () => {
  await initDb();
});

afterAll(() => {
  fs.rmSync(dbFile, { force: true });
});

// Minimal viable site; individual tests layer on what they care about.
function site(extra = {}) {
  return Object.assign({
    bizName: 'Aurora Studio',
    tagline: 'Portraits that feel like you',
    industry: 'Photography',
    colorPrimary: '#6C47FF',
    colorAccent: '#FF6B6B',
    designStyle: 'bold-modern',
    audience: 'families who hate posing',
    sections: { about: true, services: true, cta: true },
  }, extra);
}

const render = (s) => buildWebsite(s, 'test-uuid', 'https://site-snap.app');

/* ── FAQ ─────────────────────────────────────────────────────────────────── */
describe('FAQ section', () => {
  const withFaqs = site({
    sections: { about: true, services: true, cta: true, faq: true },
    faqEyebrow: 'Good to know',
    faqTitle: 'Common questions',
    faqSub: 'Before you book.',
    faqs: [
      { q: 'How long is a session?', a: 'About 90 minutes.' },
      { q: 'Do you travel?', a: 'Yes, statewide.' },
    ],
  });

  test('renders the section with its own eyebrow, heading and subheadline', async () => {
    const html = await render(withFaqs);
    expect(html).toContain('id="faq"');
    expect(html).toContain('Good to know');
    expect(html).toContain('Common questions');
    expect(html).toContain('Before you book.');
  });

  test('uses native details/summary so it works without JavaScript', async () => {
    const html = await render(withFaqs);
    expect(html).toContain('<details class="faq-item"');
    expect(html).toContain('<summary>');
  });

  test('opens only the first question by default', async () => {
    const html = await render(withFaqs);
    const opens = html.match(/<details class="faq-item" open>/g) || [];
    expect(opens).toHaveLength(1);
  });

  test('drops a question with no answer, and an answer with no question', async () => {
    const html = await render(site({
      sections: { faq: true, cta: true },
      faqs: [
        { q: 'Real question', a: 'Real answer' },
        { q: 'Question with no answer', a: '   ' },
        { q: '', a: 'Answer with no question' },
      ],
    }));
    expect(html).toContain('Real question');
    expect(html).not.toContain('Question with no answer');
    expect(html).not.toContain('Answer with no question');
  });

  test('stays hidden when the toggle is on but nothing is filled in', async () => {
    const html = await render(site({
      sections: { faq: true, cta: true },
      faqs: [{ q: 'Orphan', a: '' }],
    }));
    expect(html).not.toContain('id="faq"');
  });

  test('stays hidden when the toggle is off even with content present', async () => {
    const html = await render(site({
      sections: { faq: false, cta: true },
      faqs: [{ q: 'Q', a: 'A' }],
    }));
    expect(html).not.toContain('id="faq"');
  });

  test('escapes HTML in questions and answers', async () => {
    const html = await render(site({
      sections: { faq: true, cta: true },
      faqs: [{ q: '<script>alert(1)</script>', a: 'Fine & dandy' }],
    }));
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('Fine &amp; dandy');
  });
});

/* ── Gallery ─────────────────────────────────────────────────────────────── */
describe('Gallery section', () => {
  const withGallery = site({
    sections: { about: true, cta: true, gallery: true },
    galleryEyebrow: 'Portfolio',
    galleryTitle: 'Recent work',
    gallerySub: 'A few favourites.',
    gallery: [
      { url: 'https://cdn.test/1.jpg', caption: 'Golden hour' },
      { url: 'https://cdn.test/2.jpg', caption: '' },
    ],
  });

  test('renders the section with its own eyebrow, heading and subheadline', async () => {
    const html = await render(withGallery);
    expect(html).toContain('id="gallery"');
    expect(html).toContain('Portfolio');
    expect(html).toContain('Recent work');
    expect(html).toContain('A few favourites.');
  });

  test('renders every uploaded image, lazily loaded', async () => {
    const html = await render(withGallery);
    expect(html).toContain('https://cdn.test/1.jpg');
    expect(html).toContain('https://cdn.test/2.jpg');
    expect(html).toContain('loading="lazy"');
  });

  test('shows a caption when given, and omits the element when not', async () => {
    const html = await render(withGallery);
    expect(html).toContain('Golden hour');
    const caps = html.match(/class="gallery-cap"/g) || [];
    expect(caps).toHaveLength(1); // only the first image has a caption
  });

  test('builds one lightbox target per image', async () => {
    const html = await render(withGallery);
    expect(html).toContain('id="lb-0"');
    expect(html).toContain('id="lb-1"');
    expect(html).not.toContain('id="lb-2"');
  });

  test('falls back to a descriptive alt when there is no caption', async () => {
    const html = await render(withGallery);
    expect(html).toContain('Aurora Studio gallery image 2');
  });

  test('skips slots that were added but never uploaded', async () => {
    const html = await render(site({
      sections: { cta: true, gallery: true },
      gallery: [
        { url: 'https://cdn.test/real.jpg', caption: 'Kept' },
        { url: '', caption: 'Caption with no image' },
      ],
    }));
    expect(html).toContain('https://cdn.test/real.jpg');
    expect(html).not.toContain('Caption with no image');
  });

  test('stays hidden when the toggle is on but no images were uploaded', async () => {
    const html = await render(site({
      sections: { cta: true, gallery: true },
      gallery: [{ url: '', caption: 'x' }],
    }));
    expect(html).not.toContain('id="gallery"');
  });
});

/* ── Navigation ──────────────────────────────────────────────────────────── */
describe('Navigation reflects which sections exist', () => {
  test('adds Gallery and FAQ links when those sections render', async () => {
    const html = await render(site({
      sections: { about: true, services: true, cta: true, gallery: true, faq: true },
      gallery: [{ url: 'https://cdn.test/1.jpg' }],
      faqs: [{ q: 'Q', a: 'A' }],
    }));
    expect(html).toContain('href="#gallery"');
    expect(html).toContain('href="#faq"');
  });

  test('omits those links when the sections are absent', async () => {
    const html = await render(site());
    expect(html).not.toContain('href="#gallery"');
    expect(html).not.toContain('href="#faq"');
  });
});

/* ── Background config parsing ───────────────────────────────────────────── */
describe('bgConfig — when a photo background applies', () => {
  test('solid mode is ignored even if an image was uploaded earlier', () => {
    expect(bgConfig({ sectionBg: { hero: { mode: 'solid', url: 'a.jpg' } } }, 'hero')).toBeNull();
  });

  test('image mode with no URL falls back to the theme colour', () => {
    expect(bgConfig({ sectionBg: { hero: { mode: 'image', url: '   ' } } }, 'hero')).toBeNull();
  });

  test('a section with no config at all is null', () => {
    expect(bgConfig({}, 'hero')).toBeNull();
    expect(bgConfig({ sectionBg: {} }, 'cta')).toBeNull();
  });

  test('clamps tint strength into a usable band', () => {
    const at = (strength) => bgConfig(
      { sectionBg: { hero: { mode: 'image', url: 'a.jpg', strength } } }, 'hero'
    ).strength;
    expect(at(0)).toBe(0.2);     // never fully transparent
    expect(at(400)).toBe(0.95);  // never fully opaque
    expect(at(70)).toBeCloseTo(0.7);
  });

  test('defaults to a middling strength when unset', () => {
    expect(bgConfig({ sectionBg: { hero: { mode: 'image', url: 'a.jpg' } } }, 'hero').strength)
      .toBe(0.65);
  });
});

/* ── Readability ─────────────────────────────────────────────────────────── */
describe('Overlay contrast keeps text readable', () => {
  test('a dark tint gets light text', () => {
    expect(bgTextVars({ color: '#111319', strength: 0.8 }).heading).toBe('#FFFFFF');
  });

  test('a light tint gets dark text', () => {
    expect(bgTextVars({ color: '#FFFFFF', strength: 0.85 }).heading).toBe('#141414');
  });

  test('a weak tint also gets a scrim shadow, because the photo dominates', () => {
    // Below the comfortable threshold we cannot know what is behind any given
    // line of text, so colour alone is not enough.
    expect(bgTextVars({ color: '#111319', strength: 0.3 }).shadow).not.toBe('none');
    expect(bgTextVars({ color: '#FFFFFF', strength: 0.3 }).shadow).not.toBe('none');
  });

  test('a strong tint needs no shadow', () => {
    expect(bgTextVars({ color: '#111319', strength: 0.8 }).shadow).toBe('none');
  });

  test('the shadow opposes the text colour so it actually adds contrast', () => {
    expect(bgTextVars({ color: '#111319', strength: 0.3 }).shadow).toContain('rgba(0,0,0');
    expect(bgTextVars({ color: '#FFFFFF', strength: 0.3 }).shadow).toContain('rgba(255,255,255');
  });

  test('brand purple at full strength reads as dark', () => {
    expect(bgIsDark({ color: '#6C47FF', strength: 0.9 })).toBe(true);
  });
});

/* ── Background CSS output ───────────────────────────────────────────────── */
describe('bgStyle — generated CSS', () => {
  const cfg = { color: '#111319', strength: 0.7, url: 'https://cdn.test/a.jpg' };

  test('layers a tint gradient over the photo and covers the section', () => {
    const css = bgStyle(cfg);
    expect(css).toContain('linear-gradient(');
    expect(css).toContain('https://cdn.test/a.jpg');
    expect(css).toContain('background-size:cover');
  });

  test('the hero scrim fades directionally so the copy side stays opaque', () => {
    expect(bgStyle(cfg, 'left')).toContain('100deg');
    expect(bgStyle(cfg)).not.toContain('100deg');
  });

  test('encodes spaces and escapes quotes in image URLs', () => {
    const css = bgStyle({ ...cfg, url: "my photo'.jpg" });
    expect(css).toContain('my%20photo');
    expect(css).not.toContain("photo'.jpg"); // would break out of url('…')
  });

  test('hexToRgb and rgba handle valid, prefixed and junk input', () => {
    expect(hexToRgb('#6C47FF')).toEqual({ r: 108, g: 71, b: 255 });
    expect(hexToRgb('111319')).toEqual({ r: 17, g: 19, b: 25 });
    expect(hexToRgb('not-a-colour')).toEqual({ r: 0, g: 0, b: 0 });
    expect(rgba('#000000', 5)).toBe('rgba(0,0,0,1)'); // alpha clamped
  });
});

/* ── Applied to the rendered page ────────────────────────────────────────── */
describe('Backgrounds applied to the generated site', () => {
  test('a hero photo replaces the inset image and forces readable text', async () => {
    const html = await render(site({
      sectionBg: { hero: { mode: 'image', url: 'https://cdn.test/hero.jpg', overlay: '#111319', strength: 75 } },
    }));
    expect(html).toContain('https://cdn.test/hero.jpg');
    expect(html).toContain('100deg');                       // directional scrim
    expect(html).toContain('.hero h1{color:#FFFFFF');        // light text on dark tint
    expect(html).toContain('.hero .hero-img-wrap{display:none;}'); // no duplicate photo
  });

  test('a light tint on the FAQ section flips its text dark', async () => {
    const html = await render(site({
      sections: { cta: true, faq: true },
      faqs: [{ q: 'Q', a: 'A' }],
      sectionBg: { faq: { mode: 'image', url: 'https://cdn.test/faq.jpg', overlay: '#FFFFFF', strength: 30 } },
    }));
    expect(html).toContain('.faq-section .section-title{color:#141414');
  });

  test('sections left on solid colour get no background image', async () => {
    const html = await render(site({
      sectionBg: { cta: { mode: 'solid' } },
    }));
    expect(html).not.toMatch(/\.cta-section\{background-image/);
  });
});

/* ── Backwards compatibility ─────────────────────────────────────────────── */
describe('Sites saved before these features existed', () => {
  test('render unchanged, with no new sections and no photo backgrounds', async () => {
    const html = await render(site()); // no gallery / faqs / sectionBg keys at all
    expect(html).not.toContain('id="gallery"');
    expect(html).not.toContain('id="faq"');
    expect(html).not.toContain('class="lb"');
    expect(html).not.toMatch(/\.hero\{background-image/);
    // and the long-standing sections still appear
    expect(html).toContain('id="about"');
    expect(html).toContain('id="services"');
    expect(html).toContain('id="contact"');
    expect(html).toContain('hero-img-wrap');
  });

  test('never leaves an unresolved template placeholder in the output', async () => {
    const html = await render(site({
      sections: { about: true, services: true, cta: true, gallery: true, faq: true },
      gallery: [{ url: 'https://cdn.test/1.jpg', caption: 'C' }],
      faqs: [{ q: 'Q', a: 'A' }],
      sectionBg: { hero: { mode: 'image', url: 'https://cdn.test/h.jpg', overlay: '#111319', strength: 60 } },
    }));
    expect(html).not.toContain('${');
    expect(html).not.toContain('undefined');
  });
});
