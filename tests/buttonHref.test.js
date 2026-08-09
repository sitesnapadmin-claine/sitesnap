// Pure unit tests for buttonHref() — the function that turns a configured
// CTA button (email / phone / URL / section) into the href written onto the
// generated site. This is exactly the logic behind the "mailto: doesn't
// work" bug fixed earlier, so it's the highest-value thing to lock down.

process.env.SQLITE_PATH = 'test-buttonhref.db';
const path = require('path');
const fs = require('fs');
const dbFile = path.join(__dirname, '..', process.env.SQLITE_PATH);

const { buttonHref } = require('../server.js');

afterAll(() => {
    fs.rmSync(dbFile, { force: true });
});

describe('buttonHref — email buttons', () => {
    test('plain email address becomes a mailto: link', () => {
          expect(buttonHref({ type: 'email', value: 'hello@example.com' }))
            .toBe('mailto:hello@example.com');
    });

           test('strips an accidental "mailto:" prefix instead of doubling it', () => {
                 expect(buttonHref({ type: 'email', value: 'mailto:hello@example.com' }))
                   .toBe('mailto:hello@example.com');
           });

           test('strips prefix case-insensitively and trims whitespace', () => {
                 expect(buttonHref({ type: 'email', value: '  MAILTO:hello@example.com  ' }))
                   .toBe('mailto:hello@example.com');
           });

           test('rejects an invalid email', () => {
                 expect(buttonHref({ type: 'email', value: 'not-an-email' })).toBeNull();
           });
});

describe('buttonHref — phone buttons', () => {
    test('phone number becomes a tel: link with punctuation stripped', () => {
          expect(buttonHref({ type: 'phone', value: '(555) 123-4567' }))
            .toBe('tel:5551234567');
    });

           test('keeps a leading + for international numbers', () => {
                 expect(buttonHref({ type: 'phone', value: '+1 555 123 4567' }))
                   .toBe('tel:+15551234567');
           });

           test('empty phone value returns null', () => {
                 expect(buttonHref({ type: 'phone', value: '   ' })).toBeNull();
           });
});

describe('buttonHref — URL buttons', () => {
    test('bare domain gets https:// prefixed', () => {
          expect(buttonHref({ type: 'url', value: 'example.com/book' }))
            .toBe('https://example.com/book');
    });

           test('already-prefixed http(s) URL is left alone', () => {
                 expect(buttonHref({ type: 'url', value: 'http://example.com' }))
                   .toBe('http://example.com');
           });

           test('javascript: payloads are neutralised, not passed through', () => {
                 expect(buttonHref({ type: 'url', value: 'javascript:alert(1)' }))
                   .toBeNull();
           });
});

describe('buttonHref — section (scroll) and none', () => {
    test('section type returns a hash link, defaulting to #contact', () => {
          expect(buttonHref({ type: 'section', value: 'pricing' })).toBe('#pricing');
          expect(buttonHref({ type: 'section', value: '' })).toBe('#contact');
    });

           test('"none" type and missing action return null (renders a disabled button)', () => {
                 expect(buttonHref({ type: 'none', value: 'x' })).toBeNull();
                 expect(buttonHref(null)).toBeNull();
           });
});
