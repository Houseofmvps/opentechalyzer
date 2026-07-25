import { describe, expect, it } from 'vitest';
import { combineConfidence, detect } from '../src/detect/engine.js';
import type { Evidence, Evidence_Bundle, Fingerprint } from '../src/types.js';

function bundle(overrides: Partial<Evidence_Bundle> = {}): Evidence_Bundle {
  return {
    url: 'https://example.com',
    finalUrl: 'https://example.com',
    status: 200,
    headers: {},
    setCookies: [],
    html: '',
    scriptSrcs: [],
    scriptContents: [],
    stylesheetSrcs: [],
    cssContents: [],
    metas: {},
    requestHosts: [],
    jsGlobals: {},
    domSelectors: new Set(),
    dns: { txt: [], mx: [], cname: [], ns: [], a: [] },
    certSubdomains: [],
    npmDeps: [],
    probes: {},
    warnings: [],
    timings: {},
    ...overrides,
  };
}

const ev = (reliability: number, source: Evidence['source'] = 'html'): Evidence => ({
  source,
  subject: 'test',
  pattern: 'test',
  match: 'test',
  reliability,
});

describe('combineConfidence', () => {
  it('returns 0 with no evidence', () => {
    expect(combineConfidence([])).toBe(0);
  });

  it('returns the single reliability for one signal', () => {
    expect(combineConfidence([ev(0.9, 'cookie')])).toBeCloseTo(90, 0);
  });

  it('combines independent sources probabilistically rather than by summing', () => {
    // Two independent 0.5 signals should yield 75%, not 100%.
    const combined = combineConfidence([ev(0.5, 'html'), ev(0.5, 'header')]);
    expect(combined).toBeCloseTo(75, 0);
  });

  it('never reaches or exceeds 100', () => {
    const many = Array.from({ length: 40 }, () => ev(0.95, 'cookie'));
    expect(combineConfidence(many)).toBeLessThan(100);
  });

  it('damps repeated matches from the same source', () => {
    // Three HTML regexes are weaker than three signals from three distinct sources,
    // because they are not independent observations.
    const sameSource = combineConfidence([ev(0.6, 'html'), ev(0.6, 'html'), ev(0.6, 'html')]);
    const diffSource = combineConfidence([ev(0.6, 'html'), ev(0.6, 'header'), ev(0.6, 'cookie')]);
    expect(diffSource).toBeGreaterThan(sameSource);
  });

  it('makes several weak signals beat one moderate signal', () => {
    const threeWeak = combineConfidence([ev(0.55, 'html'), ev(0.55, 'meta'), ev(0.55, 'url')]);
    const oneModerate = combineConfidence([ev(0.82, 'dom')]);
    expect(threeWeak).toBeGreaterThan(oneModerate);
  });
});

describe('detect', () => {
  const db: Fingerprint[] = [
    { name: 'Widget', categories: ['misc'], headers: { 'x-widget': '' } },
    {
      name: 'WidgetPlugin',
      categories: ['misc'],
      html: ['widget-plugin'],
      requires: ['Widget'],
    },
    {
      name: 'MetaFramework',
      categories: ['js-framework'],
      html: ['__META_DATA__'],
      implies: ['BaseLib'],
    },
    { name: 'BaseLib', categories: ['js-library'], html: ['base-lib-marker'] },
    { name: 'ServerA', categories: ['web-server'], headers: { server: 'a-server' }, excludes: ['ServerB'] },
    { name: 'ServerB', categories: ['web-server'], html: ['maybe-b'] },
  ];

  it('detects from a header', () => {
    const found = detect(db, bundle({ headers: { 'x-widget': '1' } }), 0);
    expect(found.map((d) => d.name)).toContain('Widget');
  });

  it('extracts versions from capture groups', () => {
    const found = detect(
      [{ name: 'Thing', categories: ['misc'], headers: { server: { re: 'thing/([\\d.]+)', version: '$1' } } }],
      bundle({ headers: { server: 'thing/2.5.1' } }),
      0,
    );
    expect(found[0]?.version).toBe('2.5.1');
  });

  it('captures account ids separately from versions', () => {
    const found = detect(
      [
        {
          name: 'Tagger',
          categories: ['tag-manager'],
          html: [{ re: '\\b(GTM-[A-Z0-9]{6,10})\\b', id: '$1', caseSensitive: true }],
        },
      ],
      bundle({ html: '<script>GTM-ABC1234</script>' }),
      0,
    );
    expect(found[0]?.accountIds).toEqual(['GTM-ABC1234']);
    expect(found[0]?.version).toBeUndefined();
  });

  it('honours caseSensitive so identifier patterns do not match lowercase text', () => {
    const db2: Fingerprint[] = [
      {
        name: 'GA4ish',
        categories: ['analytics'],
        html: [{ re: '\\b(G-[A-Z0-9]{9,12})\\b', id: '$1', caseSensitive: true }],
      },
    ];
    // "g-recaptcha" must not be mistaken for a GA4 measurement ID.
    expect(detect(db2, bundle({ html: 'class="g-recaptcha-response"' }), 0)).toHaveLength(0);
    expect(detect(db2, bundle({ html: 'id=G-MFK23BV2BG' }), 0)).toHaveLength(1);
  });

  it('matches case-insensitively by default', () => {
    const found = detect(
      [{ name: 'Loose', categories: ['misc'], html: ['WoRdPrEsS'] }],
      bundle({ html: 'powered by wordpress' }),
      0,
    );
    expect(found).toHaveLength(1);
  });

  it('drops a detection whose `requires` is unsatisfied', () => {
    const found = detect(db, bundle({ html: 'widget-plugin here' }), 0);
    expect(found.map((d) => d.name)).not.toContain('WidgetPlugin');
  });

  it('keeps a detection whose `requires` is satisfied', () => {
    const found = detect(db, bundle({ headers: { 'x-widget': '1' }, html: 'widget-plugin' }), 0);
    expect(found.map((d) => d.name)).toContain('WidgetPlugin');
  });

  it('adds implied technologies and marks them inferred', () => {
    const found = detect(db, bundle({ html: 'window.__META_DATA__ = {}' }), 0);
    const base = found.find((d) => d.name === 'BaseLib');
    expect(base).toBeDefined();
    expect(base?.inferred).toBe(true);
    expect(base?.impliedBy).toBe('MetaFramework');
  });

  it('prefers an observed detection over an inferred one', () => {
    const found = detect(db, bundle({ html: '__META_DATA__ and base-lib-marker' }), 0);
    const base = found.find((d) => d.name === 'BaseLib');
    expect(base?.inferred).toBe(false);
  });

  it('applies `excludes` so mutually exclusive technologies do not both appear', () => {
    const found = detect(db, bundle({ headers: { server: 'a-server' }, html: 'maybe-b' }), 0);
    const names = found.map((d) => d.name);
    expect(names).toContain('ServerA');
    expect(names).not.toContain('ServerB');
  });

  it('respects the minimum confidence threshold', () => {
    const weak: Fingerprint[] = [
      { name: 'Weak', categories: ['misc'], html: [{ re: 'weak', confidence: 0.1 }] },
    ];
    expect(detect(weak, bundle({ html: 'weak' }), 25)).toHaveLength(0);
    expect(detect(weak, bundle({ html: 'weak' }), 5)).toHaveLength(1);
  });

  it('survives a malformed regex in the database', () => {
    const broken: Fingerprint[] = [{ name: 'Broken', categories: ['misc'], html: ['([unclosed'] }];
    expect(() => detect(broken, bundle({ html: 'anything' }), 0)).not.toThrow();
  });

  it('matches cookies by name only when the value pattern is empty', () => {
    const found = detect(
      [{ name: 'Sess', categories: ['misc'], cookies: { '^mysess$': '' } }],
      bundle({ setCookies: ['mysess=abc123; Path=/; HttpOnly'] }),
      0,
    );
    expect(found).toHaveLength(1);
  });

  it('sorts results by descending confidence', () => {
    const found = detect(db, bundle({ headers: { 'x-widget': '1', server: 'a-server' } }), 0);
    for (let i = 1; i < found.length; i++) {
      expect(found[i - 1]!.confidence).toBeGreaterThanOrEqual(found[i]!.confidence);
    }
  });
});
