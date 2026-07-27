import { describe, expect, it } from 'vitest';
import { BUILTIN_FINGERPRINTS, listCategories } from '../src/fingerprints/index.js';
import { convertWappalyzerTech } from '../src/fingerprints/external.js';
import { buildReverseQuery, defaultCrawlDate } from '../src/reverse/bigquery.js';
import type { Fingerprint, PatternInput } from '../src/types.js';

function allPatterns(fp: Fingerprint): string[] {
  const out: string[] = [];
  const push = (p: PatternInput): void => {
    out.push(typeof p === 'string' ? p : p.re);
  };
  for (const list of [
    fp.html,
    fp.scriptSrc,
    fp.scriptContent,
    fp.stylesheetSrc,
    fp.url,
    fp.robots,
    fp.requestHost,
    fp.dnsTxt,
    fp.dnsMx,
    fp.dnsCname,
    fp.dnsNs,
    fp.certSubdomain,
    fp.npmDep,
  ]) {
    for (const p of list ?? []) push(p);
  }
  for (const record of [fp.headers, fp.cookies, fp.meta, fp.js]) {
    for (const p of Object.values(record ?? {})) push(p);
  }
  for (const probe of fp.probe ?? []) {
    if (probe.body) push(probe.body);
  }
  return out;
}

describe('built-in fingerprint database', () => {
  it('is not trivially small', () => {
    expect(BUILTIN_FINGERPRINTS.length).toBeGreaterThan(250);
  });

  it('has unique technology names', () => {
    const seen = new Map<string, number>();
    for (const fp of BUILTIN_FINGERPRINTS) {
      seen.set(fp.name, (seen.get(fp.name) ?? 0) + 1);
    }
    const duplicates = [...seen.entries()].filter(([, n]) => n > 1).map(([name]) => name);
    expect(duplicates).toEqual([]);
  });

  it('gives every fingerprint at least one category', () => {
    const bad = BUILTIN_FINGERPRINTS.filter((fp) => fp.categories.length === 0).map((fp) => fp.name);
    expect(bad).toEqual([]);
  });

  it('gives every fingerprint at least one signal', () => {
    // A fingerprint with no patterns can only ever be reached through `implies`, which is
    // legitimate for abstract entries like languages, so those are allowed through by name.
    const impliedOnly = new Set([
      'MySQL',
      'PostgreSQL',
      'SQLite',
      'Liquid',
      'Lua',
      'Shopify Plus',
    ]);
    const bad = BUILTIN_FINGERPRINTS.filter(
      (fp) => allPatterns(fp).length === 0 && !fp.dom?.length && !fp.faviconMd5?.length && !fp.probe?.length,
    )
      .map((fp) => fp.name)
      .filter((name) => !impliedOnly.has(name));
    expect(bad).toEqual([]);
  });

  it('contains only valid regular expressions', () => {
    const broken: string[] = [];
    for (const fp of BUILTIN_FINGERPRINTS) {
      for (const pattern of allPatterns(fp)) {
        if (pattern === '') continue;
        try {
          new RegExp(pattern, 'i');
        } catch {
          broken.push(`${fp.name}: ${pattern}`);
        }
      }
    }
    expect(broken).toEqual([]);
  });

  it('only references technologies that exist in implies/requires/excludes', () => {
    const names = new Set(BUILTIN_FINGERPRINTS.map((fp) => fp.name));
    const dangling: string[] = [];
    for (const fp of BUILTIN_FINGERPRINTS) {
      for (const key of ['implies', 'requires', 'excludes'] as const) {
        for (const ref of fp[key] ?? []) {
          if (!names.has(ref)) dangling.push(`${fp.name}.${key} -> ${ref}`);
        }
      }
    }
    expect(dangling).toEqual([]);
  });

  it('has no self-referential relationships', () => {
    const bad: string[] = [];
    for (const fp of BUILTIN_FINGERPRINTS) {
      for (const key of ['implies', 'requires', 'excludes'] as const) {
        if ((fp[key] ?? []).includes(fp.name)) bad.push(`${fp.name}.${key}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it('uses only declared categories', () => {
    const declared = new Set(listCategories());
    for (const fp of BUILTIN_FINGERPRINTS) {
      for (const c of fp.categories) expect(declared.has(c)).toBe(true);
    }
  });

  it('gives every version template a matching capture group', () => {
    const bad: string[] = [];
    for (const fp of BUILTIN_FINGERPRINTS) {
      const check = (p: PatternInput): void => {
        if (typeof p === 'string' || !p.version) return;
        const groups = (p.re.match(/\((?!\?[:=!])/g) ?? []).length;
        for (const m of p.version.matchAll(/\$(\d+)/g)) {
          if (Number(m[1]) > groups) bad.push(`${fp.name}: "${p.re}" has no group ${m[1]}`);
        }
      };
      for (const list of [fp.html, fp.scriptSrc, fp.stylesheetSrc, fp.url, fp.npmDep]) {
        for (const p of list ?? []) check(p);
      }
      for (const record of [fp.headers, fp.cookies, fp.meta, fp.js]) {
        for (const p of Object.values(record ?? {})) check(p);
      }
    }
    expect(bad).toEqual([]);
  });
});

describe('Wappalyzer format adapter', () => {
  it('converts the version tag dialect into our template form', () => {
    const fp = convertWappalyzerTech('Foo', {
      cats: [1],
      headers: { 'X-Powered-By': 'Foo/([\\d.]+)\\;version:\\1' },
    });
    const pattern = fp.headers?.['X-Powered-By'];
    expect(typeof pattern).toBe('object');
    expect((pattern as { re: string }).re).toBe('Foo/([\\d.]+)');
    expect((pattern as { version?: string }).version).toBe('$1');
  });

  it('normalises the confidence tag from 0-100 to 0-1', () => {
    const fp = convertWappalyzerTech('Bar', { cats: [1], html: ['bar\\;confidence:50'] });
    const pattern = fp.html?.[0] as { confidence?: number };
    expect(pattern.confidence).toBeCloseTo(0.5, 2);
  });

  it('maps known category ids and falls back to misc', () => {
    expect(convertWappalyzerTech('A', { cats: [1] }).categories).toContain('cms');
    expect(convertWappalyzerTech('B', { cats: [99999] }).categories).toEqual(['misc']);
  });

  it('accepts dom as string, array or object', () => {
    expect(convertWappalyzerTech('A', { dom: '.x' }).dom).toEqual(['.x']);
    expect(convertWappalyzerTech('B', { dom: ['.y'] }).dom).toEqual(['.y']);
    expect(convertWappalyzerTech('C', { dom: { '.z': {} } }).dom).toEqual(['.z']);
  });

  it('strips confidence tags off relationship names', () => {
    const fp = convertWappalyzerTech('A', { implies: ['PHP\\;confidence:80'] });
    expect(fp.implies).toEqual(['PHP']);
  });

  it('damps imported fingerprints below built-in weight', () => {
    expect(convertWappalyzerTech('A', {}).weight).toBeLessThan(1);
  });
});

describe('reverse lookup query builder', () => {
  it('requires at least one filter so a full-table scan is impossible by accident', () => {
    expect(() => buildReverseQuery({})).toThrow(/at least one/i);
  });

  it('always constrains the partition and cluster columns', () => {
    const { sql } = buildReverseQuery({ tech: ['Shopify'] });
    // date partitions the table and client/is_root_page cluster it. Without all three the
    // query scans the whole month across both clients and every inner page.
    expect(sql).toMatch(/WHERE date = '\d{4}-\d{2}-01'/);
    expect(sql).toContain("client = 'mobile'");
    expect(sql).toContain('is_root_page = TRUE');
  });

  it('ANDs multiple technologies via HAVING rather than WHERE', () => {
    // A WHERE over the unnested array can only test one element at a time, so "Shopify AND
    // Klaviyo" written that way silently returns nothing.
    const { sql } = buildReverseQuery({ tech: ['Shopify', 'Klaviyo'] });
    expect(sql).toContain("LOGICAL_OR(t.technology = 'Shopify')");
    expect(sql).toContain("LOGICAL_OR(t.technology = 'Klaviyo')");
    expect(sql).toContain('GROUP BY page');
  });

  it('negates excluded technologies', () => {
    const { sql } = buildReverseQuery({ tech: ['Shopify'], notTech: ['WooCommerce'] });
    expect(sql).toContain("LOGICAL_OR(t.technology = 'WooCommerce') = FALSE");
  });

  it('escapes quotes so a technology name cannot break out of the literal', () => {
    const { sql } = buildReverseQuery({ tech: ["O'Reilly"] });
    expect(sql).toContain("\\'Reilly");
  });

  it('backticks rank, which collides with the RANK window function', () => {
    const { sql } = buildReverseQuery({ tech: ['Shopify'], rank: 1000 });
    expect(sql).toContain('`rank` <= 1000');
    expect(sql).not.toMatch(/[^`]\brank <= /);
  });

  it('caps the limit so a single call cannot pull unbounded rows', () => {
    expect(buildReverseQuery({ tech: ['X'], limit: 999_999 }).sql).toContain('LIMIT 10000');
    expect(buildReverseQuery({ tech: ['X'], limit: 0 }).sql).toContain('LIMIT 1');
  });

  it('defaults to a crawl month that already exists', () => {
    // HTTP Archive publishes monthly and lags, so "now" is never a valid partition.
    const date = defaultCrawlDate(new Date('2026-07-27T00:00:00Z'));
    expect(date).toBe('2026-05-01');
  });
});
