import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { Category, Fingerprint, Pattern, PatternInput } from '../types.js';

/**
 * Optional external fingerprint database support.
 *
 * ## Why this is an importer and not a bundled file
 *
 * The most complete open fingerprint dataset available today is the community-maintained
 * Wappalyzer technologies set (enthec/webappanalyzer), which is licensed **GPL-3.0**.
 * Opentechalyzer is MIT licensed. Vendoring GPL-3.0 data into this repository would force
 * the entire distributed work to become GPL-3.0, which would stop people embedding it in
 * their own products, exactly the freedom this project exists to provide.
 *
 * So the dataset is never redistributed here. Instead this module can fetch it, on the
 * user's own machine, at the user's explicit request, into their own cache directory. The
 * code that does the fetching is MIT; the data it downloads stays under its own licence and
 * never enters this repository or the npm tarball.
 *
 * Run `opentechalyzer db import` to opt in. Everything works without it; importing simply
 * widens long-tail coverage.
 */

const DEFAULT_SOURCE = 'https://raw.githubusercontent.com/enthec/webappanalyzer/main/src';

export const EXTERNAL_DB_LICENSE_NOTICE = [
  'The external technology dataset (enthec/webappanalyzer) is licensed GPL-3.0.',
  'It is downloaded to your machine and is NOT redistributed as part of Opentechalyzer (MIT).',
  'If you redistribute a product that bundles this dataset, GPL-3.0 obligations apply to you.',
  'Source: https://github.com/enthec/webappanalyzer',
].join('\n');

export function externalDbPath(): string {
  const override = process.env['OPENTECHALYZER_DB_PATH'];
  if (override) return override;
  const base =
    process.env['XDG_CACHE_HOME'] ?? join(homedir(), '.cache');
  return join(base, 'opentechalyzer', 'external-db.json');
}

/**
 * Wappalyzer-format category IDs mapped onto our category union.
 *
 * Unmapped IDs fall through to 'misc' rather than being dropped, so an imported technology
 * is always reported even when we cannot classify it precisely.
 */
const CATEGORY_MAP: Record<number, Category> = {
  1: 'cms',
  4: 'documentation',
  6: 'ecommerce',
  10: 'analytics',
  11: 'cms',
  12: 'js-framework',
  14: 'video',
  16: 'captcha',
  17: 'font',
  18: 'backend-framework',
  19: 'misc',
  22: 'web-server',
  23: 'cdn',
  24: 'js-library',
  25: 'js-library',
  26: 'ui-framework',
  27: 'language',
  29: 'search',
  31: 'cdn',
  32: 'marketing-automation',
  34: 'database',
  35: 'maps',
  36: 'advertising',
  38: 'media',
  41: 'payment',
  42: 'tag-manager',
  44: 'devops',
  47: 'devops',
  51: 'cms',
  52: 'chat',
  53: 'crm',
  57: 'static-site-generator',
  59: 'js-library',
  60: 'devops',
  62: 'web-server',
  63: 'web-server',
  64: 'ui-framework',
  65: 'cookie-consent',
  66: 'accessibility',
  67: 'auth',
  69: 'ecommerce-app',
  70: 'personalisation',
  71: 'reviews',
  72: 'ab-testing',
  73: 'email',
  74: 'advertising',
  75: 'apm',
  80: 'shipping',
  81: 'loyalty',
  83: 'apm',
  84: 'analytics',
  89: 'payment',
  92: 'security',
  93: 'feature-flags',
  95: 'translation',
  96: 'video',
  97: 'support',
  99: 'baas',
};

interface WappalyzerTech {
  cats?: number[];
  website?: string;
  description?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  meta?: Record<string, string | string[]>;
  html?: string | string[];
  text?: string | string[];
  scripts?: string | string[];
  scriptSrc?: string | string[];
  js?: Record<string, string>;
  dom?: string | string[] | Record<string, unknown>;
  url?: string | string[];
  xhr?: string | string[];
  dns?: Record<string, string | string[]>;
  robots?: string | string[];
  implies?: string | string[];
  requires?: string | string[];
  excludes?: string | string[];
}

function arr(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Translate the Wappalyzer pattern dialect into our Pattern shape.
 *
 * Their format appends metadata to the regex with backslash-semicolon, for example
 * `Foo/([\d.]+)\;version:\1\;confidence:50`. We split those tags off, convert `\1` version
 * references into our `$1` template, and normalise confidence from 0-100 to 0-1.
 */
function convertPattern(raw: string): Pattern {
  const parts = raw.split('\\;');
  const re = parts[0] ?? '';
  const out: Pattern = { re };
  for (const tag of parts.slice(1)) {
    const [key, ...rest] = tag.split(':');
    const value = rest.join(':');
    if (key === 'version' && value) {
      out.version = value.replace(/\\(\d)/g, '$$$1');
    } else if (key === 'confidence' && value) {
      const n = Number(value);
      if (Number.isFinite(n)) out.confidence = Math.max(0.05, Math.min(0.99, n / 100));
    }
  }
  return out;
}

function convertPatternList(value: string | string[] | undefined): PatternInput[] | undefined {
  const list = arr(value).map(convertPattern).filter((p) => p.re.length > 0);
  return list.length > 0 ? list : undefined;
}

function convertPatternRecord(
  value: Record<string, string | string[]> | undefined,
): Record<string, PatternInput> | undefined {
  if (!value) return undefined;
  const out: Record<string, PatternInput> = {};
  for (const [key, raw] of Object.entries(value)) {
    const first = Array.isArray(raw) ? raw[0] : raw;
    out[key] = convertPattern(first ?? '');
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Extract CSS selectors from the several shapes Wappalyzer's `dom` field takes. */
function convertDom(dom: WappalyzerTech['dom']): string[] | undefined {
  if (!dom) return undefined;
  if (typeof dom === 'string') return [dom];
  if (Array.isArray(dom)) return dom.filter((d): d is string => typeof d === 'string');
  const keys = Object.keys(dom);
  return keys.length > 0 ? keys : undefined;
}

export function convertWappalyzerTech(name: string, tech: WappalyzerTech): Fingerprint {
  const categories = (tech.cats ?? [])
    .map((id) => CATEGORY_MAP[id])
    .filter((c): c is Category => Boolean(c));

  const fp: Fingerprint = {
    name,
    categories: categories.length > 0 ? [...new Set(categories)] : ['misc'],
    // Imported definitions are damped slightly: they are broader and less curated than the
    // built-ins, and a wrong confident answer is worse than a hedged one.
    weight: 0.9,
  };

  if (tech.website) fp.website = tech.website;
  if (tech.description) fp.description = tech.description;

  const headers = convertPatternRecord(tech.headers);
  if (headers) fp.headers = headers;
  const cookies = convertPatternRecord(tech.cookies);
  if (cookies) fp.cookies = cookies;
  const meta = convertPatternRecord(tech.meta);
  if (meta) fp.meta = meta;
  const js = convertPatternRecord(tech.js);
  if (js) fp.js = js;

  const html = convertPatternList(tech.html);
  const text = convertPatternList(tech.text);
  if (html || text) fp.html = [...(html ?? []), ...(text ?? [])];

  const scriptSrc = [...(convertPatternList(tech.scripts) ?? []), ...(convertPatternList(tech.scriptSrc) ?? [])];
  if (scriptSrc.length > 0) fp.scriptSrc = scriptSrc;

  const url = convertPatternList(tech.url);
  if (url) fp.url = url;
  const xhr = convertPatternList(tech.xhr);
  if (xhr) fp.requestHost = xhr;
  const robots = convertPatternList(tech.robots);
  if (robots) fp.robots = robots;

  const dom = convertDom(tech.dom);
  if (dom) fp.dom = dom;

  if (tech.dns) {
    const txt = convertPatternList(tech.dns['TXT']);
    if (txt) fp.dnsTxt = txt;
    const mx = convertPatternList(tech.dns['MX']);
    if (mx) fp.dnsMx = mx;
    const cname = convertPatternList(tech.dns['CNAME']);
    if (cname) fp.dnsCname = cname;
    const ns = convertPatternList(tech.dns['NS']);
    if (ns) fp.dnsNs = ns;
  }

  // Relationship fields carry Wappalyzer's confidence tags too, which we discard here
  // because our resolver applies its own inheritance penalty.
  const strip = (list: string[]): string[] => list.map((s) => (s.split('\\;')[0] ?? '').trim()).filter(Boolean);
  const implies = strip(arr(tech.implies));
  if (implies.length > 0) fp.implies = implies;
  const requires = strip(arr(tech.requires));
  if (requires.length > 0) fp.requires = requires;
  const excludes = strip(arr(tech.excludes));
  if (excludes.length > 0) fp.excludes = excludes;

  return fp;
}

/**
 * Download and convert an external dataset into the local cache.
 *
 * Returns the number of fingerprints imported. The caller is responsible for having shown
 * the licence notice and obtained consent.
 */
export async function importExternalDatabase(
  options: { source?: string; onProgress?: (msg: string) => void } = {},
): Promise<{ count: number; path: string }> {
  const source = options.source ?? DEFAULT_SOURCE;
  const progress = options.onProgress ?? (() => undefined);
  const shards = ['_', ...'abcdefghijklmnopqrstuvwxyz'.split('')];
  const all: Fingerprint[] = [];

  const CONCURRENCY = 6;
  for (let i = 0; i < shards.length; i += CONCURRENCY) {
    const slice = shards.slice(i, i + CONCURRENCY);
    await Promise.all(
      slice.map(async (shard) => {
        const url = `${source}/technologies/${shard}.json`;
        try {
          const res = await fetch(url, {
            headers: { 'user-agent': 'Opentechalyzer/0.1 (+https://github.com/Houseofmvps/opentechalyzer)' },
          });
          if (!res.ok) {
            progress(`skip ${shard}.json (HTTP ${res.status})`);
            return;
          }
          const json = (await res.json()) as Record<string, WappalyzerTech>;
          for (const [name, tech] of Object.entries(json)) {
            all.push(convertWappalyzerTech(name, tech));
          }
          progress(`imported ${shard}.json (${Object.keys(json).length} technologies)`);
        } catch (err) {
          progress(`skip ${shard}.json (${(err as Error).message})`);
        }
      }),
    );
  }

  if (all.length === 0) {
    throw new Error(`No technologies could be imported from ${source}. Check network access.`);
  }

  const path = externalDbPath();
  await mkdir(dirname(path), { recursive: true });
  await writeFile(
    path,
    JSON.stringify(
      {
        source,
        importedAt: new Date().toISOString(),
        license: 'GPL-3.0 (see EXTERNAL_DB_LICENSE_NOTICE)',
        count: all.length,
        fingerprints: all,
      },
      null,
      0,
    ),
    'utf8',
  );

  return { count: all.length, path };
}

/** Load a previously imported external database, or an empty array if none exists. */
export async function loadExternalDatabase(): Promise<Fingerprint[]> {
  if (process.env['OPENTECHALYZER_NO_EXTERNAL'] === '1') return [];
  try {
    const raw = await readFile(externalDbPath(), 'utf8');
    const parsed = JSON.parse(raw) as { fingerprints?: Fingerprint[] };
    return parsed.fingerprints ?? [];
  } catch {
    return [];
  }
}

/** Describe the current external database state, for `db status`. */
export async function externalDatabaseStatus(): Promise<{
  installed: boolean;
  path: string;
  count?: number;
  importedAt?: string;
  source?: string;
}> {
  const path = externalDbPath();
  try {
    const raw = await readFile(path, 'utf8');
    const parsed = JSON.parse(raw) as { count?: number; importedAt?: string; source?: string };
    return {
      installed: true,
      path,
      count: parsed.count,
      importedAt: parsed.importedAt,
      source: parsed.source,
    };
  } catch {
    return { installed: false, path };
  }
}
