import { decodeEntities } from '../collect/http.js';

/**
 * Content extraction for the enrichment field sets.
 *
 * Everything here is derived from page content the site publishes itself. No third-party
 * data broker is involved, which is both the point (it stays free) and the limit (a company's
 * employee count is not on its homepage, so that field cannot be filled honestly).
 */

export interface MetaFields {
  title?: string;
  description?: string;
  copyright?: string;
  copyrightYear?: string;
  schemaOrgTypes: string[];
  keywords: string[];
}

export interface ContactFields {
  email: string[];
  phone: string[];
  whatsapp: string[];
}

export interface SocialFields {
  x: string[];
  facebook: string[];
  instagram: string[];
  linkedin: string[];
  github: string[];
  youtube: string[];
  tiktok: string[];
  pinterest: string[];
}

export interface CompanyFields {
  inferredCompanyName?: string;
  companyName?: string;
  about?: string;
  locations: string[];
  industry?: string;
  companyFounded?: string;
}

/** Strip tags, scripts and styles to leave readable text. */
export function visibleText(html: string): string {
  return decodeEntities(
    html
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<[^>]+>/g, ' '),
  ).replace(/\s+/g, ' ');
}

const COPYRIGHT_RE =
  /(?:©|&copy;|\(c\)|copyright)\s*((?:19|20)\d{2}(?:\s*[-–—]\s*(?:19|20)?\d{2})?)?[^.<>\n]{0,80}/i;

export function extractMeta(html: string, metas: Record<string, string>, title?: string): MetaFields {
  const text = visibleText(html);

  const copyrightMatch = text.match(COPYRIGHT_RE);
  const copyright = copyrightMatch?.[0]?.trim().replace(/\s+/g, ' ');
  // The most recent year in the notice, which is what indicates whether a site is maintained.
  const years = [...(copyright ?? '').matchAll(/(19|20)\d{2}/g)].map((m) => m[0]);
  const copyrightYear = years.length > 0 ? years.sort().at(-1) : undefined;

  const schemaOrgTypes = new Set<string>();
  for (const m of html.matchAll(
    /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]{0,200000}?)<\/script>/gi,
  )) {
    const raw = m[1];
    if (!raw) continue;
    try {
      collectTypes(JSON.parse(raw) as unknown, schemaOrgTypes);
    } catch {
      // Malformed JSON-LD is extremely common; fall back to a regex sweep.
      for (const t of raw.matchAll(/"@type"\s*:\s*"([A-Za-z]+)"/g)) {
        if (t[1]) schemaOrgTypes.add(t[1]);
      }
    }
  }
  // Microdata is still widely used alongside JSON-LD.
  for (const m of html.matchAll(/itemtype=["']https?:\/\/schema\.org\/([A-Za-z]+)["']/gi)) {
    if (m[1]) schemaOrgTypes.add(m[1]);
  }

  const keywords = extractKeywords(text, metas);

  const out: MetaFields = { schemaOrgTypes: [...schemaOrgTypes].sort(), keywords };
  if (title) out.title = title;
  const description = metas['description'] ?? metas['og:description'];
  if (description) out.description = decodeEntities(description).trim();
  if (copyright) out.copyright = copyright;
  if (copyrightYear) out.copyrightYear = copyrightYear;
  return out;
}

function collectTypes(node: unknown, into: Set<string>, depth = 0): void {
  if (depth > 8 || node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) collectTypes(item, into, depth + 1);
    return;
  }
  const obj = node as Record<string, unknown>;
  const type = obj['@type'];
  if (typeof type === 'string') into.add(type);
  else if (Array.isArray(type)) for (const t of type) if (typeof t === 'string') into.add(t);
  for (const value of Object.values(obj)) collectTypes(value, into, depth + 1);
}

/**
 * Stop words for keyword extraction.
 *
 * Deliberately short. The goal is to surface what a site is about for segmentation, not to
 * do proper NLP, and an aggressive stop list would strip meaningful product vocabulary.
 */
const STOP_WORDS = new Set(
  ('a about above after again against all also am an and any are as at be because been before being below between both but by ' +
    'can cannot could did do does doing down during each few for from further had has have having he her here hers herself him ' +
    'himself his how i if in into is it its itself just me more most my myself no nor not now of off on once only or other our ' +
    'ours ourselves out over own same she should so some such than that the their theirs them themselves then there these they ' +
    'this those through to too under until up very was we were what when where which while who whom why will with would you ' +
    'your yours yourself yourselves get got new use used using make made like one two three first best top free home page site ' +
    'website click here read more learn view see our us we you they it will can may shop buy now menu skip content search ' +
    'privacy policy terms cookie cookies accept close login sign account cart checkout all rights reserved copyright inc ltd llc'
  ).split(' '),
);

export function extractKeywords(text: string, metas: Record<string, string>, limit = 25): string[] {
  const declared = (metas['keywords'] ?? '')
    .split(',')
    .map((k) => k.trim().toLowerCase())
    .filter((k) => k.length > 2 && k.length < 40);

  const counts = new Map<string, number>();
  for (const raw of text.toLowerCase().matchAll(/[a-z][a-z'-]{2,}/g)) {
    const word = raw[0].replace(/^['-]+|['-]+$/g, '');
    if (word.length < 3 || word.length > 30) continue;
    if (STOP_WORDS.has(word)) continue;
    counts.set(word, (counts.get(word) ?? 0) + 1);
  }

  const frequent = [...counts.entries()]
    // Require a word to appear more than once, so incidental vocabulary is excluded.
    .filter(([, n]) => n > 1)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([word]) => word);

  // Declared keywords first: the site author's own description of the page beats frequency.
  return [...new Set([...declared, ...frequent])].slice(0, limit);
}

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const OBFUSCATED_EMAIL_RE = /[a-z0-9._%+-]+\s*(?:\[at\]|\(at\)|&#64;|\s+at\s+)\s*[a-z0-9.-]+\s*(?:\[dot\]|\(dot\)|\s+dot\s+)\s*[a-z]{2,}/gi;

/** Extension-like suffixes that indicate a filename, not an address. */
const NON_EMAIL_SUFFIX = /\.(?:png|jpe?g|gif|webp|svg|css|js|woff2?|ttf|eot|ico|mp4|webm|pdf|json|xml|map)$/i;

export function extractContact(html: string, hostname: string): ContactFields {
  const emails = new Set<string>();
  const phones = new Set<string>();
  const whatsapp = new Set<string>();

  // mailto: links are the highest-signal source, so they are collected first.
  for (const m of html.matchAll(/mailto:([^"'?>\s]+)/gi)) {
    const value = decodeEntities(m[1] ?? '').trim().toLowerCase();
    if (value && !NON_EMAIL_SUFFIX.test(value)) emails.add(value);
  }
  const text = visibleText(html);
  for (const m of text.matchAll(EMAIL_RE)) {
    const value = m[0].toLowerCase();
    if (NON_EMAIL_SUFFIX.test(value)) continue;
    // Tracking pixels and CDN hosts produce address-shaped noise; require a plausible TLD.
    if (/\.(?:local|invalid|example|test)$/.test(value)) continue;
    emails.add(value);
  }
  for (const m of html.matchAll(OBFUSCATED_EMAIL_RE)) {
    const value = m[0]
      .replace(/\s*(?:\[at\]|\(at\)|&#64;|\s+at\s+)\s*/i, '@')
      .replace(/\s*(?:\[dot\]|\(dot\)|\s+dot\s+)\s*/i, '.')
      .trim()
      .toLowerCase();
    if (EMAIL_RE.test(value)) emails.add(value);
  }

  for (const m of html.matchAll(/tel:([+0-9()\-.\s]{6,25})/gi)) {
    const value = normalisePhone(m[1] ?? '');
    if (value) phones.add(value);
  }
  for (const m of html.matchAll(/(?:wa\.me|api\.whatsapp\.com\/send\?phone=)\/?([+0-9]{8,18})/gi)) {
    const value = normalisePhone(m[1] ?? '');
    if (value) whatsapp.add(value);
  }

  const apex = hostname.replace(/^www\./, '');
  // Addresses on the site's own domain are far more likely to be the business's own.
  const ranked = [...emails].sort((a, b) => {
    const aOwn = a.endsWith(`@${apex}`) || a.includes(apex) ? 0 : 1;
    const bOwn = b.endsWith(`@${apex}`) || b.includes(apex) ? 0 : 1;
    return aOwn - bOwn || a.localeCompare(b);
  });

  return { email: ranked.slice(0, 25), phone: [...phones].slice(0, 15), whatsapp: [...whatsapp].slice(0, 5) };
}

function normalisePhone(raw: string): string | null {
  const cleaned = raw.replace(/[^\d+]/g, '');
  const digits = cleaned.replace(/\D/g, '');
  if (digits.length < 7 || digits.length > 15) return null;
  return cleaned;
}

const SOCIAL_PATTERNS: Array<[keyof SocialFields, RegExp]> = [
  ['x', /(?:twitter|x)\.com\/(?!share|intent|home|search|hashtag|i\/)([A-Za-z0-9_]{1,20})/gi],
  ['facebook', /facebook\.com\/(?!sharer|share|dialog|tr\?|plugins|profile\.php)([A-Za-z0-9.\-_]{2,60})/gi],
  ['instagram', /instagram\.com\/(?!p\/|reel\/|explore\/|accounts\/)([A-Za-z0-9._]{2,40})/gi],
  ['linkedin', /linkedin\.com\/(?:company|in|school)\/([A-Za-z0-9\-_%.]{2,80})/gi],
  ['github', /github\.com\/(?!sponsors|features|about|pricing)([A-Za-z0-9\-_.]{1,40})/gi],
  ['youtube', /youtube\.com\/(?:c\/|channel\/|user\/|@)([A-Za-z0-9\-_.]{2,60})/gi],
  ['tiktok', /tiktok\.com\/@([A-Za-z0-9._]{2,30})/gi],
  ['pinterest', /pinterest\.[a-z.]{2,6}\/(?!pin\/|_\/)([A-Za-z0-9\-_/]{2,40})/gi],
];

export function extractSocial(html: string): SocialFields {
  const out: SocialFields = {
    x: [],
    facebook: [],
    instagram: [],
    linkedin: [],
    github: [],
    youtube: [],
    tiktok: [],
    pinterest: [],
  };
  for (const [key, re] of SOCIAL_PATTERNS) {
    const found = new Set<string>();
    for (const m of html.matchAll(re)) {
      const handle = (m[1] ?? '').replace(/\/$/, '');
      if (handle && handle.length > 1) found.add(handle);
    }
    out[key] = [...found].slice(0, 10);
  }
  return out;
}

/**
 * Infer company identity from what the site publishes about itself.
 *
 * `companyName` comes from structured data only, so it is trustworthy. `inferredCompanyName`
 * is a best guess from the title or copyright notice and is labelled as such, because the
 * difference between "we know" and "we guessed" matters when this feeds a CRM.
 */
export function extractCompany(
  html: string,
  metas: Record<string, string>,
  meta: MetaFields,
  hostname: string,
): CompanyFields {
  const out: CompanyFields = { locations: [] };

  for (const m of html.matchAll(
    /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]{0,200000}?)<\/script>/gi,
  )) {
    try {
      const parsed = JSON.parse(m[1] ?? '') as unknown;
      readOrganisation(parsed, out);
    } catch {
      /* handled by the meta extractor's regex fallback */
    }
  }

  if (!out.companyName) {
    const siteName = metas['og:site_name'] ?? metas['application-name'];
    if (siteName) out.inferredCompanyName = decodeEntities(siteName).trim();
  }
  if (!out.companyName && !out.inferredCompanyName) {
    // Titles are usually "Page name | Company", so the last segment is the best candidate.
    const segments = (meta.title ?? '').split(/\s[|\-–—·»]\s/).map((s) => s.trim());
    const candidate = segments.length > 1 ? segments.at(-1) : undefined;
    out.inferredCompanyName =
      candidate && candidate.length > 1 && candidate.length < 60
        ? candidate
        : hostname.replace(/^www\./, '').split('.')[0];
  }

  if (!out.about) {
    const about = metas['og:description'] ?? metas['description'];
    if (about) out.about = decodeEntities(about).trim().slice(0, 500);
  }

  const founded = visibleText(html).match(/(?:founded|established|since)\s+(?:in\s+)?((?:18|19|20)\d{2})/i);
  if (founded?.[1]) out.companyFounded = founded[1];

  return out;
}

function readOrganisation(node: unknown, out: CompanyFields, depth = 0): void {
  if (depth > 8 || node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) readOrganisation(item, out, depth + 1);
    return;
  }
  const obj = node as Record<string, unknown>;
  const types = ([] as string[]).concat((obj['@type'] as string | string[]) ?? []);
  const isOrg = types.some((t) =>
    /^(?:Organization|Corporation|LocalBusiness|Store|OnlineStore|NGO|EducationalOrganization|GovernmentOrganization|Restaurant|MedicalOrganization)$/i.test(
      t,
    ),
  );
  if (isOrg) {
    if (!out.companyName && typeof obj['name'] === 'string') out.companyName = obj['name'];
    if (!out.about && typeof obj['description'] === 'string') out.about = obj['description'].slice(0, 500);
    if (typeof obj['foundingDate'] === 'string') {
      const year = obj['foundingDate'].match(/(\d{4})/);
      if (year?.[1] && !out.companyFounded) out.companyFounded = year[1];
    }
    const address = obj['address'];
    for (const a of ([] as unknown[]).concat(address ?? [])) {
      const formatted = formatAddress(a);
      if (formatted && !out.locations.includes(formatted)) out.locations.push(formatted);
    }
  }
  for (const value of Object.values(obj)) readOrganisation(value, out, depth + 1);
}

function formatAddress(node: unknown): string | null {
  if (typeof node === 'string') return node.trim() || null;
  if (node === null || typeof node !== 'object') return null;
  const a = node as Record<string, unknown>;
  const parts = [
    a['streetAddress'],
    a['addressLocality'],
    a['addressRegion'],
    a['postalCode'],
    a['addressCountry'],
  ]
    .map((p) => (typeof p === 'string' ? p.trim() : typeof p === 'object' && p !== null ? String((p as Record<string, unknown>)['name'] ?? '') : ''))
    .filter((p) => p.length > 0);
  return parts.length > 0 ? parts.join(', ') : null;
}
