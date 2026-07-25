import type {
  Detection,
  Evidence,
  Evidence_Bundle,
  Fingerprint,
  Pattern,
  PatternInput,
  SignalSource,
} from '../types.js';
import { SOURCE_RELIABILITY } from '../types.js';

/** Normalise the shorthand string form of a pattern into the object form. */
function toPattern(p: PatternInput): Pattern {
  return typeof p === 'string' ? { re: p } : p;
}

const regexCache = new Map<string, RegExp | null>();

/**
 * Compile a pattern once and cache it. A malformed pattern in the database must never
 * take down an entire scan, so compilation failures degrade to "never matches".
 */
function compile(source: string, caseSensitive = false): RegExp | null {
  const key = caseSensitive ? `cs:${source}` : `ci:${source}`;
  const cached = regexCache.get(key);
  if (cached !== undefined) return cached;
  let re: RegExp | null;
  try {
    re = new RegExp(source, caseSensitive ? '' : 'i');
  } catch {
    re = null;
  }
  regexCache.set(key, re);
  return re;
}

/** Resolve a version or id template such as "$1.$2" against a regex match. */
function resolveTemplate(template: string | undefined, m: RegExpMatchArray): string | undefined {
  if (!template) return undefined;
  const out = template.replace(/\$(\d+)/g, (_, d: string) => m[Number(d)] ?? '');
  const trimmed = out.replace(/^[.\-_\s]+|[.\-_\s]+$/g, '');
  return trimmed.length > 0 ? trimmed : undefined;
}

function truncate(s: string, n = 140): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > n ? `${flat.slice(0, n)}...` : flat;
}

/**
 * Test one pattern against one haystack, returning evidence on a hit.
 *
 * `reliabilityScale` lets a fingerprint dampen or boost all of its own signals via
 * `weight`, and lets an individual pattern override via `confidence`.
 */
function testPattern(
  pattern: PatternInput,
  haystack: string,
  source: SignalSource,
  subject: string,
  weight: number,
): Evidence | null {
  const p = toPattern(pattern);
  const re = compile(p.re, p.caseSensitive);
  if (!re) return null;
  const m = haystack.match(re);
  if (!m) return null;
  const base = p.confidence ?? SOURCE_RELIABILITY[source];
  return {
    source,
    subject,
    pattern: p.re,
    match: truncate(m[0]),
    reliability: Math.max(0, Math.min(0.99, base * weight)),
    version: resolveTemplate(p.version, m),
    accountId: resolveTemplate(p.id, m),
    note: p.note,
  };
}

/**
 * Combine independent evidence into a single confidence value.
 *
 * Each piece of evidence is treated as an independent test with a false-positive rate
 * of (1 - reliability). The probability that *every* one of them is a false positive is
 * the product of those rates, so overall confidence is one minus that product. This is
 * why three mediocre signals (0.55 each) beat one decent signal (0.82): 0.909 vs 0.82.
 *
 * Naive summing, by contrast, saturates at 100 as soon as you add enough weak matches,
 * which is exactly how tech detectors end up confidently wrong.
 */
export function combineConfidence(evidence: Evidence[]): number {
  if (evidence.length === 0) return 0;
  // Group by source so that ten HTML regexes for the same library cannot masquerade
  // as ten independent observations. Within a source we keep the strongest signal and
  // give the remainder sharply diminishing influence.
  const bySource = new Map<SignalSource, number[]>();
  for (const e of evidence) {
    const arr = bySource.get(e.source) ?? [];
    arr.push(e.reliability);
    bySource.set(e.source, arr);
  }

  let falseProduct = 1;
  for (const reliabilities of bySource.values()) {
    reliabilities.sort((a, b) => b - a);
    reliabilities.forEach((r, i) => {
      // First match in a source counts fully, subsequent ones are damped by 1/(i+1).
      const damped = r / (i + 1);
      falseProduct *= 1 - damped;
    });
  }
  return Math.round((1 - falseProduct) * 1000) / 10;
}

/** Pick the most plausible version string from an evidence set. */
function pickVersion(evidence: Evidence[]): string | undefined {
  const versions = evidence
    .filter((e) => e.version)
    .sort((a, b) => b.reliability - a.reliability)
    .map((e) => e.version as string);
  if (versions.length === 0) return undefined;
  // Prefer the most specific version (most dot-separated parts) among the top tier of
  // reliability, since "3" and "3.7.1" often both match and the longer one is right.
  const best = versions[0] as string;
  const topTier = versions.filter((v) => v.split('.').length >= best.split('.').length);
  return topTier.sort((a, b) => b.length - a.length)[0] ?? best;
}

/** Collect every distinct account identifier captured across an evidence set. */
function pickAccountIds(evidence: Evidence[]): string[] | undefined {
  const ids = [...new Set(evidence.map((e) => e.accountId).filter((v): v is string => Boolean(v)))];
  return ids.length > 0 ? ids : undefined;
}

/** Extract cookie name/value pairs from raw Set-Cookie lines and a document.cookie string. */
function parseCookies(setCookies: string[]): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  for (const line of setCookies) {
    const first = line.split(';')[0];
    if (!first) continue;
    const idx = first.indexOf('=');
    if (idx <= 0) continue;
    out.push({ name: first.slice(0, idx).trim(), value: first.slice(idx + 1).trim() });
  }
  return out;
}

/** Collect all evidence for a single fingerprint against a bundle. */
function matchFingerprint(fp: Fingerprint, b: Evidence_Bundle): Evidence[] {
  const weight = fp.weight ?? 1;
  const found: Evidence[] = [];
  const push = (e: Evidence | null) => {
    if (e) found.push(e);
  };

  // Headers. The header name is itself a pattern so that "x-.*-cache" style families work.
  if (fp.headers) {
    for (const [rawName, pattern] of Object.entries(fp.headers)) {
      const nameRe = compile(`^${rawName}$`);
      for (const [hName, hValue] of Object.entries(b.headers)) {
        if (nameRe ? nameRe.test(hName) : hName === rawName.toLowerCase()) {
          const p = toPattern(pattern);
          if (p.re === '') {
            push({
              source: 'header',
              subject: hName,
              pattern: '(present)',
              match: truncate(`${hName}: ${hValue}`),
              reliability: (p.confidence ?? SOURCE_RELIABILITY.header) * weight,
              note: p.note,
            });
          } else {
            push(testPattern(pattern, hValue, 'header', hName, weight));
          }
        }
      }
    }
  }

  // Cookies.
  if (fp.cookies) {
    const cookies = parseCookies(b.setCookies);
    for (const [rawName, pattern] of Object.entries(fp.cookies)) {
      const nameRe = compile(rawName);
      for (const c of cookies) {
        if (!nameRe || !nameRe.test(c.name)) continue;
        const p = toPattern(pattern);
        if (p.re === '') {
          push({
            source: 'cookie',
            subject: 'set-cookie',
            pattern: rawName,
            match: truncate(c.name),
            reliability: (p.confidence ?? SOURCE_RELIABILITY.cookie) * weight,
            note: p.note,
          });
        } else {
          push(testPattern(pattern, c.value, 'cookie', `cookie:${c.name}`, weight));
        }
      }
    }
  }

  // Meta tags.
  if (fp.meta) {
    for (const [rawName, pattern] of Object.entries(fp.meta)) {
      const nameRe = compile(`^${rawName}$`);
      for (const [mName, mContent] of Object.entries(b.metas)) {
        if (!nameRe || !nameRe.test(mName)) continue;
        const p = toPattern(pattern);
        if (p.re === '') {
          push({
            source: 'meta',
            subject: `meta[${mName}]`,
            pattern: '(present)',
            match: truncate(mContent),
            reliability: (p.confidence ?? SOURCE_RELIABILITY.meta) * weight,
            note: p.note,
          });
        } else {
          push(testPattern(pattern, mContent, 'meta', `meta[${mName}]`, weight));
        }
      }
    }
  }

  // HTML body. Rendered HTML is a superset of raw when available.
  const htmlHay = b.renderedHtml ?? b.html;
  if (fp.html) {
    for (const pattern of fp.html) {
      push(testPattern(pattern, htmlHay, 'html', 'html', weight));
      // Only fall back to raw HTML if the rendered pass missed it, so we do not
      // double-count the same fact from two haystacks.
      if (b.renderedHtml && !found.some((e) => e.pattern === toPattern(pattern).re)) {
        push(testPattern(pattern, b.html, 'html', 'html(raw)', weight));
      }
    }
  }

  const listSignals: Array<[PatternInput[] | undefined, string[], SignalSource, string]> = [
    [fp.scriptSrc, b.scriptSrcs, 'script-src', 'script[src]'],
    [fp.scriptContent, b.scriptContents, 'script-content', 'inline script'],
    [fp.stylesheetSrc, b.stylesheetSrcs, 'stylesheet-src', 'link[href]'],
    [fp.cssContent, b.cssContents, 'css-content', 'stylesheet body'],
    [fp.requestHost, b.requestHosts, 'request-host', 'runtime request'],
    [fp.dnsTxt, b.dns.txt, 'dns-txt', 'TXT'],
    [fp.dnsMx, b.dns.mx, 'dns-mx', 'MX'],
    [fp.dnsCname, b.dns.cname, 'dns-cname', 'CNAME'],
    [fp.dnsNs, b.dns.ns, 'dns-ns', 'NS'],
    [fp.certSubdomain, b.certSubdomains, 'cert-subdomain', 'cert SAN'],
    [fp.npmDep, b.npmDeps, 'sourcemap-dep', 'sourcemap'],
  ];

  for (const [patterns, haystacks, source, subject] of listSignals) {
    if (!patterns) continue;
    for (const pattern of patterns) {
      for (const hay of haystacks) {
        const e = testPattern(pattern, hay, source, subject, weight);
        if (e) {
          found.push(e);
          break; // one hit per pattern per source is enough
        }
      }
    }
  }

  if (fp.url) {
    for (const pattern of fp.url) {
      push(testPattern(pattern, b.finalUrl, 'url', 'url', weight));
    }
  }

  if (fp.robots && b.robots) {
    for (const pattern of fp.robots) {
      push(testPattern(pattern, b.robots, 'robots', 'robots.txt', weight));
    }
  }

  // JS globals.
  if (fp.js) {
    for (const [path, pattern] of Object.entries(fp.js)) {
      const value = b.jsGlobals[path];
      if (value === undefined) continue;
      const p = toPattern(pattern);
      if (p.re === '') {
        push({
          source: 'js-global',
          subject: `window.${path}`,
          pattern: '(exists)',
          match: truncate(value || 'defined'),
          reliability: (p.confidence ?? SOURCE_RELIABILITY['js-global']) * weight,
          note: p.note,
        });
      } else {
        push(testPattern(pattern, value, 'js-global', `window.${path}`, weight));
      }
    }
  }

  // DOM selectors, resolved during rendering.
  if (fp.dom) {
    for (const selector of fp.dom) {
      if (b.domSelectors.has(selector)) {
        push({
          source: 'dom',
          subject: 'rendered DOM',
          pattern: selector,
          match: selector,
          reliability: SOURCE_RELIABILITY.dom * weight,
        });
      }
    }
  }

  // Favicon hash.
  if (fp.faviconMd5 && b.faviconMd5 && fp.faviconMd5.includes(b.faviconMd5)) {
    push({
      source: 'favicon',
      subject: '/favicon.ico',
      pattern: b.faviconMd5,
      match: b.faviconMd5,
      reliability: SOURCE_RELIABILITY.favicon * weight,
    });
  }

  // Probes.
  if (fp.probe) {
    for (const probe of fp.probe) {
      const res = b.probes[probe.path];
      if (!res) continue;
      const okStatus = (probe.status ?? [200]).includes(res.status);
      if (!okStatus) continue;
      if (probe.body) {
        push(testPattern(probe.body, res.body, 'probe', `GET ${probe.path}`, weight));
      } else if (probe.header) {
        const idx = probe.header.indexOf(':');
        const hName = probe.header.slice(0, idx).toLowerCase();
        const hPattern = probe.header.slice(idx + 1);
        const hv = res.headers[hName];
        if (hv) push(testPattern(hPattern, hv, 'probe', `GET ${probe.path} [${hName}]`, weight));
      } else {
        push({
          source: 'probe',
          subject: `GET ${probe.path}`,
          pattern: `status ${res.status}`,
          match: `status ${res.status}`,
          reliability: SOURCE_RELIABILITY.probe * weight,
        });
      }
    }
  }

  return found;
}

/**
 * Run the whole database against an evidence bundle and resolve relationships.
 */
export function detect(
  fingerprints: Fingerprint[],
  bundle: Evidence_Bundle,
  minConfidence = 25,
): Detection[] {
  const index = new Map(fingerprints.map((f) => [f.name, f]));
  const raw = new Map<string, Detection>();

  for (const fp of fingerprints) {
    const evidence = matchFingerprint(fp, bundle);
    if (evidence.length === 0) continue;
    raw.set(fp.name, {
      name: fp.name,
      categories: fp.categories,
      website: fp.website,
      description: fp.description,
      confidence: combineConfidence(evidence),
      version: pickVersion(evidence),
      accountIds: pickAccountIds(evidence),
      inferred: false,
      evidence,
    });
  }

  // `requires`: drop detections whose prerequisite technology is absent. This is what
  // stops "WooCommerce" firing on a site that merely mentions the word without WordPress.
  let changed = true;
  while (changed) {
    changed = false;
    for (const name of [...raw.keys()]) {
      const fp = index.get(name);
      if (!fp?.requires?.length) continue;
      const satisfied = fp.requires.some((r) => raw.has(r));
      if (!satisfied) {
        raw.delete(name);
        changed = true;
      }
    }
  }

  // `implies`: add technologies that are logically entailed. Confidence is inherited with
  // a penalty because an inference is always weaker than an observation, and the chain
  // decays so that deep implication paths do not manufacture certainty.
  const queue = [...raw.values()];
  while (queue.length > 0) {
    const det = queue.shift() as Detection;
    const fp = index.get(det.name);
    if (!fp?.implies?.length) continue;
    for (const impliedName of fp.implies) {
      const impliedFp = index.get(impliedName);
      if (!impliedFp) continue;
      const inheritedConfidence = Math.round(det.confidence * 0.85 * 10) / 10;
      const existing = raw.get(impliedName);
      if (existing) {
        // An implication is corroborating evidence, so take the stronger of the two rather
        // than letting whichever arrived first win. Without this, a weak direct match
        // suppresses a strong inference: laravel.com matched Laravel at only 30% from a
        // generic XSRF-TOKEN cookie, which blocked the 75% inference from Statamic (a
        // framework built on Laravel) and understated a certainty as a maybe.
        if (inheritedConfidence > existing.confidence) {
          existing.confidence = inheritedConfidence;
          // `inferred` stays false when the technology was genuinely observed; only the
          // confidence is lifted. Provenance is only rewritten for a purely inferred entry.
          if (existing.inferred) existing.impliedBy = det.name;
        }
        continue;
      }
      const inferred: Detection = {
        name: impliedFp.name,
        categories: impliedFp.categories,
        website: impliedFp.website,
        description: impliedFp.description,
        confidence: inheritedConfidence,
        inferred: true,
        impliedBy: det.name,
        evidence: [
          {
            source: 'implied',
            subject: det.name,
            pattern: `${det.name} implies ${impliedName}`,
            match: det.name,
            reliability: 0,
          },
        ],
      };
      raw.set(impliedName, inferred);
      queue.push(inferred);
    }
  }

  // `excludes`: mutually exclusive technologies, strongest wins.
  for (const [name, det] of raw) {
    const fp = index.get(name);
    if (!fp?.excludes?.length) continue;
    for (const other of fp.excludes) {
      const victim = raw.get(other);
      if (victim && det.confidence >= victim.confidence) raw.delete(other);
    }
  }

  return [...raw.values()]
    .filter((d) => d.confidence >= minConfidence)
    .sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name));
}
