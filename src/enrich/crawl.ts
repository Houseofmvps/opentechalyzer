import type { AnalyzeOptions } from '../types.js';
import { absolutise, fetchPage, hostOf, parseHtml } from '../collect/http.js';

/**
 * Follow a small number of internal links to widen coverage.
 *
 * This is the equivalent of a commercial API's `recursive=true`, and it matters for two
 * reasons. First, technology coverage: checkout scripts, review widgets and payment SDKs only
 * load on product and cart pages, so a homepage-only scan systematically under-reports
 * ecommerce stacks. Second, contact data: emails, phone numbers and social handles live on
 * contact and about pages, essentially never on the homepage.
 *
 * Page selection is prioritised rather than breadth-first, because the goal is a handful of
 * high-yield pages, not a full site crawl.
 */

const PRIORITY_PATTERNS: Array<[RegExp, number]> = [
  [/\/(?:contact|contact-us|contactus|kontakt|get-in-touch)\b/i, 100],
  [/\/(?:about|about-us|aboutus|company|who-we-are|team|impressum)\b/i, 90],
  [/\/(?:products?|shop|store|collections?|catalog)\b/i, 80],
  [/\/(?:cart|basket|checkout)\b/i, 75],
  [/\/(?:pricing|plans|subscribe)\b/i, 70],
  [/\/(?:blog|news|articles?|insights)\b/i, 50],
  [/\/(?:support|help|faq|docs?)\b/i, 45],
  [/\/(?:careers?|jobs)\b/i, 40],
  [/\/(?:privacy|terms|legal|imprint)\b/i, 20],
];

export interface CrawledPage {
  url: string;
  status: number;
  html: string;
  scriptSrcs: string[];
  scriptContents: string[];
  stylesheetSrcs: string[];
  metas: Record<string, string>;
}

/** Score and rank internal links, then fetch the best ones. */
export async function crawlAdditionalPages(
  baseUrl: string,
  homepageHtml: string,
  opts: AnalyzeOptions & { maxPages?: number },
): Promise<{ pages: CrawledPage[]; warnings: string[] }> {
  const maxPages = Math.max(0, opts.maxPages ?? 5);
  if (maxPages === 0) return { pages: [], warnings: [] };

  const origin = new URL(baseUrl).origin;
  const baseHost = hostOf(baseUrl);
  const seen = new Set<string>([normalise(baseUrl)]);
  const scored = new Map<string, number>();

  for (const m of homepageHtml.matchAll(/<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
    const raw = m[1] ?? m[2] ?? m[3];
    if (!raw) continue;
    if (/^(?:#|mailto:|tel:|javascript:|data:|whatsapp:)/i.test(raw)) continue;

    let absolute: string;
    try {
      absolute = new URL(absolutise(raw, baseUrl)).toString();
    } catch {
      continue;
    }
    // Same-origin only. Following third-party links would attribute another site's stack
    // to this one, which is the worst failure mode a detector can have.
    if (!absolute.startsWith(origin) || hostOf(absolute) !== baseHost) continue;
    if (/\.(?:pdf|zip|jpe?g|png|gif|svg|webp|mp4|mp3|css|js|xml|ics|dmg|exe)$/i.test(absolute)) continue;

    const key = normalise(absolute);
    if (seen.has(key)) continue;

    let score = 1;
    for (const [pattern, weight] of PRIORITY_PATTERNS) {
      if (pattern.test(absolute)) {
        score = Math.max(score, weight);
      }
    }
    // Prefer shallow URLs when scores tie: they are more likely to be real sections rather
    // than individual items.
    const depth = new URL(absolute).pathname.split('/').filter(Boolean).length;
    score -= Math.min(depth, 5);
    scored.set(key, Math.max(scored.get(key) ?? 0, score));
  }

  const targets = [...scored.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, maxPages)
    .map(([url]) => url);

  const warnings: string[] = [];
  const pages: CrawledPage[] = [];

  // Two at a time: enough to keep the scan fast without behaving like a load test against
  // someone else's site.
  const CONCURRENCY = 2;
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    const slice = targets.slice(i, i + CONCURRENCY);
    await Promise.all(
      slice.map(async (url) => {
        try {
          const res = await fetchPage(url, { ...opts, timeout: Math.min(opts.timeout ?? 15_000, 10_000) });
          if (res.status !== 200 || !res.body) return;
          const parsed = parseHtml(res.body, res.finalUrl);
          pages.push({
            url: res.finalUrl,
            status: res.status,
            html: res.body,
            scriptSrcs: parsed.scriptSrcs,
            scriptContents: parsed.scriptContents,
            stylesheetSrcs: parsed.stylesheetSrcs,
            metas: parsed.metas,
          });
        } catch {
          warnings.push(`Could not fetch ${url} during crawl`);
        }
      }),
    );
  }

  return { pages, warnings };
}

function normalise(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    // Strip tracking parameters so the same page is not fetched several times.
    for (const key of [...u.searchParams.keys()]) {
      if (/^(?:utm_|fbclid|gclid|msclkid|ref|source)/i.test(key)) u.searchParams.delete(key);
    }
    return u.toString().replace(/\/$/, '');
  } catch {
    return url;
  }
}
