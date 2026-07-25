import { collectCertSubdomains } from './collect/certs.js';
import { collectCss } from './collect/css.js';
import { resolveDns } from './collect/dns.js';
import { faviconHash } from './collect/favicon.js';
import { apexOf, fetchPage, hostOf, normaliseUrl, parseHtml } from './collect/http.js';
import { runProbes } from './collect/probe.js';
import { renderPage } from './collect/render.js';
import { collectNpmDeps } from './collect/sourcemap.js';
import { detect } from './detect/engine.js';
import { crawlAdditionalPages } from './enrich/crawl.js';
import { ALL_FIELD_SETS, enrich, type FieldSet } from './enrich/index.js';
import { getFingerprints, DATABASE_VERSION } from './fingerprints/index.js';
import type {
  AnalyzeOptions,
  AnalyzeResult,
  Category,
  Detection,
  Evidence_Bundle,
  Fingerprint,
} from './types.js';

/**
 * Analyse a single URL and return every technology detected, with evidence.
 *
 * Collection is staged so that a failure in any optional signal source degrades the result
 * rather than failing the scan. The only hard requirement is that the initial page fetch
 * succeeds; everything after that is additive.
 */
export async function analyze(
  input: string,
  options: AnalyzeOptions = {},
  fingerprintsOverride?: Fingerprint[],
): Promise<AnalyzeResult> {
  const opts: AnalyzeOptions = {
    dns: true,
    probe: true,
    favicon: true,
    css: true,
    certs: false,
    sourcemaps: false,
    render: false,
    minConfidence: 25,
    timeout: 15_000,
    maxBundles: 8,
    ...options,
  };
  const progress = opts.onProgress ?? (() => undefined);
  const url = normaliseUrl(input);
  const fingerprints = fingerprintsOverride ?? (await getFingerprints());
  const timings: Record<string, number> = {};
  const warnings: string[] = [];

  const time = async <T>(stage: string, fn: () => Promise<T>): Promise<T> => {
    const started = Date.now();
    try {
      return await fn();
    } finally {
      timings[stage] = Date.now() - started;
    }
  };

  // --- Stage 1: the page itself. Everything else is optional. ---
  progress('fetch', url);
  const page = await time('fetch', () => fetchPage(url, opts));
  const parsed = parseHtml(page.body, page.finalUrl);
  const hostname = hostOf(page.finalUrl);
  const apex = apexOf(hostname);

  const bundle: Evidence_Bundle = {
    url,
    finalUrl: page.finalUrl,
    status: page.status,
    headers: page.headers,
    setCookies: [...page.setCookies],
    html: page.body,
    scriptSrcs: [...parsed.scriptSrcs],
    scriptContents: [...parsed.scriptContents],
    stylesheetSrcs: [...parsed.stylesheetSrcs],
    cssContents: [],
    metas: { ...parsed.metas },
    requestHosts: [],
    jsGlobals: {},
    domSelectors: new Set(),
    dns: { txt: [], mx: [], cname: [], ns: [], a: [] },
    certSubdomains: [],
    npmDeps: [],
    probes: {},
    warnings,
    timings,
  };

  // Subresource hosts are a signal even without a browser: preconnect and preload hints in
  // the HTML head name third parties before any script executes.
  for (const src of [...parsed.scriptSrcs, ...parsed.stylesheetSrcs]) {
    const h = hostOf(src);
    if (h && h !== hostname) bundle.requestHosts.push(h);
  }
  const linkHeader = page.headers['link'];
  if (linkHeader) {
    for (const m of linkHeader.matchAll(/<([^>]+)>/g)) {
      const h = hostOf(m[1]?.startsWith('//') ? `https:${m[1]}` : (m[1] ?? ''));
      if (h && h !== hostname) bundle.requestHosts.push(h);
    }
  }

  // --- Stage 2: optional collectors, all run concurrently. ---
  const jobs: Array<Promise<void>> = [];

  if (opts.render) {
    progress('render', 'launching browser');
    jobs.push(
      time('render', async () => {
        try {
          const rendered = await renderPage(page.finalUrl, fingerprints, opts);
          if (!rendered) {
            warnings.push(
              'Playwright is not installed, so DOM, JS global and runtime request signals were skipped. Install it with: npm i playwright && npx playwright install chromium',
            );
            return;
          }
          bundle.renderedHtml = rendered.html;
          bundle.jsGlobals = rendered.jsGlobals;
          bundle.domSelectors = rendered.domSelectors;
          bundle.requestHosts.push(...rendered.requestHosts);
          // Client-set cookies arrive smuggled through warnings to keep the render
          // contract simple; unpack them into the cookie evidence.
          for (const w of rendered.warnings) {
            if (w.startsWith('__cookie__')) bundle.setCookies.push(w.slice('__cookie__'.length));
            else warnings.push(w);
          }
          // Re-parse the rendered DOM so scripts injected by tag managers are matched too.
          const renderedParsed = parseHtml(rendered.html, rendered.finalUrl);
          bundle.scriptSrcs.push(...renderedParsed.scriptSrcs);
          bundle.scriptContents.push(...renderedParsed.scriptContents);
          bundle.stylesheetSrcs.push(...renderedParsed.stylesheetSrcs);
          Object.assign(bundle.metas, renderedParsed.metas);
        } catch (err) {
          warnings.push(`Render failed: ${(err as Error).message}`);
        }
      }),
    );
  }

  if (opts.dns && hostname) {
    progress('dns', hostname);
    jobs.push(
      time('dns', async () => {
        bundle.dns = await resolveDns(hostname, apex);
      }),
    );
  }

  if (opts.probe) {
    progress('probe', 'well-known paths');
    jobs.push(
      time('probe', async () => {
        const { results, failed } = await runProbes(page.finalUrl, fingerprints, opts);
        bundle.probes = results;
        bundle.robots = results['/robots.txt']?.body;
        if (failed.length > 0) {
          // Surfaced rather than swallowed: a failed probe removes evidence, so the user
          // needs to know the result is less complete than it looks.
          warnings.push(
            `${failed.length} probe request(s) failed (${failed.slice(0, 4).join(', ')}${failed.length > 4 ? ', ...' : ''}). Detections relying on them may be missing. Retry, or raise --timeout.`,
          );
        }
      }),
    );
  }

  if (opts.favicon) {
    jobs.push(
      time('favicon', async () => {
        bundle.faviconMd5 = await faviconHash(page.finalUrl, opts);
      }),
    );
  }

  if (opts.css) {
    jobs.push(
      time('css', async () => {
        bundle.cssContents = await collectCss(parsed.stylesheetSrcs, page.finalUrl, opts);
      }),
    );
  }

  if (opts.sourcemaps) {
    progress('sourcemaps', 'inspecting bundles');
    jobs.push(
      time('sourcemaps', async () => {
        const { deps, warnings: w } = await collectNpmDeps(parsed.scriptSrcs, page.finalUrl, opts);
        bundle.npmDeps = deps;
        warnings.push(...w);
      }),
    );
  }

  if (opts.certs && apex) {
    progress('certs', apex);
    jobs.push(
      time('certs', async () => {
        const { subdomains, warnings: w } = await collectCertSubdomains(apex, opts);
        bundle.certSubdomains = subdomains;
        warnings.push(...w);
      }),
    );
  }

  // Crawling happens before matching so additional pages contribute their own scripts and
  // markup to the same evidence bundle rather than being analysed separately.
  const crawledPages: string[] = [];
  let combinedHtml = page.body;
  if (opts.crawl) {
    const maxPages = typeof opts.crawl === 'number' ? opts.crawl : 5;
    progress('crawl', `up to ${maxPages} internal pages`);
    await time('crawl', async () => {
      const { pages, warnings: w } = await crawlAdditionalPages(page.finalUrl, page.body, {
        ...opts,
        maxPages,
      });
      warnings.push(...w);
      for (const p of pages) {
        crawledPages.push(p.url);
        bundle.scriptSrcs.push(...p.scriptSrcs);
        bundle.scriptContents.push(...p.scriptContents);
        bundle.stylesheetSrcs.push(...p.stylesheetSrcs);
        for (const [k, v] of Object.entries(p.metas)) bundle.metas[k] ??= v;
        for (const src of [...p.scriptSrcs, ...p.stylesheetSrcs]) {
          const h = hostOf(src);
          if (h && h !== hostname) bundle.requestHosts.push(h);
        }
      }
      // Matching runs against the concatenation, so a widget present only on the cart page
      // is still found. Kept separate from `bundle.html` for the homepage-only meta fields.
      combinedHtml = [page.body, ...pages.map((p) => p.html)].join('\n');
      bundle.html = combinedHtml;
    });
  }

  await Promise.allSettled(jobs);

  bundle.requestHosts = [...new Set(bundle.requestHosts)];
  bundle.scriptSrcs = [...new Set(bundle.scriptSrcs)];
  bundle.stylesheetSrcs = [...new Set(bundle.stylesheetSrcs)];

  // --- Stage 3: match. ---
  progress('detect', `${fingerprints.length} fingerprints`);
  const detections = await time('detect', async () =>
    detect(fingerprints, bundle, opts.minConfidence ?? 25),
  );

  const byCategory: Partial<Record<Category, Detection[]>> = {};
  for (const det of detections) {
    for (const category of det.categories) {
      (byCategory[category] ??= []).push(det);
    }
  }

  // --- Stage 4: enrichment field sets. ---
  let enrichment: AnalyzeResult['enrichment'];
  if (opts.fields && opts.fields.length > 0) {
    const requested = opts.fields.includes('all')
      ? ALL_FIELD_SETS
      : (opts.fields.filter((f) => (ALL_FIELD_SETS as string[]).includes(f)) as FieldSet[]);
    const unknown = opts.fields.filter(
      (f) => f !== 'all' && !(ALL_FIELD_SETS as string[]).includes(f),
    );
    if (unknown.length > 0) {
      warnings.push(
        `Unknown field sets ignored: ${unknown.join(', ')}. Valid sets: ${ALL_FIELD_SETS.join(', ')}, all.`,
      );
    }
    if (requested.length > 0) {
      progress('enrich', requested.join(', '));
      await time('enrich', async () => {
        const { enrichment: e, warnings: w } = await enrich(
          {
            html: bundle.renderedHtml ? `${combinedHtml}\n${bundle.renderedHtml}` : combinedHtml,
            homepageHtml: bundle.renderedHtml ?? page.body,
            metas: bundle.metas,
            ...(parsed.title ? { title: parsed.title } : {}),
            hostname,
            finalUrl: page.finalUrl,
            ...(page.headers['content-language']
              ? { contentLanguage: page.headers['content-language'] }
              : {}),
            detections,
          },
          requested,
          opts,
        );
        enrichment = e;
        warnings.push(...w);
      });
    }
  }

  return {
    url,
    finalUrl: page.finalUrl,
    status: page.status,
    detections,
    byCategory,
    warnings: [...new Set(warnings)],
    timings,
    meta: {
      title: parsed.title,
      description: parsed.metas['description'],
      generator: parsed.metas['generator'],
      ip: bundle.dns.a[0],
    },
    ...(enrichment ? { enrichment } : {}),
    ...(crawledPages.length > 0 ? { crawledPages } : {}),
    databaseVersion: DATABASE_VERSION,
    fingerprintCount: fingerprints.length,
    analyzedAt: new Date().toISOString(),
  };
}

/**
 * Analyse many URLs with bounded concurrency.
 *
 * Failures are captured per URL so one dead host cannot abort a batch of a thousand.
 */
export async function analyzeMany(
  urls: string[],
  options: AnalyzeOptions & { concurrency?: number } = {},
): Promise<Array<{ url: string; result?: AnalyzeResult; error?: string }>> {
  const concurrency = Math.max(1, options.concurrency ?? 5);
  const fingerprints = await getFingerprints();
  const out: Array<{ url: string; result?: AnalyzeResult; error?: string }> = [];
  let cursor = 0;

  const worker = async (): Promise<void> => {
    for (;;) {
      const index = cursor++;
      const target = urls[index];
      if (target === undefined) return;
      try {
        out[index] = { url: target, result: await analyze(target, options, fingerprints) };
      } catch (err) {
        out[index] = { url: target, error: (err as Error).message };
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length) }, worker));
  return out;
}
