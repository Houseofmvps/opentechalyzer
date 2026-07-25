import type { AnalyzeOptions, Fingerprint } from '../types.js';
import { DEFAULT_UA } from './http.js';

export interface RenderResult {
  finalUrl: string;
  status: number;
  html: string;
  jsGlobals: Record<string, string>;
  domSelectors: Set<string>;
  requestHosts: string[];
  warnings: string[];
}

/**
 * Render with Playwright to collect the signals a static fetch cannot see.
 *
 * Roughly half of a modern site's stack is injected after load: tag managers pull in
 * pixels, Shopify app blocks mount widgets, SPAs hydrate their framework globals. On the
 * Vilvah audit that motivated this tool, static HTML alone missed most of the app layer.
 *
 * Playwright is an optional peer dependency, so this returns null rather than throwing
 * when it is not installed. The static path stays fully functional without it.
 */
export async function renderPage(
  url: string,
  fingerprints: Fingerprint[],
  opts: AnalyzeOptions,
): Promise<RenderResult | null> {
  const pw = await loadPlaywright();
  if (!pw) return null;
  const { chromium } = pw;

  const wantedGlobals = collectGlobalPaths(fingerprints);
  const wantedSelectors = collectSelectors(fingerprints);
  const warnings: string[] = [];
  const requestHosts = new Set<string>();

  const browser = await chromium.launch({ args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  try {
    const context = await browser.newContext({
      userAgent: opts.userAgent ?? DEFAULT_UA,
      ignoreHTTPSErrors: true,
      viewport: { width: 1440, height: 900 },
      locale: 'en-US',
    });
    const page = await context.newPage();

    // Every request the page makes is a stack signal, including beacons that never
    // appear in the DOM.
    page.on('request', (req: { url: () => string }) => {
      try {
        requestHosts.add(new URL(req.url()).hostname);
      } catch {
        /* opaque url */
      }
    });

    const timeout = opts.timeout ?? 15_000;
    const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout });

    // Let deferred third parties boot. `networkidle` is unreliable on sites with polling
    // or open sockets, so we wait for it but never let it block the scan.
    await page
      .waitForLoadState('networkidle', { timeout: Math.min(timeout, 8000) })
      .catch(() => warnings.push('Page never reached network idle; late-loading scripts may be missed'));
    await page.waitForTimeout(1200);

    const html = await page.content();

    const jsGlobals = await page.evaluate((paths: string[]) => {
      const out: Record<string, string> = {};
      for (const path of paths) {
        try {
          let cursor: unknown = globalThis as unknown as Record<string, unknown>;
          for (const part of path.split('.')) {
            if (cursor === null || cursor === undefined) {
              cursor = undefined;
              break;
            }
            cursor = (cursor as Record<string, unknown>)[part];
          }
          if (cursor === undefined) continue;
          let repr: string;
          const t = typeof cursor;
          if (t === 'string' || t === 'number' || t === 'boolean') {
            repr = String(cursor);
          } else if (t === 'function') {
            repr = 'function';
          } else {
            // Objects: expose a shallow shape plus any version-looking field, since that
            // is what version patterns need to match against.
            const obj = cursor as Record<string, unknown>;
            const version =
              typeof obj['version'] === 'string'
                ? obj['version']
                : typeof obj['VERSION'] === 'string'
                  ? obj['VERSION']
                  : '';
            const keys = Object.keys(obj).slice(0, 25).join(',');
            repr = version ? `${version} {${keys}}` : `{${keys}}`;
          }
          out[path] = repr;
        } catch {
          /* cross-origin or throwing getter */
        }
      }
      return out;
    }, wantedGlobals);

    const matchedSelectors = await page.evaluate((selectors: string[]) => {
      const hits: string[] = [];
      for (const selector of selectors) {
        try {
          if (document.querySelector(selector)) hits.push(selector);
        } catch {
          /* invalid selector in the database */
        }
      }
      return hits;
    }, wantedSelectors);

    // document.cookie catches cookies set by client-side JS, which never appear in
    // Set-Cookie response headers.
    const clientCookies = await context.cookies();

    return {
      finalUrl: page.url(),
      status: response?.status() ?? 0,
      html,
      jsGlobals,
      domSelectors: new Set(matchedSelectors),
      requestHosts: [...requestHosts],
      warnings: [
        ...warnings,
        ...clientCookies.map((c: { name: string; value: string }) => `__cookie__${c.name}=${c.value}`),
      ],
    };
  } finally {
    await browser.close().catch(() => undefined);
  }
}

function collectGlobalPaths(fingerprints: Fingerprint[]): string[] {
  const set = new Set<string>();
  for (const fp of fingerprints) {
    for (const path of Object.keys(fp.js ?? {})) set.add(path);
  }
  return [...set];
}

function collectSelectors(fingerprints: Fingerprint[]): string[] {
  const set = new Set<string>();
  for (const fp of fingerprints) {
    for (const selector of fp.dom ?? []) set.add(selector);
  }
  return [...set];
}

/**
 * Load Playwright at runtime without making it a build-time dependency.
 *
 * The specifier is held in a variable so TypeScript does not try to resolve the module,
 * which keeps the package installable and type-checkable for the majority of users who
 * only ever run static scans and do not want a 300 MB browser download.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadPlaywright(): Promise<any | null> {
  const specifier = 'playwright';
  try {
    return await import(specifier);
  } catch {
    return null;
  }
}

/** True when Playwright can be loaded in this environment. */
export async function isRenderAvailable(): Promise<boolean> {
  return (await loadPlaywright()) !== null;
}
