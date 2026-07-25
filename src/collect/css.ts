import type { AnalyzeOptions } from '../types.js';
import { absolutise, fetchPage } from './http.js';

/**
 * Download first-party stylesheets so CSS frameworks can be identified from their output.
 *
 * Guessing a CSS framework from class names in HTML is unreliable: `flex items-center` looks
 * like Tailwind but any codebase can define those names, and detectors that guess this way
 * report Tailwind on sites that have never used it. The compiled CSS, by contrast, contains
 * unforgeable evidence, because the framework itself generated it: Tailwind emits `--tw-*`
 * custom properties, Bootstrap 5 emits `--bs-*`, Bulma emits its own variable set.
 *
 * Only first-party stylesheets are fetched. Vendor CSS on a CDN is already identified by URL.
 */
export async function collectCss(
  stylesheetSrcs: string[],
  baseUrl: string,
  opts: AnalyzeOptions,
): Promise<string[]> {
  const origin = new URL(baseUrl).origin;

  const candidates = stylesheetSrcs
    .filter((href) => /\.css(\?|$)/i.test(href))
    .filter((href) => {
      try {
        return new URL(href, baseUrl).origin === origin;
      } catch {
        return false;
      }
    })
    .slice(0, 4);

  if (candidates.length === 0) return [];

  const bodies = await Promise.all(
    candidates.map(async (href) => {
      try {
        const res = await fetchPage(absolutise(href, baseUrl), {
          ...opts,
          timeout: Math.min(opts.timeout ?? 15_000, 8000),
        });
        if (res.status !== 200) return '';
        // Framework signatures live in the variable declarations and preflight rules at the
        // top of a compiled bundle, so a prefix is enough and keeps memory bounded on the
        // multi-megabyte stylesheets that utility frameworks produce.
        return res.body.slice(0, 250_000);
      } catch {
        return '';
      }
    }),
  );

  return bodies.filter((b) => b.length > 0);
}
