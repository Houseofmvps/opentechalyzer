import type { AnalyzeOptions, Fingerprint } from '../types.js';
import { fetchPage } from './http.js';

export interface ProbeResult {
  status: number;
  body: string;
  headers: Record<string, string>;
}

/**
 * Paths always fetched because they are part of the normal public surface of a site and
 * cost one cheap GET each. Anything more invasive has to be requested explicitly.
 */
const BASELINE_PATHS = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/humans.txt'];

/**
 * Request the well-known paths referenced by the fingerprint database, plus a baseline set.
 *
 * Only paths that some fingerprint actually asks about are fetched, so adding a probe to a
 * fingerprint is what turns the request on. This keeps the request count proportional to
 * the database rather than growing with every idea anyone ever had.
 */
export async function runProbes(
  baseUrl: string,
  fingerprints: Fingerprint[],
  opts: AnalyzeOptions,
): Promise<Record<string, ProbeResult>> {
  const wanted = new Set<string>(BASELINE_PATHS);
  for (const fp of fingerprints) {
    for (const probe of fp.probe ?? []) {
      if (probe.intrusive && !opts.intrusiveProbes) continue;
      wanted.add(probe.path);
    }
  }

  const origin = new URL(baseUrl).origin;
  const results: Record<string, ProbeResult> = {};
  const paths = [...wanted];
  const CONCURRENCY = 6;

  for (let i = 0; i < paths.length; i += CONCURRENCY) {
    const slice = paths.slice(i, i + CONCURRENCY);
    await Promise.all(
      slice.map(async (path) => {
        try {
          const res = await fetchPage(origin + path, { ...opts, timeout: Math.min(opts.timeout ?? 15000, 8000) });
          results[path] = {
            status: res.status,
            // Cap the body: error pages and sitemaps can be enormous and we only need the head.
            body: res.body.slice(0, 60_000),
            headers: res.headers,
          };
        } catch {
          // A failed probe is simply an absent signal.
        }
      }),
    );
  }

  return results;
}
