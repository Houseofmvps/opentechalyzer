import type { AnalyzeOptions } from '../types.js';
import { absolutise, fetchPage } from './http.js';

/**
 * Recover dependency names from sourcemaps and bundle contents.
 *
 * This is the single highest-value signal available, and the one commercial detectors
 * largely ignore. A sourcemap's `sources` array contains the original module paths, so
 * `node_modules/@tanstack/react-query/...` proves the dependency outright rather than
 * inferring it from a minified side effect. Most teams ship maps unintentionally, either
 * by leaving them on in production or by referencing them from a `sourceMappingURL`.
 *
 * When no map is available we fall back to scanning the bundle for bare specifiers and
 * webpack module paths, which still recovers a useful subset.
 */
export async function collectNpmDeps(
  scriptSrcs: string[],
  baseUrl: string,
  opts: AnalyzeOptions,
): Promise<{ deps: string[]; warnings: string[] }> {
  const deps = new Set<string>();
  const warnings: string[] = [];
  const origin = new URL(baseUrl).origin;

  // Only inspect first-party bundles. Third-party CDN scripts identify themselves by URL
  // already, and fetching them would waste the budget on vendor code we can name anyway.
  const candidates = scriptSrcs
    .filter((s) => {
      try {
        return new URL(s, baseUrl).origin === origin;
      } catch {
        return false;
      }
    })
    .filter((s) => /\.[cm]?js(\?|$)/i.test(s))
    .slice(0, opts.maxBundles ?? 8);

  if (candidates.length === 0) return { deps: [], warnings: [] };

  await Promise.all(
    candidates.map(async (src) => {
      try {
        const res = await fetchPage(absolutise(src, baseUrl), {
          ...opts,
          timeout: Math.min(opts.timeout ?? 15000, 10_000),
        });
        if (res.status !== 200 || !res.body) return;
        const bundle = res.body;

        // 1. Follow an explicit sourceMappingURL if present.
        const mapRef = bundle.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
        let mapText: string | null = null;
        if (mapRef?.[1] && !mapRef[1].startsWith('data:')) {
          const mapUrl = absolutise(mapRef[1], src);
          const mapRes = await fetchPage(mapUrl, { ...opts, timeout: 10_000 });
          if (mapRes.status === 200 && mapRes.body.trimStart().startsWith('{')) {
            mapText = mapRes.body;
          }
        } else if (mapRef?.[1]?.startsWith('data:')) {
          const b64 = mapRef[1].split(',')[1];
          if (b64) {
            try {
              mapText = Buffer.from(b64, 'base64').toString('utf8');
            } catch {
              /* malformed inline map */
            }
          }
        } else {
          // 2. Try the conventional sibling path even when unreferenced.
          const guess = `${src.split('?')[0]}.map`;
          const mapRes = await fetchPage(guess, { ...opts, timeout: 6000 });
          if (mapRes.status === 200 && mapRes.body.trimStart().startsWith('{')) {
            mapText = mapRes.body;
            warnings.push(`Sourcemap exposed at ${guess}`);
          }
        }

        if (mapText) {
          try {
            const map = JSON.parse(mapText) as { sources?: string[] };
            for (const source of map.sources ?? []) {
              for (const name of packagesFromPath(source)) deps.add(name);
            }
          } catch {
            /* not valid JSON */
          }
        }

        // 3. Always also scan the bundle body: webpack and Vite leave module paths behind
        //    in comments and in the module map even without a sourcemap.
        for (const m of bundle.matchAll(/node_modules\/((?:@[\w.-]+\/)?[\w.-]+)/g)) {
          const name = m[1];
          if (name) deps.add(name);
        }
      } catch {
        /* unreachable bundle is just an absent signal */
      }
    }),
  );

  return { deps: [...deps], warnings };
}

/** Pull package names out of a sourcemap `sources` entry. */
function packagesFromPath(path: string): string[] {
  const out: string[] = [];
  for (const m of path.matchAll(/node_modules\/((?:@[\w.-]+\/)?[\w.-]+)/g)) {
    if (m[1]) out.push(m[1]);
  }
  // Vite and Rollup rewrite bare specifiers without node_modules for externalised deps.
  const bare = path.match(/^(?:\.\.\/)*((?:@[\w.-]+\/)?[\w.-]+)\/(?:dist|es|lib|esm|src)\//);
  if (bare?.[1]) out.push(bare[1]);
  return out;
}
