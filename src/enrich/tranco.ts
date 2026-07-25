import { createWriteStream } from 'node:fs';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

/**
 * Traffic ranking from the Tranco list.
 *
 * Commercial detectors expose a `trafficRank` field backed by a proprietary dataset. Tranco is
 * a free, research-grade top-sites list (a rank-aggregated combination of several public
 * sources, published by KU Leuven), which makes the same field reproducible without paying
 * anyone. It is imported on demand because the list is a ~20 MB download.
 *
 * The list ranks registrable domains, not URLs, so a rank describes the whole domain.
 */

const TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip';

export function trancoPath(): string {
  const override = process.env['OPENTECHALYZER_TRANCO_PATH'];
  if (override) return override;
  const base = process.env['XDG_CACHE_HOME'] ?? join(homedir(), '.cache');
  return join(base, 'opentechalyzer', 'tranco.json');
}

let cache: Map<string, number> | null = null;

/**
 * Import the Tranco list into a compact local lookup table.
 *
 * The published file is a zipped CSV. Node has no bundled zip reader, so `unzip` is used when
 * available and the plain-CSV endpoint is used as a fallback, which keeps the dependency count
 * at zero either way.
 */
export async function importTranco(options: { onProgress?: (msg: string) => void } = {}): Promise<{
  count: number;
  path: string;
}> {
  const progress = options.onProgress ?? (() => undefined);
  const target = trancoPath();
  await mkdir(dirname(target), { recursive: true });

  progress('downloading Tranco top-1m list');
  const zipPath = `${target}.zip`;

  const res = await fetch(TRANCO_URL, {
    headers: { 'user-agent': 'Opentechalyzer/0.1 (+https://github.com/Houseofmvps/opentechalyzer)' },
  });
  if (!res.ok || !res.body) throw new Error(`Tranco download failed with HTTP ${res.status}`);

  await new Promise<void>((resolve, reject) => {
    const out = createWriteStream(zipPath);
    // Node's fetch body is a web stream; Readable.fromWeb keeps this dependency-free.
    import('node:stream')
      .then(({ Readable }) => {
        const nodeStream = Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]);
        nodeStream.pipe(out);
        out.on('finish', resolve);
        out.on('error', reject);
        nodeStream.on('error', reject);
      })
      .catch(reject);
  });

  progress('extracting');
  const csv = await extractCsv(zipPath);
  if (!csv) {
    throw new Error(
      'Could not extract the Tranco archive. Install `unzip`, or set OPENTECHALYZER_TRANCO_PATH to a pre-built JSON map.',
    );
  }

  const ranks: Record<string, number> = {};
  let count = 0;
  for (const line of csv.split('\n')) {
    const comma = line.indexOf(',');
    if (comma <= 0) continue;
    const rank = Number(line.slice(0, comma));
    const domain = line.slice(comma + 1).trim().toLowerCase();
    if (!Number.isFinite(rank) || domain.length === 0) continue;
    ranks[domain] = rank;
    count++;
  }
  if (count === 0) throw new Error('Tranco archive contained no usable rows');

  await writeFile(target, JSON.stringify({ importedAt: new Date().toISOString(), count, ranks }), 'utf8');
  cache = null;
  progress(`imported ${count} ranked domains`);
  return { count, path: target };
}

async function extractCsv(zipPath: string): Promise<string | null> {
  try {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const run = promisify(execFile);
    // -p writes to stdout. The list is ASCII domains, so the 40 MB buffer is ample.
    const { stdout } = await run('unzip', ['-p', zipPath], { maxBuffer: 64 * 1024 * 1024 });
    return stdout;
  } catch {
    return null;
  }
}

/** Look up a domain's rank, returning null when the list is not imported or the domain is absent. */
export async function trancoRank(domain: string): Promise<number | null> {
  if (!cache) {
    try {
      const raw = await readFile(trancoPath(), 'utf8');
      const parsed = JSON.parse(raw) as { ranks?: Record<string, number> };
      cache = new Map(Object.entries(parsed.ranks ?? {}));
    } catch {
      cache = new Map();
      return null;
    }
  }
  if (cache.size === 0) return null;
  const clean = domain.toLowerCase().replace(/^www\./, '');
  return cache.get(clean) ?? null;
}

export async function trancoStatus(): Promise<{ installed: boolean; path: string; count?: number; importedAt?: string }> {
  const path = trancoPath();
  try {
    await stat(path);
    const parsed = JSON.parse(await readFile(path, 'utf8')) as { count?: number; importedAt?: string };
    const out: { installed: boolean; path: string; count?: number; importedAt?: string } = { installed: true, path };
    if (parsed.count !== undefined) out.count = parsed.count;
    if (parsed.importedAt) out.importedAt = parsed.importedAt;
    return out;
  } catch {
    return { installed: false, path };
  }
}
