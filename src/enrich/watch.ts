import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { AnalyzeResult } from '../types.js';

/**
 * Technology change tracking, the self-hosted equivalent of a website-alerts product.
 *
 * A snapshot of each scan is stored locally, and a later scan is diffed against it. This is
 * what turns a point-in-time detector into a monitoring tool: a competitor adding Klaviyo or
 * dropping Shopify Plus is a buying signal, and a dependency version changing is a security
 * signal, but neither is visible from a single scan.
 *
 * Snapshots live in the user's own cache directory. Nothing is transmitted anywhere, which is
 * the difference between this and a hosted alerting service.
 */

export interface Snapshot {
  url: string;
  capturedAt: string;
  technologies: Array<{ name: string; version?: string; confidence: number; categories: string[] }>;
  meta?: { title?: string; ip?: string };
}

export interface TechChange {
  name: string;
  categories: string[];
  change: 'added' | 'removed' | 'version-changed';
  from?: string;
  to?: string;
}

export interface DiffResult {
  url: string;
  previousAt?: string;
  currentAt: string;
  changes: TechChange[];
  unchanged: number;
  isFirstRun: boolean;
}

function snapshotDir(): string {
  const override = process.env['OPENTECHALYZER_SNAPSHOT_DIR'];
  if (override) return override;
  const base = process.env['XDG_DATA_HOME'] ?? join(homedir(), '.local', 'share');
  return join(base, 'opentechalyzer', 'snapshots');
}

function snapshotPath(url: string): string {
  // A hash keeps the filename stable and filesystem-safe regardless of URL shape, and the
  // hostname prefix keeps the directory browsable by a human.
  let host = 'unknown';
  try {
    host = new URL(url).hostname.replace(/[^a-z0-9.-]/gi, '_');
  } catch {
    /* keep the fallback */
  }
  const hash = createHash('sha256').update(url).digest('hex').slice(0, 12);
  return join(snapshotDir(), `${host}-${hash}.json`);
}

export function toSnapshot(result: AnalyzeResult): Snapshot {
  const seen = new Set<string>();
  const technologies: Snapshot['technologies'] = [];
  for (const det of result.detections) {
    if (det.inferred || seen.has(det.name)) continue;
    seen.add(det.name);
    const entry: Snapshot['technologies'][number] = {
      name: det.name,
      confidence: det.confidence,
      categories: det.categories,
    };
    if (det.version) entry.version = det.version;
    technologies.push(entry);
  }
  const snapshot: Snapshot = {
    url: result.finalUrl,
    capturedAt: result.analyzedAt,
    technologies: technologies.sort((a, b) => a.name.localeCompare(b.name)),
  };
  const meta: { title?: string; ip?: string } = {};
  if (result.meta.title) meta.title = result.meta.title;
  if (result.meta.ip) meta.ip = result.meta.ip;
  if (Object.keys(meta).length > 0) snapshot.meta = meta;
  return snapshot;
}

export async function loadSnapshot(url: string): Promise<Snapshot | null> {
  try {
    return JSON.parse(await readFile(snapshotPath(url), 'utf8')) as Snapshot;
  } catch {
    return null;
  }
}

export async function saveSnapshot(snapshot: Snapshot): Promise<string> {
  const path = snapshotPath(snapshot.url);
  await mkdir(snapshotDir(), { recursive: true });
  await writeFile(path, JSON.stringify(snapshot, null, 2), 'utf8');
  return path;
}

/**
 * Compare a fresh result against the stored snapshot.
 *
 * Detections below 50% confidence are ignored for change purposes. Without that floor, normal
 * confidence jitter between scans would generate a stream of phantom added/removed alerts,
 * which is the fastest way to make a monitoring tool useless.
 */
export function diffSnapshots(previous: Snapshot | null, current: Snapshot): DiffResult {
  const CHANGE_FLOOR = 50;
  const out: DiffResult = {
    url: current.url,
    currentAt: current.capturedAt,
    changes: [],
    unchanged: 0,
    isFirstRun: previous === null,
  };
  if (!previous) return out;
  out.previousAt = previous.capturedAt;

  const prev = new Map(
    previous.technologies.filter((t) => t.confidence >= CHANGE_FLOOR).map((t) => [t.name, t]),
  );
  const curr = new Map(
    current.technologies.filter((t) => t.confidence >= CHANGE_FLOOR).map((t) => [t.name, t]),
  );

  for (const [name, tech] of curr) {
    const before = prev.get(name);
    if (!before) {
      out.changes.push({ name, categories: tech.categories, change: 'added' });
    } else if (before.version !== tech.version && (before.version ?? tech.version)) {
      const change: TechChange = { name, categories: tech.categories, change: 'version-changed' };
      if (before.version) change.from = before.version;
      if (tech.version) change.to = tech.version;
      out.changes.push(change);
    } else {
      out.unchanged++;
    }
  }
  for (const [name, tech] of prev) {
    if (!curr.has(name)) out.changes.push({ name, categories: tech.categories, change: 'removed' });
  }

  out.changes.sort((a, b) => a.change.localeCompare(b.change) || a.name.localeCompare(b.name));
  return out;
}

/** List every URL currently being watched. */
export async function listWatched(): Promise<Array<{ url: string; capturedAt: string; count: number }>> {
  try {
    const files = await readdir(snapshotDir());
    const out: Array<{ url: string; capturedAt: string; count: number }> = [];
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const snapshot = JSON.parse(await readFile(join(snapshotDir(), file), 'utf8')) as Snapshot;
        out.push({
          url: snapshot.url,
          capturedAt: snapshot.capturedAt,
          count: snapshot.technologies.length,
        });
      } catch {
        /* skip unreadable snapshot */
      }
    }
    return out.sort((a, b) => a.url.localeCompare(b.url));
  } catch {
    return [];
  }
}

export { snapshotDir };
