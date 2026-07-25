import { createHash } from 'node:crypto';
import type { AnalyzeOptions } from '../types.js';
import { fetchBuffer } from './http.js';

/**
 * Hash /favicon.ico.
 *
 * A favicon hash is a strong identifier for self-hosted software, because almost nobody
 * replaces the default icon on a Grafana, Jenkins, Gitea, Metabase, phpMyAdmin or Plex
 * install. It is the same signal Shodan indexes hosts by, and it identifies products that
 * emit no other client-side fingerprint at all.
 */
export async function faviconHash(baseUrl: string, opts: AnalyzeOptions): Promise<string | undefined> {
  const origin = new URL(baseUrl).origin;
  const bytes = await fetchBuffer(`${origin}/favicon.ico`, {
    ...opts,
    timeout: Math.min(opts.timeout ?? 15000, 6000),
  });
  if (!bytes || bytes.length === 0) return undefined;
  // Guard against SPA catch-all routes returning index.html for every unknown path.
  const head = Buffer.from(bytes.slice(0, 200)).toString('utf8').toLowerCase();
  if (head.includes('<!doctype html') || head.includes('<html')) return undefined;
  return createHash('md5').update(bytes).digest('hex');
}
