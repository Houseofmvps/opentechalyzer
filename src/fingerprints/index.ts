import type { Fingerprint } from '../types.js';
import { analytics, advertising } from './analytics.js';
import { commerceApps, conversion, payments } from './commerce.js';
import { backend, frameworks, servers } from './frameworks.js';
import { globalPayments, globalPlatforms, logistics, merchantGrowth, shopifyApps } from './ecommerce-global.js';
import { dnsProviders, infrastructure, mail } from './infrastructure.js';
import { fonts, libraries, media, misc, ui } from './libraries.js';
import { platforms } from './platforms.js';
import { selfHosted } from './selfhosted.js';
import { auth, data, marketing, observability, search, security, support } from './services.js';
import { loadExternalDatabase } from './external.js';

export const DATABASE_VERSION = '0.2.0';

/**
 * The built-in fingerprint database, authored for this project and MIT licensed.
 *
 * Coverage is deliberately concentrated on technologies that actually show up in the wild
 * rather than padded for a headline count. For long-tail coverage, `loadExternalDatabase`
 * can merge in a community dataset at runtime.
 */
export const BUILTIN_FINGERPRINTS: Fingerprint[] = [
  ...platforms,
  ...frameworks,
  ...backend,
  ...servers,
  ...infrastructure,
  ...mail,
  ...dnsProviders,
  ...analytics,
  ...advertising,
  ...payments,
  ...commerceApps,
  ...conversion,
  ...globalPlatforms,
  ...shopifyApps,
  ...globalPayments,
  ...logistics,
  ...merchantGrowth,
  ...auth,
  ...data,
  ...search,
  ...observability,
  ...support,
  ...marketing,
  ...security,
  ...ui,
  ...libraries,
  ...media,
  ...fonts,
  ...misc,
  ...selfHosted,
];

let cache: Fingerprint[] | null = null;

/**
 * Return the active fingerprint set: the built-in database, plus any imported external
 * database, with built-ins taking precedence on name collisions.
 */
export async function getFingerprints(options: { external?: boolean } = {}): Promise<Fingerprint[]> {
  if (cache && options.external !== false) return cache;

  const merged = new Map<string, Fingerprint>();

  if (options.external !== false) {
    const external = await loadExternalDatabase();
    for (const fp of external) merged.set(fp.name.toLowerCase(), fp);
  }
  // Built-ins are applied last so a curated definition always wins over an imported one.
  for (const fp of BUILTIN_FINGERPRINTS) merged.set(fp.name.toLowerCase(), fp);

  const result = [...merged.values()];
  if (options.external !== false) cache = result;
  return result;
}

/** Reset the cache. Used by tests and after importing a new external database. */
export function clearFingerprintCache(): void {
  cache = null;
}

/** Every category present in the built-in database, for CLI help and validation. */
export function listCategories(): string[] {
  const set = new Set<string>();
  for (const fp of BUILTIN_FINGERPRINTS) for (const c of fp.categories) set.add(c);
  return [...set].sort();
}
