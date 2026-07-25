import { Resolver } from 'node:dns/promises';
import { collectCertSubdomains } from '../collect/certs.js';
import type { AnalyzeOptions } from '../types.js';

export interface SubdomainResult {
  domain: string;
  subdomains: Array<{ host: string; resolves: boolean; addresses?: string[]; source: string[] }>;
  total: number;
  sources: string[];
  warnings: string[];
}

/**
 * Common subdomain labels, grouped by what finding them tells you.
 *
 * Certificate transparency is the primary source and finds far more than any wordlist, but it
 * misses hosts that were never issued a public certificate: internal services behind a
 * wildcard, or hosts using a private CA. The wordlist covers that gap cheaply.
 */
const COMMON_LABELS = [
  // public-facing
  'www', 'app', 'api', 'admin', 'shop', 'store', 'blog', 'news', 'docs', 'help', 'support',
  'status', 'cdn', 'assets', 'static', 'img', 'images', 'media', 'files', 'download',
  'mail', 'webmail', 'smtp', 'imap', 'mx', 'email', 'go', 'link', 'links',
  'login', 'auth', 'sso', 'id', 'account', 'accounts', 'my', 'portal', 'dashboard',
  'checkout', 'pay', 'payments', 'billing', 'invoice',
  // environments
  'dev', 'test', 'stage', 'staging', 'uat', 'qa', 'demo', 'sandbox', 'preview', 'beta', 'alpha',
  // internal tooling, the highest-value finds for recon
  'git', 'gitlab', 'jenkins', 'ci', 'build', 'grafana', 'metrics', 'monitor', 'monitoring',
  'kibana', 'logs', 'sentry', 'metabase', 'analytics', 'bi', 'data', 'warehouse', 'airflow',
  'vault', 'consul', 'nomad', 'k8s', 'argocd', 'rancher', 'portainer', 'jira', 'confluence',
  'wiki', 'vpn', 'remote', 'ssh', 'bastion', 'jump', 'proxy', 'ns1', 'ns2', 'db', 'redis',
  'internal', 'intranet', 'corp', 'partners', 'vendor', 'crm', 'erp',
];

/**
 * Discover subdomains for a domain.
 *
 * This is the parity feature for a commercial subdomain-finder endpoint, and it is one place
 * where the free approach is arguably stronger: certificate transparency is a complete public
 * log of every certificate ever issued, whereas a vendor dataset only contains hosts their
 * crawler happened to visit. The trade-off is that CT includes hosts that no longer resolve,
 * which is why each result is DNS-checked and labelled.
 */
export async function findSubdomains(
  domain: string,
  options: AnalyzeOptions & { wordlist?: boolean; resolve?: boolean; limit?: number } = {},
): Promise<SubdomainResult> {
  const apex = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '').toLowerCase();
  const limit = options.limit ?? 500;
  const warnings: string[] = [];
  const sources: string[] = [];
  const bySource = new Map<string, Set<string>>();

  const add = (host: string, source: string): void => {
    const clean = host.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    if (!clean.endsWith(apex) || clean === apex) return;
    const set = bySource.get(clean) ?? new Set<string>();
    set.add(source);
    bySource.set(clean, set);
  };

  // 1. Certificate transparency.
  const ct = await collectCertSubdomains(apex, options);
  warnings.push(...ct.warnings);
  if (ct.subdomains.length > 0) {
    sources.push('certificate-transparency');
    for (const host of ct.subdomains) add(host, 'ct');
  }

  // 2. Wordlist probing, on by default because it is cheap and catches what CT cannot.
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  if (options.wordlist !== false) {
    sources.push('wordlist');
    const CONCURRENCY = 24;
    for (let i = 0; i < COMMON_LABELS.length; i += CONCURRENCY) {
      const slice = COMMON_LABELS.slice(i, i + CONCURRENCY);
      await Promise.all(
        slice.map(async (label) => {
          const host = `${label}.${apex}`;
          try {
            const addresses = await resolver.resolve4(host);
            if (addresses.length > 0) add(host, 'wordlist');
          } catch {
            try {
              const cname = await resolver.resolveCname(host);
              if (cname.length > 0) add(host, 'wordlist');
            } catch {
              /* does not exist */
            }
          }
        }),
      );
    }
  }

  const hosts = [...bySource.keys()].sort().slice(0, limit);

  // 3. Resolve every candidate so dead CT entries are marked rather than silently included.
  const subdomains: SubdomainResult['subdomains'] = [];
  if (options.resolve !== false) {
    const CONCURRENCY = 24;
    for (let i = 0; i < hosts.length; i += CONCURRENCY) {
      const slice = hosts.slice(i, i + CONCURRENCY);
      await Promise.all(
        slice.map(async (host) => {
          let addresses: string[] = [];
          try {
            addresses = await resolver.resolve4(host);
          } catch {
            try {
              addresses = await resolver.resolveCname(host);
            } catch {
              addresses = [];
            }
          }
          const entry: SubdomainResult['subdomains'][number] = {
            host,
            resolves: addresses.length > 0,
            source: [...(bySource.get(host) ?? [])],
          };
          if (addresses.length > 0) entry.addresses = addresses.slice(0, 5);
          subdomains.push(entry);
        }),
      );
    }
  } else {
    for (const host of hosts) {
      subdomains.push({ host, resolves: false, source: [...(bySource.get(host) ?? [])] });
    }
  }

  subdomains.sort((a, b) => Number(b.resolves) - Number(a.resolves) || a.host.localeCompare(b.host));

  return { domain: apex, subdomains, total: subdomains.length, sources, warnings };
}
