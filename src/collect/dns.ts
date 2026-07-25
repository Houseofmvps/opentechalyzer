import { Resolver } from 'node:dns/promises';

export interface DnsRecords {
  txt: string[];
  mx: string[];
  cname: string[];
  ns: string[];
  a: string[];
}

const EMPTY: DnsRecords = { txt: [], mx: [], cname: [], ns: [], a: [] };

/**
 * Resolve the DNS records that carry stack signal.
 *
 * TXT is the richest: SPF `include:` directives enumerate every service allowed to send
 * mail as the domain (Klaviyo, SendGrid, Salesforce...), and vendor verification tokens
 * name SaaS the site never references in its HTML. MX identifies the mail provider
 * outright. NS identifies the DNS host, which often implies the wider platform.
 *
 * Records are looked up for both the apex and the requested hostname, because `www` is
 * usually a CNAME to the platform while the apex holds the TXT records.
 */
export async function resolveDns(hostname: string, apex: string, timeoutMs = 8000): Promise<DnsRecords> {
  const resolver = new Resolver({ timeout: Math.min(timeoutMs, 5000), tries: 2 });
  const out: DnsRecords = { txt: [], mx: [], cname: [], ns: [], a: [] };

  const settle = async <T>(p: Promise<T>): Promise<T | null> => {
    try {
      return await p;
    } catch {
      return null;
    }
  };

  const hosts = [...new Set([hostname, apex])];

  const tasks = hosts.flatMap((host) => [
    settle(resolver.resolveTxt(host)).then((r) => {
      if (r) out.txt.push(...r.map((chunks) => chunks.join('')));
    }),
    settle(resolver.resolveMx(host)).then((r) => {
      if (r) out.mx.push(...r.map((x) => x.exchange));
    }),
    settle(resolver.resolveCname(host)).then((r) => {
      if (r) out.cname.push(...r);
    }),
    settle(resolver.resolveNs(host)).then((r) => {
      if (r) out.ns.push(...r);
    }),
    settle(resolver.resolve4(host)).then((r) => {
      if (r) out.a.push(...r);
    }),
  ]);

  const guard = new Promise<void>((resolve) => setTimeout(resolve, timeoutMs));
  await Promise.race([Promise.allSettled(tasks), guard]);

  return {
    txt: [...new Set(out.txt)],
    mx: [...new Set(out.mx)],
    cname: [...new Set(out.cname)],
    ns: [...new Set(out.ns)],
    a: [...new Set(out.a)],
  };
}

export { EMPTY as EMPTY_DNS };
