import type { AnalyzeOptions } from '../types.js';

/**
 * Enumerate subdomains from certificate transparency logs via crt.sh.
 *
 * Every publicly trusted certificate is logged, so CT is a complete public record of the
 * subdomains an organisation has ever requested a certificate for. That exposes internal
 * tooling nothing on the marketing site references: `grafana.`, `sentry.`, `metabase.`,
 * `argocd.`, `jenkins.`, `vault.`, and the SaaS-hosted subdomains vendors provision.
 *
 * This is opt-in because crt.sh is a single volunteer-run service that is frequently slow,
 * and hammering it on every scan would be rude.
 */
export async function collectCertSubdomains(
  apex: string,
  opts: AnalyzeOptions,
): Promise<{ subdomains: string[]; warnings: string[] }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(opts.timeout ?? 15_000, 20_000));
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(`%.${apex}`)}&output=json&exclude=expired`,
      {
        signal: controller.signal,
        headers: { 'user-agent': 'Opentechalyzer/0.1 (+https://github.com/Houseofmvps/opentechalyzer)' },
      },
    );
    if (!res.ok) {
      return { subdomains: [], warnings: [`crt.sh returned ${res.status}; subdomain signals skipped`] };
    }
    const rows = (await res.json()) as Array<{ name_value?: string }>;
    const names = new Set<string>();
    for (const row of rows) {
      for (const name of (row.name_value ?? '').split('\n')) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, '');
        if (clean.endsWith(apex)) names.add(clean);
      }
    }
    return { subdomains: [...names], warnings: [] };
  } catch (err) {
    const reason = err instanceof Error && err.name === 'AbortError' ? 'timed out' : 'failed';
    return { subdomains: [], warnings: [`crt.sh lookup ${reason}; subdomain signals skipped`] };
  } finally {
    clearTimeout(timer);
  }
}
