import kleur from 'kleur';
import type { AnalyzeResult, Category, Detection } from '../types.js';

/**
 * Display order for categories.
 *
 * Ordered by what a reader actually wants first: the platform decision, then how it is
 * served, then what it is built with, then the bolted-on services. Anything not listed
 * here is appended alphabetically, so adding a category never silently hides it.
 */
const CATEGORY_ORDER: Category[] = [
  'platform',
  'cms',
  'ecommerce',
  'static-site-generator',
  'js-framework',
  'backend-framework',
  'language',
  'runtime',
  'web-server',
  'hosting',
  'paas',
  'cdn',
  'database',
  'baas',
  'ui-framework',
  'css-framework',
  'js-library',
  'build-tool',
  'auth',
  'payment',
  'subscription',
  'ecommerce-app',
  'reviews',
  'loyalty',
  'shipping',
  'search',
  'analytics',
  'product-analytics',
  'tag-manager',
  'advertising',
  'marketing-automation',
  'email',
  'crm',
  'support',
  'chat',
  'apm',
  'error-tracking',
  'feature-flags',
  'ab-testing',
  'personalisation',
  'cookie-consent',
  'security',
  'captcha',
  'bot-protection',
  'media',
  'video',
  'maps',
  'font',
  'translation',
  'accessibility',
  'documentation',
  'devops',
  'mail-provider',
  'ai',
  'misc',
];

const CATEGORY_LABELS: Partial<Record<Category, string>> = {
  cms: 'CMS',
  ecommerce: 'Ecommerce platform',
  'ecommerce-app': 'Ecommerce apps',
  'static-site-generator': 'Static site generator',
  'js-framework': 'JavaScript framework',
  'backend-framework': 'Backend framework',
  'ui-framework': 'UI framework',
  'css-framework': 'CSS framework',
  'js-library': 'JavaScript libraries',
  'web-server': 'Web server',
  paas: 'PaaS',
  cdn: 'CDN',
  baas: 'Backend as a service',
  'build-tool': 'Build tooling',
  'tag-manager': 'Tag manager',
  'product-analytics': 'Product analytics',
  'marketing-automation': 'Marketing automation',
  crm: 'CRM',
  apm: 'APM',
  'error-tracking': 'Error tracking',
  'feature-flags': 'Feature flags',
  'ab-testing': 'A/B testing',
  'cookie-consent': 'Cookie consent',
  captcha: 'CAPTCHA',
  'bot-protection': 'Bot protection',
  'mail-provider': 'Email provider',
  ai: 'AI',
  misc: 'Other',
};

function label(category: Category): string {
  return (
    CATEGORY_LABELS[category] ??
    category.charAt(0).toUpperCase() + category.slice(1).replace(/-/g, ' ')
  );
}

function orderedCategories(byCategory: Partial<Record<Category, Detection[]>>): Category[] {
  const present = Object.keys(byCategory) as Category[];
  const known = CATEGORY_ORDER.filter((c) => present.includes(c));
  const unknown = present.filter((c) => !CATEGORY_ORDER.includes(c)).sort();
  return [...known, ...unknown];
}

function confidenceColour(confidence: number): (s: string) => string {
  if (confidence >= 85) return kleur.green;
  if (confidence >= 60) return kleur.yellow;
  return kleur.gray;
}

/**
 * Deduplicate a technology across categories for the flat listing, while keeping it visible
 * under each category it belongs to in the grouped view.
 */
function uniqueByName(detections: Detection[]): Detection[] {
  const seen = new Set<string>();
  return detections.filter((d) => {
    if (seen.has(d.name)) return false;
    seen.add(d.name);
    return true;
  });
}

export interface FormatOptions {
  /** Show the evidence trail under each detection. */
  verbose?: boolean;
  /** Disable ANSI colour. */
  noColor?: boolean;
  /** Only these categories. */
  only?: Category[];
}

export function formatTerminal(result: AnalyzeResult, options: FormatOptions = {}): string {
  if (options.noColor) kleur.enabled = false;
  const lines: string[] = [];
  const bold = kleur.bold;

  lines.push('');
  lines.push(`${bold(kleur.cyan('Opentechalyzer'))}  ${kleur.gray(`db ${result.databaseVersion} · ${result.fingerprintCount} fingerprints`)}`);
  lines.push('');
  lines.push(`${bold('URL')}      ${result.finalUrl}`);
  if (result.finalUrl !== result.url) lines.push(`${bold('Requested')} ${kleur.gray(result.url)}`);
  lines.push(`${bold('Status')}   ${result.status}`);
  if (result.meta.title) lines.push(`${bold('Title')}    ${result.meta.title}`);
  if (result.meta.ip) lines.push(`${bold('IP')}       ${result.meta.ip}`);
  lines.push(`${bold('Found')}    ${uniqueByName(result.detections).length} technologies`);
  lines.push('');

  const categories = orderedCategories(result.byCategory).filter(
    (c) => !options.only || options.only.includes(c),
  );

  if (categories.length === 0) {
    lines.push(kleur.gray('  No technologies detected above the confidence threshold.'));
  }

  for (const category of categories) {
    const items = result.byCategory[category];
    if (!items || items.length === 0) continue;
    lines.push(`${bold(kleur.magenta(label(category)))}`);
    for (const det of [...items].sort((a, b) => b.confidence - a.confidence)) {
      const colour = confidenceColour(det.confidence);
      const version = det.version ? kleur.white(` ${det.version}`) : '';
      const ids = det.accountIds?.length ? kleur.cyan(` [${det.accountIds.join(', ')}]`) : '';
      const inferred = det.inferred ? kleur.gray(` (inferred from ${det.impliedBy})`) : '';
      const conf = colour(`${det.confidence.toFixed(0)}%`.padStart(4));
      lines.push(`  ${conf}  ${det.name}${version}${ids}${inferred}`);
      if (options.verbose) {
        for (const ev of det.evidence.slice(0, 6)) {
          if (ev.source === 'implied') continue;
          lines.push(kleur.gray(`         ${ev.source} · ${ev.subject} · ${ev.match}`));
        }
        if (det.description) lines.push(kleur.gray(`         ${det.description}`));
      }
    }
    lines.push('');
  }

  if (result.enrichment) lines.push(...enrichmentLines(result.enrichment, bold));

  if (result.crawledPages?.length) {
    lines.push(bold(kleur.magenta('Pages crawled')));
    for (const url of result.crawledPages) lines.push(kleur.gray(`  ${url}`));
    lines.push('');
  }

  if (result.warnings.length > 0) {
    lines.push(bold(kleur.yellow('Notes')));
    for (const w of result.warnings) lines.push(kleur.yellow(`  ! ${w}`));
    lines.push('');
  }

  const total = Object.values(result.timings).reduce((a, b) => a + b, 0);
  const stages = Object.entries(result.timings)
    .map(([k, v]) => `${k} ${v}ms`)
    .join(' · ');
  lines.push(kleur.gray(`Completed in ${total}ms  (${stages})`));
  lines.push('');

  return lines.join('\n');
}

/** Render the enrichment field sets, skipping anything that came back empty. */
function enrichmentLines(
  e: NonNullable<AnalyzeResult['enrichment']>,
  bold: (s: string) => string,
): string[] {
  const lines: string[] = [];
  const section = (title: string, rows: Array<[string, string | undefined]>): void => {
    const present = rows.filter(([, value]) => value && value.length > 0);
    if (present.length === 0) return;
    lines.push(bold(kleur.magenta(title)));
    for (const [label_, value] of present) {
      lines.push(`  ${kleur.gray(`${label_}:`.padEnd(18))}${value as string}`);
    }
    lines.push('');
  };
  const list = (values: string[] | undefined, max = 6): string | undefined =>
    values && values.length > 0
      ? values.slice(0, max).join(', ') + (values.length > max ? ` (+${values.length - max})` : '')
      : undefined;

  if (e.company) {
    section('Company', [
      ['name', e.company.companyName],
      ['inferred name', e.company.companyName ? undefined : e.company.inferredCompanyName],
      ['founded', e.company.companyFounded],
      ['locations', list(e.company.locations, 3)],
      ['about', e.company.about?.slice(0, 160)],
    ]);
  }
  if (e.contact) {
    section('Contact', [
      ['email', list(e.contact.email, 5)],
      ['phone', list(e.contact.phone, 4)],
      ['whatsapp', list(e.contact.whatsapp, 3)],
    ]);
  }
  if (e.social) {
    section('Social', [
      ['x', list(e.social.x, 3)],
      ['linkedin', list(e.social.linkedin, 3)],
      ['instagram', list(e.social.instagram, 3)],
      ['facebook', list(e.social.facebook, 3)],
      ['youtube', list(e.social.youtube, 2)],
      ['tiktok', list(e.social.tiktok, 2)],
      ['github', list(e.social.github, 3)],
      ['pinterest', list(e.social.pinterest, 2)],
    ]);
  }
  if (e.locale) {
    section('Locale', [
      ['language', e.locale.language],
      ['languages', list(e.locale.languages, 8)],
      ['country', e.locale.ipCountry],
      ['countries', list(e.locale.ipCountries, 6)],
      ['currencies', list(e.locale.currencies, 4)],
    ]);
  }
  if (e.security) {
    const c = e.security.certInfo;
    const expiry =
      c?.daysUntilExpiry !== undefined
        ? `${c.validTo?.slice(0, 10)} (${c.daysUntilExpiry} days)`
        : c?.validTo?.slice(0, 10);
    section('Security', [
      ['cert org', c?.subjectOrg],
      ['cert issuer', c?.issuer],
      ['cert country', c?.subjectCountry],
      ['tls', c?.protocol],
      ['cert expires', expiry],
      ['SPF', e.security.dns.spf ? 'present' : 'missing'],
      [
        'DMARC',
        e.security.dns.dmarc
          ? `present (p=${e.security.dns.dmarcPolicy ?? '?'})`
          : 'missing',
      ],
      ['DKIM', e.security.dns.dkim ? 'present' : undefined],
      ['CAA', e.security.dns.caa ? 'present' : undefined],
    ]);
  }
  if (e.signals) {
    section('Signals', [
      [
        'tech spend',
        `${e.signals.technologySpend} (floor ~$${e.signals.technologySpendMonthlyFloorUsd}/mo)`,
      ],
      ['spend drivers', list(e.signals.technologySpendDrivers, 5)],
      ['traffic rank', e.signals.trafficRank ? `#${e.signals.trafficRank}` : undefined],
      ['traffic level', e.signals.trafficLevel],
    ]);
  }
  if (e.meta) {
    section('Metadata', [
      ['copyright', e.meta.copyright?.slice(0, 80)],
      ['copyright year', e.meta.copyrightYear],
      ['schema.org', list(e.meta.schemaOrgTypes, 8)],
      ['keywords', list(e.meta.keywords, 12)],
    ]);
  }
  if (e.cpes?.length) {
    lines.push(bold(kleur.magenta('CPE identifiers')));
    lines.push(kleur.gray('  (use `ota cve <url>` to look these up against the NVD CVE database)'));
    for (const entry of e.cpes.slice(0, 12)) lines.push(kleur.gray(`  ${entry.cpe}`));
    lines.push('');
  }
  return lines;
}

export function formatMarkdown(result: AnalyzeResult, options: FormatOptions = {}): string {
  const lines: string[] = [];
  lines.push(`# Tech stack: ${new URL(result.finalUrl).hostname}`);
  lines.push('');
  lines.push(`- **URL:** ${result.finalUrl}`);
  lines.push(`- **Status:** ${result.status}`);
  if (result.meta.title) lines.push(`- **Title:** ${result.meta.title}`);
  if (result.meta.ip) lines.push(`- **IP:** ${result.meta.ip}`);
  lines.push(`- **Technologies found:** ${uniqueByName(result.detections).length}`);
  lines.push(`- **Analyzed:** ${result.analyzedAt}`);
  lines.push(`- **Database:** ${result.databaseVersion} (${result.fingerprintCount} fingerprints)`);
  lines.push('');

  for (const category of orderedCategories(result.byCategory)) {
    if (options.only && !options.only.includes(category)) continue;
    const items = result.byCategory[category];
    if (!items || items.length === 0) continue;
    lines.push(`## ${label(category)}`);
    lines.push('');
    lines.push('| Technology | Version | Account ID | Confidence | Evidence |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const det of [...items].sort((a, b) => b.confidence - a.confidence)) {
      const ev = det.inferred
        ? `inferred from ${det.impliedBy}`
        : det.evidence
            .slice(0, 2)
            .map((e) => `${e.source}: \`${e.match.replace(/\|/g, '\\|').slice(0, 60)}\``)
            .join('; ');
      const ids = det.accountIds?.join(', ') ?? '';
      lines.push(
        `| ${det.name} | ${det.version ?? ''} | ${ids} | ${det.confidence.toFixed(0)}% | ${ev} |`,
      );
    }
    lines.push('');
  }

  if (result.warnings.length > 0) {
    lines.push('## Notes');
    lines.push('');
    for (const w of result.warnings) lines.push(`- ${w}`);
    lines.push('');
  }

  return lines.join('\n');
}

export function formatCsv(results: AnalyzeResult[]): string {
  const rows: string[] = ['url,technology,categories,version,account_ids,confidence,inferred'];
  const esc = (s: string): string => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  for (const result of results) {
    for (const det of uniqueByName(result.detections)) {
      rows.push(
        [
          esc(result.finalUrl),
          esc(det.name),
          esc(det.categories.join('|')),
          esc(det.version ?? ''),
          esc(det.accountIds?.join('|') ?? ''),
          det.confidence.toFixed(0),
          String(det.inferred),
        ].join(','),
      );
    }
  }
  return rows.join('\n');
}

/**
 * A compact one-line-per-category summary, designed to be read by an LLM or pasted into
 * a ticket. Keeps only the highest-confidence detection per category.
 */
export function summarise(result: AnalyzeResult): string {
  const parts: string[] = [];
  for (const category of orderedCategories(result.byCategory)) {
    const items = result.byCategory[category];
    if (!items || items.length === 0) continue;
    const names = [...items]
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 4)
      .map((d) => {
        const version = d.version ? ` ${d.version}` : '';
        const ids = d.accountIds?.length ? ` [${d.accountIds.join(', ')}]` : '';
        return `${d.name}${version}${ids}`;
      });
    parts.push(`${label(category)}: ${names.join(', ')}`);
  }
  return parts.join('\n');
}
