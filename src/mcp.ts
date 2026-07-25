#!/usr/bin/env node
/**
 * Opentechalyzer MCP server.
 *
 * Exposes tech-stack detection over the Model Context Protocol on stdio, so any MCP client
 * (Claude Code, Claude Desktop, Codex, Cursor, Windsurf, Zed, ChatGPT Developer Mode, or a
 * custom agent) can analyse a URL without shelling out.
 *
 * Install into Claude Code:
 *   claude mcp add opentechalyzer -- npx -y opentechalyzer-mcp
 *
 * Tool results are returned as text, because that is what every client renders reliably, and
 * as structured JSON alongside it for clients that support structured content. The text form
 * is written to be read by a model: grouped by category, confidence first, no ANSI codes.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { analyze, analyzeMany } from './analyze.js';
import { isRenderAvailable } from './collect/render.js';
import {
  EXTERNAL_DB_LICENSE_NOTICE,
  externalDatabaseStatus,
  importExternalDatabase,
} from './fingerprints/external.js';
import { BUILTIN_FINGERPRINTS, DATABASE_VERSION } from './fingerprints/index.js';
import { lookupCves } from './enrich/cve.js';
import { findSubdomains } from './enrich/subdomains.js';
import { trancoStatus } from './enrich/tranco.js';
import { verifyEmail } from './enrich/verify-email.js';
import { diffSnapshots, loadSnapshot, saveSnapshot, toSnapshot } from './enrich/watch.js';
import { formatMarkdown, summarise } from './report/format.js';
import type { AnalyzeResult, Category, Detection } from './types.js';

const VERSION = '0.1.0';

const server = new McpServer({ name: 'opentechalyzer', version: VERSION });

/** Compact JSON shape for structured output: everything a model needs, nothing it does not. */
function toStructured(result: AnalyzeResult): Record<string, unknown> {
  return {
    url: result.finalUrl,
    status: result.status,
    title: result.meta.title,
    ip: result.meta.ip,
    analyzedAt: result.analyzedAt,
    enrichment: result.enrichment,
    crawledPages: result.crawledPages,
    technologies: dedupe(result.detections).map((d) => ({
      name: d.name,
      categories: d.categories,
      version: d.version,
      accountIds: d.accountIds,
      confidence: d.confidence,
      inferred: d.inferred,
      impliedBy: d.impliedBy,
      website: d.website,
      evidence: d.evidence
        .filter((e) => e.source !== 'implied')
        .slice(0, 4)
        .map((e) => ({ source: e.source, subject: e.subject, match: e.match })),
    })),
    warnings: result.warnings,
  };
}

function dedupe(detections: Detection[]): Detection[] {
  const seen = new Set<string>();
  return detections.filter((d) => (seen.has(d.name) ? false : (seen.add(d.name), true)));
}

/**
 * Render a result as plain text for the model.
 *
 * Deliberately not the terminal formatter: no colour codes, and evidence is included so the
 * model can tell the user *why* something was detected instead of asserting it blindly.
 */
function toText(result: AnalyzeResult, verbose: boolean): string {
  const lines: string[] = [];
  lines.push(`Tech stack for ${result.finalUrl} (HTTP ${result.status})`);
  if (result.meta.title) lines.push(`Title: ${result.meta.title}`);
  if (result.meta.ip) lines.push(`IP: ${result.meta.ip}`);
  lines.push(`${dedupe(result.detections).length} technologies detected.`);
  lines.push('');
  lines.push(summarise(result));

  if (verbose) {
    lines.push('');
    lines.push('Evidence:');
    for (const det of dedupe(result.detections)) {
      const ev = det.inferred
        ? `inferred from ${det.impliedBy}`
        : det.evidence
            .filter((e) => e.source !== 'implied')
            .slice(0, 3)
            .map((e) => `${e.source}(${e.subject})="${e.match}"`)
            .join(', ');
      lines.push(`- ${det.name}${det.version ? ` ${det.version}` : ''} [${det.confidence.toFixed(0)}%]: ${ev}`);
    }
  }

  if (result.warnings.length > 0) {
    lines.push('');
    lines.push('Caveats:');
    for (const w of result.warnings) lines.push(`- ${w}`);
  }

  lines.push('');
  lines.push(
    'Note: this reflects only what is observable from the client side. Backend language, database, ' +
      'ERP and internal services generally leave no public fingerprint and are not reported here.',
  );
  return lines.join('\n');
}

const commonInput = {
  render: z
    .boolean()
    .optional()
    .describe(
      'Render the page in a headless browser before matching. Finds roughly twice as many technologies (tag-manager-injected pixels, widgets, framework globals) but is slower and requires playwright to be installed. Default false.',
    ),
  sourcemaps: z
    .boolean()
    .optional()
    .describe(
      'Download first-party JS bundles and their sourcemaps to recover exact npm dependency names. Very high precision for frontend stacks. Default false.',
    ),
  certs: z
    .boolean()
    .optional()
    .describe(
      'Query certificate transparency logs for subdomains, which can reveal internal tooling. Slow. Default false.',
    ),
  crawl: z
    .union([z.boolean(), z.number().min(1).max(20)])
    .optional()
    .describe(
      'Follow internal links for deeper coverage (true = 5 pages, or give a page budget). Essential for ecommerce: checkout, review and payment scripts only load on inner pages. Also required to find contact details and social handles, which are almost never on the homepage.',
    ),
  fields: z
    .array(z.enum(['meta', 'company', 'contact', 'social', 'signals', 'locale', 'security', 'keywords', 'all']))
    .optional()
    .describe(
      'Enrichment field sets to include. "contact" returns emails/phones/WhatsApp, "social" returns handles, "company" returns name/locations/founded, "security" returns TLS certificate plus SPF/DMARC/DKIM, "signals" returns an estimated technology spend and traffic rank, "locale" returns language and country, "meta" returns copyright and schema.org types, "keywords" returns content keywords. Use ["all"] for everything. Pair with crawl:true for best contact coverage.',
    ),
  minConfidence: z
    .number()
    .min(0)
    .max(100)
    .optional()
    .describe('Minimum confidence to report, 0-100. Default 25.'),
  categories: z
    .array(z.string())
    .optional()
    .describe(
      'Restrict the report to these categories, e.g. ["cms","payment","analytics"]. Omit for everything.',
    ),
  timeout: z.number().optional().describe('Per-request timeout in milliseconds. Default 15000.'),
};

server.registerTool(
  'detect_tech_stack',
  {
    title: 'Detect website tech stack',
    description:
      'Identify the technologies powering any public website or web app from its URL: CMS or ecommerce platform, ' +
      'JS framework, backend framework, web server, hosting and CDN, analytics, advertising pixels, payment ' +
      'processors, auth providers, support and chat widgets, CSS and UI frameworks, JS libraries, fonts, CDNs, ' +
      'mail provider and DNS host. Every detection includes a confidence score and the evidence behind it. ' +
      'Free and open source, no API key and no third-party service. Prefer render:true when the user wants ' +
      'completeness and sourcemaps:true when they care about exact frontend dependency versions.',
    inputSchema: {
      url: z.string().describe('The URL or bare domain to analyse, e.g. "stripe.com" or "https://example.com/pricing".'),
      verbose: z
        .boolean()
        .optional()
        .describe('Include the evidence trail for each detection in the text output. Default true.'),
      ...commonInput,
    },
  },
  async ({ url, verbose, render, sourcemaps, certs, crawl, fields, minConfidence, categories, timeout }) => {
    const result = await analyze(url, {
      render: render ?? false,
      sourcemaps: sourcemaps ?? false,
      certs: certs ?? false,
      crawl: crawl ?? false,
      ...(fields?.length ? { fields } : {}),
      minConfidence: minConfidence ?? 25,
      timeout: timeout ?? 15_000,
    });

    const filtered = categories?.length
      ? filterByCategories(result, categories as Category[])
      : result;

    return {
      content: [{ type: 'text' as const, text: toText(filtered, verbose ?? true) }],
      structuredContent: toStructured(filtered),
    };
  },
);

server.registerTool(
  'detect_tech_stack_batch',
  {
    title: 'Detect tech stacks for many URLs',
    description:
      'Analyse up to 25 URLs concurrently and return the technology stack of each. Use this for competitive ' +
      'sweeps, vendor audits, portfolio reviews or lead qualification, instead of calling detect_tech_stack ' +
      'repeatedly. Returns a compact per-URL summary; call detect_tech_stack on a single URL for full evidence.',
    inputSchema: {
      urls: z.array(z.string()).min(1).max(25).describe('URLs or bare domains to analyse.'),
      concurrency: z.number().min(1).max(10).optional().describe('Parallel scans. Default 5.'),
      ...commonInput,
    },
  },
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async ({ urls, concurrency, render, sourcemaps, certs, crawl, fields, minConfidence, timeout }) => {
    const batch = await analyzeMany(urls, {
      concurrency: concurrency ?? 5,
      render: render ?? false,
      sourcemaps: sourcemaps ?? false,
      certs: certs ?? false,
      crawl: crawl ?? false,
      ...(fields?.length ? { fields } : {}),
      minConfidence: minConfidence ?? 25,
      timeout: timeout ?? 15_000,
    });

    const lines: string[] = [];
    for (const entry of batch) {
      if (entry.error) {
        lines.push(`## ${entry.url}\nFAILED: ${entry.error}\n`);
        continue;
      }
      if (!entry.result) continue;
      lines.push(`## ${entry.url}\n${summarise(entry.result)}\n`);
    }

    return {
      content: [{ type: 'text' as const, text: lines.join('\n') }],
      structuredContent: {
        results: batch.map((e) =>
          e.result ? toStructured(e.result) : { url: e.url, error: e.error },
        ),
      },
    };
  },
);

server.registerTool(
  'compare_tech_stacks',
  {
    title: 'Compare tech stacks of two sites',
    description:
      'Analyse two URLs and report what they share, what only the first uses, and what only the second uses. ' +
      'Use for competitive teardowns ("what does our competitor run that we do not?"), migration planning, or ' +
      'checking whether two properties of the same company are on the same platform.',
    inputSchema: {
      url: z.string().describe('First URL, typically yours.'),
      compareTo: z.string().describe('Second URL, typically the competitor.'),
      ...commonInput,
    },
  },
  async ({ url, compareTo, render, sourcemaps, certs, minConfidence, timeout }) => {
    const options = {
      render: render ?? false,
      sourcemaps: sourcemaps ?? false,
      certs: certs ?? false,
      minConfidence: minConfidence ?? 25,
      timeout: timeout ?? 15_000,
    };
    const [a, b] = await Promise.all([analyze(url, options), analyze(compareTo, options)]);

    const namesA = new Map(dedupe(a.detections).map((d) => [d.name, d]));
    const namesB = new Map(dedupe(b.detections).map((d) => [d.name, d]));
    const shared = [...namesA.keys()].filter((n) => namesB.has(n)).sort();
    const onlyA = [...namesA.keys()].filter((n) => !namesB.has(n)).sort();
    const onlyB = [...namesB.keys()].filter((n) => !namesA.has(n)).sort();

    const describe = (name: string, from: Map<string, Detection>): string => {
      const d = from.get(name);
      if (!d) return name;
      const cats = d.categories.slice(0, 2).join('/');
      return `${name}${d.version ? ` ${d.version}` : ''} (${cats})`;
    };

    const text = [
      `# Stack comparison`,
      ``,
      `A: ${a.finalUrl}`,
      `B: ${b.finalUrl}`,
      ``,
      `## Shared (${shared.length})`,
      shared.map((n) => `- ${describe(n, namesA)}`).join('\n') || '- none',
      ``,
      `## Only A (${onlyA.length})`,
      onlyA.map((n) => `- ${describe(n, namesA)}`).join('\n') || '- none',
      ``,
      `## Only B (${onlyB.length})`,
      onlyB.map((n) => `- ${describe(n, namesB)}`).join('\n') || '- none',
    ].join('\n');

    return {
      content: [{ type: 'text' as const, text }],
      structuredContent: {
        a: toStructured(a),
        b: toStructured(b),
        shared,
        onlyA,
        onlyB,
      },
    };
  },
);

server.registerTool(
  'tech_stack_report',
  {
    title: 'Generate a markdown tech stack report',
    description:
      'Produce a full markdown report for a URL, with every detected technology grouped by category in tables, ' +
      'including versions, confidence and evidence. Use when the user wants a document, audit deliverable or ' +
      'something to paste into a doc or ticket rather than a conversational answer.',
    inputSchema: {
      url: z.string().describe('The URL or bare domain to analyse.'),
      ...commonInput,
    },
  },
  async ({ url, render, sourcemaps, certs, minConfidence, categories, timeout }) => {
    const result = await analyze(url, {
      render: render ?? true,
      sourcemaps: sourcemaps ?? true,
      certs: certs ?? false,
      minConfidence: minConfidence ?? 25,
      timeout: timeout ?? 20_000,
    });
    const filtered = categories?.length
      ? filterByCategories(result, categories as Category[])
      : result;
    return {
      content: [{ type: 'text' as const, text: formatMarkdown(filtered) }],
      structuredContent: toStructured(filtered),
    };
  },
);

server.registerTool(
  'find_subdomains',
  {
    title: 'Find a domain\'s subdomains',
    description:
      'Discover subdomains for a domain by combining certificate transparency logs with DNS probing of common ' +
      'labels, then resolving each result so dead entries are marked. Use to map an organisation\'s web footprint, ' +
      'find staging and admin hosts, or expand account research before a security review. Certificate ' +
      'transparency is a complete public log of issued certificates, so this often finds internal tooling ' +
      '(grafana, jenkins, metabase, argocd) that is not linked from anywhere.',
    inputSchema: {
      domain: z.string().describe('Apex domain, e.g. "example.com". A URL is accepted and reduced to its domain.'),
      limit: z.number().min(10).max(2000).optional().describe('Maximum subdomains to return. Default 500.'),
      wordlist: z
        .boolean()
        .optional()
        .describe('Also probe common subdomain labels via DNS, which finds hosts with no public certificate. Default true.'),
      onlyLive: z.boolean().optional().describe('Return only subdomains that currently resolve. Default false.'),
    },
  },
  async ({ domain, limit, wordlist, onlyLive }) => {
    const result = await findSubdomains(domain, {
      ...(limit !== undefined ? { limit } : {}),
      ...(wordlist !== undefined ? { wordlist } : {}),
    });
    const rows = onlyLive ? result.subdomains.filter((s) => s.resolves) : result.subdomains;
    const live = result.subdomains.filter((s) => s.resolves).length;
    const text = [
      `${result.domain}: ${result.total} subdomains found (${live} currently resolve), via ${result.sources.join(' + ')}`,
      '',
      ...rows.map((s) => `${s.resolves ? 'live' : 'dead'}  ${s.host}${s.addresses?.length ? `  ${s.addresses.slice(0, 2).join(', ')}` : ''}`),
      ...(result.warnings.length > 0 ? ['', 'Caveats:', ...result.warnings.map((w) => `- ${w}`)] : []),
      '',
      'Note: certificate transparency includes hosts that were issued a certificate at some point but may no longer exist, which is why each entry is DNS-checked and labelled.',
    ].join('\n');
    return {
      content: [{ type: 'text' as const, text }],
      structuredContent: { ...result, subdomains: rows },
    };
  },
);

server.registerTool(
  'verify_email',
  {
    title: 'Verify an email address',
    description:
      'Check whether an email address is real and safe to send to, without sending anything. Validates syntax, ' +
      'resolves MX records, and opens an SMTP session to test the recipient (RCPT TO only, no message is ever ' +
      'delivered). Returns reachable = safe / risky / invalid / unknown plus catch-all, role-account, disposable ' +
      'and free-provider flags. Use before adding an address to a CRM or outreach sequence. Note: many networks ' +
      'block outbound port 25, in which case the verdict is "unknown" with connection = false, which is a network ' +
      'limitation and not a finding about the address; set dnsOnly for a fast syntax and MX check instead.',
    inputSchema: {
      emails: z.array(z.string()).min(1).max(20).describe('Email addresses to verify.'),
      dnsOnly: z
        .boolean()
        .optional()
        .describe('Skip the SMTP conversation and check only syntax and MX records. Fast and always available. Default false.'),
      timeout: z.number().optional().describe('SMTP timeout in ms. Default 10000.'),
    },
  },
  async ({ emails, dnsOnly, timeout }) => {
    const results = [];
    for (const email of emails) {
      results.push(
        await verifyEmail(email, {
          ...(dnsOnly !== undefined ? { dnsOnly } : {}),
          ...(timeout !== undefined ? { timeout } : {}),
        }),
      );
    }
    const text = results
      .map((r) =>
        [
          `${r.email}: ${r.reachable.toUpperCase()}`,
          `  syntax=${r.syntaxValid} mx=${r.mxValid} smtp=${r.connection} deliverable=${r.deliverable}`,
          `  catchAll=${r.catchAll} role=${r.roleAccount} disposable=${r.disposable} free=${r.freeProvider}`,
          r.mxHosts.length > 0 ? `  MX: ${r.mxHosts.join(', ')}` : '',
          r.reason ? `  ${r.reason}` : '',
        ]
          .filter(Boolean)
          .join('\n'),
      )
      .join('\n\n');
    return { content: [{ type: 'text' as const, text }], structuredContent: { results } };
  },
);

server.registerTool(
  'find_vulnerabilities',
  {
    title: 'Find known CVEs for a site\'s detected stack',
    description:
      'Detect the technologies on a URL, map them to CPE identifiers, and look up published CVEs in the public ' +
      'NVD database. Use for security recon and patch triage. Only technologies with a confidently detected ' +
      'VERSION are looked up, because a versionless CPE matches every release ever published and would produce a ' +
      'meaningless list; those are reported as skipped instead. Always tell the user that versions are inferred ' +
      'from public signals and must be confirmed before acting on a CVE.',
    inputSchema: {
      url: z.string().describe('The URL or bare domain to analyse.'),
      render: z.boolean().optional().describe('Render first, which improves version detection. Default false.'),
      max: z.number().min(1).max(20).optional().describe('Maximum technologies to look up. Default 8.'),
    },
  },
  async ({ url, render, max }) => {
    const result = await analyze(url, { render: render ?? false, sourcemaps: true });
    const apiKey = process.env['NVD_API_KEY'];
    const cves = await lookupCves(result.detections, {
      ...(apiKey ? { apiKey } : {}),
      ...(max !== undefined ? { max } : {}),
    });
    const lines: string[] = [`Vulnerability scan for ${result.finalUrl}`, ''];
    let total = 0;
    for (const entry of cves) {
      const header = `${entry.technology}${entry.version ? ` ${entry.version}` : ''}`;
      if (entry.skipped) {
        lines.push(`${header}: skipped. ${entry.skipped}`);
      } else if (entry.cves.length === 0) {
        lines.push(`${header}: no published CVEs for this version.`);
      } else {
        total += entry.cves.length;
        lines.push(`${header}: ${entry.cves.length} CVEs`);
        for (const cve of entry.cves.slice(0, 10)) {
          lines.push(`  ${cve.id} ${cve.severity ?? ''} ${cve.cvss ?? ''} - ${cve.summary.slice(0, 140)}`);
        }
      }
      lines.push('');
    }
    lines.push(
      total > 0
        ? 'Versions are inferred from public signals and can be wrong. Confirm the running version before treating any CVE as applicable.'
        : 'No CVEs matched. This is not evidence that the site is secure; it only means no published CVE matched the versions detected.',
    );
    if (!apiKey) {
      lines.push('NVD requests were paced at one per 6 seconds because no NVD_API_KEY is set. A free key raises this limit.');
    }
    return { content: [{ type: 'text' as const, text: lines.join('\n') }], structuredContent: { results: cves } };
  },
);

server.registerTool(
  'track_tech_changes',
  {
    title: 'Track technology changes over time',
    description:
      'Scan a URL and compare it against the previously stored snapshot, reporting technologies added, removed or ' +
      'version-changed. The first call establishes a baseline. Use for competitor monitoring and buying signals ' +
      '(a competitor adding Klaviyo or dropping Shopify Plus), or to catch dependency changes. Snapshots are ' +
      'stored locally on this machine only; nothing is uploaded. Call repeatedly over days or weeks, or have the ' +
      'user schedule the equivalent CLI command on a cron.',
    inputSchema: {
      urls: z.array(z.string()).min(1).max(20).describe('URLs to scan and compare against their stored baseline.'),
      render: z.boolean().optional().describe('Render before comparing. Keep this consistent between runs. Default false.'),
      crawl: z.union([z.boolean(), z.number()]).optional().describe('Crawl internal pages. Keep consistent between runs.'),
    },
  },
  async ({ urls, render, crawl }) => {
    const diffs = [];
    for (const url of urls) {
      const result = await analyze(url, { render: render ?? false, crawl: crawl ?? false });
      const current = toSnapshot(result);
      const previous = await loadSnapshot(current.url);
      const diff = diffSnapshots(previous, current);
      await saveSnapshot(current);
      diffs.push(diff);
    }
    const text = diffs
      .map((d) => {
        if (d.isFirstRun) return `${d.url}: baseline saved. Run again later to see changes.`;
        if (d.changes.length === 0) return `${d.url}: no changes since ${d.previousAt} (${d.unchanged} stable).`;
        return [
          `${d.url}: ${d.changes.length} changes since ${d.previousAt}`,
          ...d.changes.map((c) =>
            c.change === 'version-changed'
              ? `  ~ ${c.name} ${c.from ?? '?'} -> ${c.to ?? '?'}`
              : `  ${c.change === 'added' ? '+' : '-'} ${c.name} (${c.categories[0] ?? ''})`,
          ),
        ].join('\n');
      })
      .join('\n\n');
    return { content: [{ type: 'text' as const, text }], structuredContent: { diffs } };
  },
);

server.registerTool(
  'opentechalyzer_status',
  {
    title: 'Opentechalyzer status and capabilities',
    description:
      'Report the fingerprint database size and version, whether headless rendering is available, and whether ' +
      'the optional external database is imported. Call this first if a scan returned fewer technologies than ' +
      'expected, to find out which capabilities are missing.',
    inputSchema: {},
  },
  async () => {
    const [renderAvailable, external, tranco] = await Promise.all([
      isRenderAvailable(),
      externalDatabaseStatus(),
      trancoStatus(),
    ]);
    const text = [
      `Opentechalyzer ${VERSION}`,
      `Built-in fingerprints: ${BUILTIN_FINGERPRINTS.length} (database ${DATABASE_VERSION}, MIT licensed)`,
      `Headless rendering: ${renderAvailable ? 'available' : 'NOT available (install playwright to enable render:true)'}`,
      external.installed
        ? `External database: installed, ${external.count ?? '?'} extra fingerprints (imported ${external.importedAt ?? '?'})`
        : `External database: not installed. Call import_external_database to widen long-tail coverage.`,
      tranco.installed
        ? `Traffic ranking: installed, ${tranco.count ?? '?'} ranked domains`
        : `Traffic ranking: not installed, so trafficRank and trafficLevel are unavailable. The user can run \`opentechalyzer db import-tranco\`.`,
      '',
      'Available tools: detect_tech_stack, detect_tech_stack_batch, compare_tech_stacks, tech_stack_report,',
      'find_subdomains, verify_email, find_vulnerabilities, track_tech_changes.',
    ].join('\n');
    return {
      content: [{ type: 'text' as const, text }],
      structuredContent: {
        version: VERSION,
        databaseVersion: DATABASE_VERSION,
        builtinFingerprints: BUILTIN_FINGERPRINTS.length,
        renderAvailable,
        external,
        tranco,
      },
    };
  },
);

server.registerTool(
  'import_external_database',
  {
    title: 'Import the optional external fingerprint database',
    description:
      'Download the community-maintained Wappalyzer-format technology dataset to this machine to widen long-tail ' +
      'coverage. The dataset is GPL-3.0 and is NOT bundled with Opentechalyzer (MIT); it is fetched to a local ' +
      'cache directory only. Tell the user about the licence before calling this, and only call it when they have ' +
      'asked for broader coverage.',
    inputSchema: {
      acknowledgeLicense: z
        .boolean()
        .describe(
          'Must be true. Confirms the user has been told the downloaded dataset is GPL-3.0 and that redistributing a product bundling it carries GPL-3.0 obligations.',
        ),
    },
  },
  async ({ acknowledgeLicense }) => {
    if (!acknowledgeLicense) {
      return {
        content: [
          {
            type: 'text' as const,
            text: `Import not performed. The user must be informed of the licence first:\n\n${EXTERNAL_DB_LICENSE_NOTICE}\n\nRe-call with acknowledgeLicense: true once they agree.`,
          },
        ],
        isError: true,
      };
    }
    const { count, path } = await importExternalDatabase();
    return {
      content: [
        {
          type: 'text' as const,
          text: `Imported ${count} additional fingerprints to ${path}.\n\n${EXTERNAL_DB_LICENSE_NOTICE}`,
        },
      ],
      structuredContent: { count, path },
    };
  },
);

function filterByCategories(result: AnalyzeResult, categories: Category[]): AnalyzeResult {
  const wanted = new Set(categories);
  const detections = result.detections.filter((d) => d.categories.some((c) => wanted.has(c)));
  const byCategory: Partial<Record<Category, Detection[]>> = {};
  for (const det of detections) {
    for (const c of det.categories) {
      if (wanted.has(c)) (byCategory[c] ??= []).push(det);
    }
  }
  return { ...result, detections, byCategory };
}

const transport = new StdioServerTransport();
await server.connect(transport);
