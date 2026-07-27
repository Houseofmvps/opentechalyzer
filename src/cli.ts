#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import kleur from 'kleur';
import { analyze, analyzeMany } from './analyze.js';
import { isRenderAvailable } from './collect/render.js';
import {
  EXTERNAL_DB_LICENSE_NOTICE,
  externalDatabaseStatus,
  importExternalDatabase,
} from './fingerprints/external.js';
import { BUILTIN_FINGERPRINTS, DATABASE_VERSION, listCategories } from './fingerprints/index.js';
import { lookupCves } from './enrich/cve.js';
import { findSubdomains } from './enrich/subdomains.js';
import { importTranco, trancoStatus } from './enrich/tranco.js';
import { verifyEmail } from './enrich/verify-email.js';
import { humanBytes, reverseLookup } from './reverse/bigquery.js';
import {
  diffSnapshots,
  listWatched,
  loadSnapshot,
  saveSnapshot,
  snapshotDir,
  toSnapshot,
} from './enrich/watch.js';
import { formatCsv, formatMarkdown, formatTerminal, summarise } from './report/format.js';
import type { AnalyzeOptions, AnalyzeResult, Category } from './types.js';

/**
 * Read the version from package.json.
 *
 * This was hardcoded and drifted: `--version` still printed 0.1.0 on the 0.3.0 package. The
 * same bug was fixed in the MCP server but missed here, which is exactly why neither should
 * carry its own copy of the number.
 */
const VERSION: string = (() => {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

const HELP = `
${kleur.bold(kleur.cyan('Opentechalyzer'))} ${kleur.gray(`v${VERSION}`)}
Free, open source website technology detection.

${kleur.bold('USAGE')}
  opentechalyzer <url...> [options]
  opentechalyzer subdomains <domain...>
  opentechalyzer verify <email...>
  opentechalyzer cve <url>
  opentechalyzer reverse --tech Shopify    ${kleur.gray('find ALL sites using a technology')}
  opentechalyzer watch <url...>            ${kleur.gray('detect tech changes since last scan')}
  opentechalyzer watch --list
  opentechalyzer db <import|import-tranco|status>
  ota <url>                                ${kleur.gray('(short alias)')}

${kleur.bold('SCAN OPTIONS')}
  -r, --render            Render with a headless browser (needs playwright)
  -s, --sourcemaps        Parse sourcemaps to recover npm dependencies
  -w, --crawl [n]         Follow up to n internal pages (default 5) for deeper coverage
  -F, --fields <sets>     Enrichment: meta,company,contact,social,signals,locale,security,keywords
                          or "all". Comma separated.
  -c, --certs             Query certificate transparency for subdomains
      --intrusive         Include probes for /.git/HEAD and /.env
      --no-dns            Skip DNS lookups
      --no-probe          Skip well-known path probes
      --no-favicon        Skip favicon hashing
      --no-css            Skip stylesheet download (weakens CSS framework detection)
      --no-external       Ignore any imported external database

  -f, --format <fmt>      text | json | markdown | csv | summary   (default: text)
  -o, --only <cats>       Comma-separated categories to report
  -m, --min <n>           Minimum confidence 0-100 (default: 25)
  -v, --verbose           Show the evidence behind every detection
  -q, --quiet             Suppress progress output
      --no-color          Disable colour
  -t, --timeout <ms>      Per-request timeout (default: 15000)
  -j, --jobs <n>          Concurrency for multiple URLs (default: 5)
  -i, --input <file>      Read newline-separated URLs from a file
  -A, --user-agent <ua>   Override the User-Agent

      --categories        List all categories and exit
      --version           Print version and exit
  -h, --help              Show this help

${kleur.bold('EXAMPLES')}
  ota example.com
  ota example.com --render --crawl --fields all --verbose
  ota example.com -f json > stack.json
  ota -i urls.txt -f csv -j 10 > stacks.csv          ${kleur.gray('bulk lookup')}
  ota example.com --only cms,payment,analytics
  ota subdomains example.com
  ota verify sales@example.com
  ota cve example.com
  ota watch example.com                              ${kleur.gray('run on a cron for alerts')}
  ota db import                                      ${kleur.gray('widen fingerprint coverage')}
  ota db import-tranco                               ${kleur.gray('enable traffic ranking')}
  ota reverse --tech Shopify --tech Klaviyo --rank 100000 --dry-run
  ota reverse --tech Shopify --not-tech "Google Analytics" --limit 500 -f csv

${kleur.bold('REVERSE LOOKUP')} ${kleur.gray('(needs a Google Cloud project, queries HTTP Archive on BigQuery)')}
      --tech <name>       Technology that must be present (repeatable, ANDed)
      --not-tech <name>   Technology that must be absent (repeatable)
      --category <name>   Match a technology category instead, e.g. Ecommerce
      --rank <n>          Only sites within the top n by CrUX popularity
      --client <c>        desktop | mobile (default mobile)
      --date <YYYY-MM-01> Crawl month (default: two months back)
      --max-bytes <n>     Cost ceiling in bytes (default 200GB)
  -l, --limit <n>         Max sites to return (default 100, max 10000)
      --dry-run           Estimate cost and print the SQL, run nothing

${kleur.bold('DEEPER SCANS')}
  Each flag finds more. Combine them for a full picture:
    --render      tag managers, injected widgets, framework globals (needs playwright)
    --crawl       checkout/review/payment scripts that only load on inner pages
    --sourcemaps  exact npm dependency names and versions
    --fields all  contact details, socials, company, security posture, spend signals

    npm i playwright && npx playwright install chromium
`;

interface ParsedArgs {
  urls: string[];
  command?: string;
  subcommand?: string;
  options: AnalyzeOptions & {
    format: string;
    verbose: boolean;
    quiet: boolean;
    noColor: boolean;
    only?: Category[];
    jobs: number;
    input?: string;
    external: boolean;
    fields?: string[];
  };
  showHelp: boolean;
  showVersion: boolean;
  showCategories: boolean;
  listMode: boolean;
  dnsOnly: boolean;
  dryRun: boolean;
  tech?: string[];
  notTech?: string[];
  category?: string;
  rank?: number;
  client?: 'desktop' | 'mobile';
  date?: string;
  project?: string;
  maxBytes?: number;
  limit?: number;
}

const SUBCOMMANDS = new Set(['db', 'database', 'subdomains', 'verify', 'cve', 'watch', 'reverse']);

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = {
    urls: [],
    options: {
      format: 'text',
      verbose: false,
      quiet: false,
      noColor: false,
      jobs: 5,
      external: true,
      render: false,
      sourcemaps: false,
      certs: false,
      dns: true,
      probe: true,
      favicon: true,
      css: true,
      crawl: false,
      intrusiveProbes: false,
      minConfidence: 25,
      timeout: 15_000,
    },
    showHelp: false,
    showVersion: false,
    showCategories: false,
    listMode: false,
    dnsOnly: false,
    dryRun: false,
  };

  const next = (i: number): string | undefined => argv[i + 1];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    switch (arg) {
      case '-h':
      case '--help':
        out.showHelp = true;
        break;
      case '--version':
        out.showVersion = true;
        break;
      case '--categories':
        out.showCategories = true;
        break;
      case '-r':
      case '--render':
        out.options.render = true;
        break;
      case '-s':
      case '--sourcemaps':
        out.options.sourcemaps = true;
        break;
      case '-c':
      case '--certs':
        out.options.certs = true;
        break;
      case '-w':
      case '--crawl': {
        // Optional numeric argument: `--crawl` alone means the default budget.
        const peek = next(i);
        if (peek && /^\d+$/.test(peek)) {
          out.options.crawl = Number(peek);
          i++;
        } else {
          out.options.crawl = true;
        }
        break;
      }
      case '-F':
      case '--fields':
        out.options.fields = (next(i) ?? '').split(',').map((s) => s.trim()).filter(Boolean);
        i++;
        break;
      case '--no-css':
        out.options.css = false;
        break;
      case '--list':
        out.listMode = true;
        break;
      case '--dns-only':
        out.dnsOnly = true;
        break;
      case '--dry-run':
        out.dryRun = true;
        break;
      case '--tech':
        (out.tech ??= []).push(next(i) ?? '');
        i++;
        break;
      case '--not-tech':
        (out.notTech ??= []).push(next(i) ?? '');
        i++;
        break;
      case '--category':
        out.category = next(i);
        i++;
        break;
      case '--rank':
        out.rank = Number(next(i) ?? 0);
        i++;
        break;
      case '--client':
        out.client = (next(i) === 'desktop' ? 'desktop' : 'mobile');
        i++;
        break;
      case '--date':
        out.date = next(i);
        i++;
        break;
      case '--project':
        out.project = next(i);
        i++;
        break;
      case '--max-bytes':
        out.maxBytes = Number(next(i) ?? 0);
        i++;
        break;
      case '-l':
      case '--limit':
        out.limit = Number(next(i) ?? 100);
        i++;
        break;
      case '--intrusive':
        out.options.intrusiveProbes = true;
        break;
      case '--no-dns':
        out.options.dns = false;
        break;
      case '--no-probe':
        out.options.probe = false;
        break;
      case '--no-favicon':
        out.options.favicon = false;
        break;
      case '--no-external':
        out.options.external = false;
        break;
      case '--no-color':
        out.options.noColor = true;
        break;
      case '-v':
      case '--verbose':
        out.options.verbose = true;
        break;
      case '-q':
      case '--quiet':
        out.options.quiet = true;
        break;
      case '-f':
      case '--format':
        out.options.format = next(i) ?? 'text';
        i++;
        break;
      case '-o':
      case '--only':
        out.options.only = (next(i) ?? '').split(',').map((s) => s.trim()) as Category[];
        i++;
        break;
      case '-m':
      case '--min':
        out.options.minConfidence = Number(next(i) ?? 25);
        i++;
        break;
      case '-t':
      case '--timeout':
        out.options.timeout = Number(next(i) ?? 15_000);
        i++;
        break;
      case '-j':
      case '--jobs':
        out.options.jobs = Number(next(i) ?? 5);
        i++;
        break;
      case '-i':
      case '--input':
        out.options.input = next(i);
        i++;
        break;
      case '-A':
      case '--user-agent':
        out.options.userAgent = next(i);
        i++;
        break;
      default:
        if (arg.startsWith('-')) {
          process.stderr.write(kleur.red(`Unknown option: ${arg}\n`));
          process.exit(2);
        }
        if (!out.command && SUBCOMMANDS.has(arg)) {
          out.command = arg === 'database' ? 'db' : arg;
        } else if (out.command === 'db' && !out.subcommand) {
          out.subcommand = arg;
        } else {
          out.urls.push(arg);
        }
    }
  }

  return out;
}

async function runDbCommand(subcommand: string | undefined): Promise<number> {
  if (subcommand === 'status') {
    const status = await externalDatabaseStatus();
    process.stdout.write(`\n${kleur.bold('Built-in database')}\n`);
    process.stdout.write(`  version:      ${DATABASE_VERSION}\n`);
    process.stdout.write(`  fingerprints: ${BUILTIN_FINGERPRINTS.length}\n`);
    process.stdout.write(`  licence:      MIT\n\n`);
    process.stdout.write(`${kleur.bold('External database')}\n`);
    if (status.installed) {
      process.stdout.write(`  status:       ${kleur.green('installed')}\n`);
      process.stdout.write(`  fingerprints: ${status.count ?? '?'}\n`);
      process.stdout.write(`  imported:     ${status.importedAt ?? '?'}\n`);
      process.stdout.write(`  source:       ${status.source ?? '?'}\n`);
      process.stdout.write(`  path:         ${status.path}\n\n`);
    } else {
      process.stdout.write(`  status:       ${kleur.gray('not installed')}\n`);
      process.stdout.write(`  path:         ${status.path}\n`);
      process.stdout.write(`\n  Run ${kleur.cyan('opentechalyzer db import')} to widen long-tail coverage.\n`);
    }
    const tranco = await trancoStatus();
    process.stdout.write(`\n${kleur.bold('Traffic ranking (Tranco)')}\n`);
    if (tranco.installed) {
      process.stdout.write(`  status:       ${kleur.green('installed')}\n`);
      process.stdout.write(`  domains:      ${tranco.count ?? '?'}\n`);
      process.stdout.write(`  imported:     ${tranco.importedAt ?? '?'}\n`);
    } else {
      process.stdout.write(`  status:       ${kleur.gray('not installed')}\n`);
      process.stdout.write(`  Run ${kleur.cyan('opentechalyzer db import-tranco')} to enable trafficRank.\n`);
    }
    process.stdout.write('\n');
    return 0;
  }

  if (subcommand === 'import') {
    process.stdout.write(`\n${kleur.bold(kleur.yellow('Licence notice'))}\n`);
    process.stdout.write(`${EXTERNAL_DB_LICENSE_NOTICE}\n\n`);
    process.stdout.write('Importing to your local cache directory...\n\n');
    try {
      const { count, path } = await importExternalDatabase({
        onProgress: (msg) => process.stdout.write(kleur.gray(`  ${msg}\n`)),
      });
      process.stdout.write(`\n${kleur.green('Imported')} ${count} additional fingerprints\n`);
      process.stdout.write(`${kleur.gray(path)}\n\n`);
      return 0;
    } catch (err) {
      process.stderr.write(kleur.red(`\nImport failed: ${(err as Error).message}\n\n`));
      return 1;
    }
  }

  if (subcommand === 'import-tranco') {
    process.stdout.write('\nImporting the Tranco top-1m list (free, research-grade traffic ranking)...\n\n');
    try {
      const { count, path } = await importTranco({
        onProgress: (msg) => process.stdout.write(kleur.gray(`  ${msg}\n`)),
      });
      process.stdout.write(`\n${kleur.green('Imported')} ${count} ranked domains\n${kleur.gray(path)}\n\n`);
      return 0;
    } catch (err) {
      process.stderr.write(kleur.red(`\nTranco import failed: ${(err as Error).message}\n\n`));
      return 1;
    }
  }

  process.stderr.write(
    kleur.red(`\nUnknown db subcommand. Use "import", "import-tranco" or "status".\n\n`),
  );
  return 2;
}

/** `subdomains <domain...>` */
async function runSubdomains(domains: string[], args: ParsedArgs): Promise<number> {
  const json = args.options.format === 'json';
  const results = [];
  for (const domain of domains) {
    const result = await findSubdomains(domain, { timeout: args.options.timeout });
    results.push(result);
    if (json) continue;
    const live = result.subdomains.filter((s) => s.resolves);
    process.stdout.write(`\n${kleur.bold(result.domain)}  ${kleur.gray(`${live.length} live of ${result.total} found via ${result.sources.join(' + ')}`)}\n`);
    for (const sub of result.subdomains) {
      const marker = sub.resolves ? kleur.green('  live') : kleur.gray('  dead');
      const addr = sub.addresses?.length ? kleur.gray(`  ${sub.addresses.slice(0, 2).join(', ')}`) : '';
      process.stdout.write(`${marker}  ${sub.host}${addr}\n`);
    }
    for (const w of result.warnings) process.stdout.write(kleur.yellow(`  ! ${w}\n`));
    process.stdout.write('\n');
  }
  if (json) process.stdout.write(`${JSON.stringify(domains.length === 1 ? results[0] : results, null, 2)}\n`);
  return 0;
}

/** `verify <email...>` */
async function runVerify(emails: string[], args: ParsedArgs): Promise<number> {
  const json = args.options.format === 'json';
  const results = [];
  for (const email of emails) {
    const result = await verifyEmail(email, {
      dnsOnly: args.dnsOnly,
      ...(args.options.timeout ? { timeout: args.options.timeout } : {}),
    });
    results.push(result);
    if (json) continue;
    const colour =
      result.reachable === 'safe'
        ? kleur.green
        : result.reachable === 'risky'
          ? kleur.yellow
          : result.reachable === 'invalid'
            ? kleur.red
            : kleur.gray;
    process.stdout.write(`\n${kleur.bold(result.email)}  ${colour(result.reachable.toUpperCase())}\n`);
    const flag = (label: string, value: boolean): string =>
      `${value ? kleur.green('yes') : kleur.gray(' no')} ${label}`;
    process.stdout.write(
      [
        `  ${flag('syntax valid', result.syntaxValid)}`,
        `  ${flag('MX valid', result.mxValid)}`,
        `  ${flag('SMTP connection', result.connection)}`,
        `  ${flag('deliverable', result.deliverable)}`,
        `  ${flag('catch-all', result.catchAll)}`,
        `  ${flag('role account', result.roleAccount)}`,
        `  ${flag('disposable', result.disposable)}`,
        `  ${flag('free provider', result.freeProvider)}`,
      ].join('\n') + '\n',
    );
    if (result.mxHosts.length > 0) process.stdout.write(kleur.gray(`  MX: ${result.mxHosts.join(', ')}\n`));
    if (result.reason) process.stdout.write(kleur.gray(`  ${result.reason}\n`));
    process.stdout.write('\n');
  }
  if (json) process.stdout.write(`${JSON.stringify(emails.length === 1 ? results[0] : results, null, 2)}\n`);
  return 0;
}

/** `cve <url>` */
async function runCve(urls: string[], args: ParsedArgs): Promise<number> {
  const target = urls[0];
  if (!target) {
    process.stderr.write(kleur.red('Usage: opentechalyzer cve <url>\n'));
    return 2;
  }
  const result = await analyze(target, {
    render: args.options.render,
    sourcemaps: true,
    timeout: args.options.timeout,
  });
  const apiKey = process.env['NVD_API_KEY'];
  if (!apiKey) {
    process.stderr.write(
      kleur.gray('No NVD_API_KEY set, so requests are paced at one per 6 seconds. Get a free key at nvd.nist.gov.\n'),
    );
  }
  const cves = await lookupCves(result.detections, {
    ...(apiKey ? { apiKey } : {}),
    onProgress: (msg) => process.stderr.write(kleur.gray(`  ${msg}\n`)),
  });

  if (args.options.format === 'json') {
    process.stdout.write(`${JSON.stringify(cves, null, 2)}\n`);
    return 0;
  }

  process.stdout.write(`\n${kleur.bold(`Known vulnerabilities for ${result.finalUrl}`)}\n\n`);
  let total = 0;
  for (const entry of cves) {
    const header = `${entry.technology}${entry.version ? ` ${entry.version}` : ''}`;
    if (entry.skipped) {
      process.stdout.write(`${kleur.gray(header)}  ${kleur.gray(entry.skipped)}\n\n`);
      continue;
    }
    if (entry.cves.length === 0) {
      process.stdout.write(`${kleur.green(header)}  no published CVEs for this version\n\n`);
      continue;
    }
    total += entry.cves.length;
    process.stdout.write(`${kleur.bold(kleur.red(header))}  ${entry.cves.length} CVEs\n`);
    for (const cve of entry.cves.slice(0, 10)) {
      const severity = cve.severity ? cve.severity.padEnd(8) : '        ';
      const score = cve.cvss !== undefined ? String(cve.cvss).padStart(4) : '    ';
      process.stdout.write(`  ${kleur.red(score)} ${kleur.yellow(severity)} ${cve.id}  ${cve.summary.slice(0, 90)}\n`);
    }
    process.stdout.write('\n');
  }
  process.stdout.write(
    total > 0
      ? kleur.yellow(`${total} CVEs found. Versions are detected from public signals and may be inaccurate; verify before acting.\n\n`)
      : kleur.gray('Nothing found. Absence of CVEs here is not proof a site is secure.\n\n'),
  );
  return 0;
}

/** `watch <url...>` and `watch --list` */
async function runWatch(urls: string[], args: ParsedArgs): Promise<number> {
  if (args.listMode) {
    const watched = await listWatched();
    if (watched.length === 0) {
      process.stdout.write(`\n${kleur.gray('Nothing is being watched yet. Run: ota watch <url>')}\n`);
      process.stdout.write(`${kleur.gray(snapshotDir())}\n\n`);
      return 0;
    }
    process.stdout.write(`\n${kleur.bold('Watched sites')}\n`);
    for (const w of watched) {
      process.stdout.write(`  ${w.url}  ${kleur.gray(`${w.count} technologies, last ${w.capturedAt}`)}\n`);
    }
    process.stdout.write(`\n${kleur.gray(snapshotDir())}\n\n`);
    return 0;
  }

  if (urls.length === 0) {
    process.stderr.write(kleur.red('Usage: opentechalyzer watch <url...>  |  opentechalyzer watch --list\n'));
    return 2;
  }

  const diffs = [];
  for (const url of urls) {
    const result = await analyze(url, {
      render: args.options.render,
      sourcemaps: args.options.sourcemaps,
      crawl: args.options.crawl,
      timeout: args.options.timeout,
    });
    const current = toSnapshot(result);
    const previous = await loadSnapshot(current.url);
    const diff = diffSnapshots(previous, current);
    await saveSnapshot(current);
    diffs.push(diff);

    if (args.options.format === 'json') continue;

    process.stdout.write(`\n${kleur.bold(current.url)}\n`);
    if (diff.isFirstRun) {
      process.stdout.write(
        kleur.gray(`  Baseline saved with ${current.technologies.length} technologies. Run again later to see changes.\n`),
      );
      continue;
    }
    if (diff.changes.length === 0) {
      process.stdout.write(kleur.gray(`  No changes since ${diff.previousAt} (${diff.unchanged} technologies stable)\n`));
      continue;
    }
    for (const change of diff.changes) {
      if (change.change === 'added') {
        process.stdout.write(`  ${kleur.green('+')} ${change.name} ${kleur.gray(`(${change.categories[0] ?? ''})`)}\n`);
      } else if (change.change === 'removed') {
        process.stdout.write(`  ${kleur.red('-')} ${change.name} ${kleur.gray(`(${change.categories[0] ?? ''})`)}\n`);
      } else {
        process.stdout.write(`  ${kleur.yellow('~')} ${change.name} ${kleur.gray(`${change.from ?? '?'} -> ${change.to ?? '?'}`)}\n`);
      }
    }
  }

  if (args.options.format === 'json') {
    process.stdout.write(`${JSON.stringify(urls.length === 1 ? diffs[0] : diffs, null, 2)}\n`);
  } else {
    process.stdout.write('\n');
  }
  return 0;
}


/** `reverse --tech X` */
async function runReverse(args: ParsedArgs): Promise<number> {
  const json = args.options.format === 'json';
  try {
    const result = await reverseLookup({
      ...(args.tech?.length ? { tech: args.tech } : {}),
      ...(args.notTech?.length ? { notTech: args.notTech } : {}),
      ...(args.category ? { category: args.category } : {}),
      ...(args.rank ? { rank: args.rank } : {}),
      ...(args.client ? { client: args.client } : {}),
      ...(args.date ? { date: args.date } : {}),
      ...(args.project ? { projectId: args.project } : {}),
      ...(args.maxBytes ? { maxBytes: args.maxBytes } : {}),
      dryRun: args.dryRun,
      ...(args.limit ? { limit: args.limit } : {}),
      onProgress: (m) => {
        if (!args.options.quiet && !json) process.stderr.write(kleur.gray(`  ${m}\n`));
      },
    });

    if (json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return result.notRun ? 1 : 0;
    }

    process.stdout.write(`\n${kleur.bold('Reverse lookup')}  ${kleur.gray(`HTTP Archive crawl ${result.date}`)}\n`);
    process.stdout.write(
      `${kleur.gray('Scan estimate:')} ${humanBytes(result.estimatedBytes)}  ` +
        `${kleur.gray('approx cost:')} $${result.estimatedCostUsd.toFixed(2)} ` +
        `${kleur.gray('(first 1 TB per month is free)')}\n\n`,
    );

    if (result.notRun) {
      process.stdout.write(`${kleur.yellow(result.notRun)}\n\n`);
      if (args.options.verbose || args.dryRun) {
        process.stdout.write(`${kleur.gray(result.query)}\n\n`);
      }
      return 0;
    }

    if (args.options.verbose) process.stdout.write(`${kleur.gray(result.query)}\n\n`);

    const rows = result.rows ?? [];
    if (rows.length === 0) {
      process.stdout.write(
        kleur.yellow('No sites matched. Check the technology name spelling, or try an earlier --date: ') +
          kleur.yellow('HTTP Archive names come from their own Wappalyzer fork, not this project.\n\n'),
      );
      return 0;
    }

    for (const row of rows) {
      const rank = row.rank ? kleur.gray(` #${row.rank}`) : '';
      process.stdout.write(`  ${row.page}${rank}\n`);
    }
    process.stdout.write(`\n${kleur.green(`${rows.length} sites`)}\n`);
    process.stdout.write(
      kleur.gray(
        'Source: HTTP Archive monthly crawl, detected with their Wappalyzer fork rather than this\n' +
          "project's fingerprints, so results can differ from a direct scan. Coverage is CrUX-based,\n" +
          'so small or low-traffic sites may be missing entirely.\n\n',
      ),
    );
    return 0;
  } catch (err) {
    process.stderr.write(kleur.red(`\n${(err as Error).message}\n\n`));
    return 1;
  }
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));

  if (args.options.noColor || !process.stdout.isTTY) kleur.enabled = !args.options.noColor && kleur.enabled;
  if (args.options.noColor) kleur.enabled = false;

  if (args.showVersion) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (args.showCategories) {
    process.stdout.write(`${listCategories().join('\n')}\n`);
    return 0;
  }
  if (args.command === 'db') return runDbCommand(args.subcommand);

  let urls = [...args.urls];
  if (args.options.input) {
    try {
      const text = await readFile(args.options.input, 'utf8');
      urls.push(
        ...text
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l.length > 0 && !l.startsWith('#')),
      );
    } catch (err) {
      process.stderr.write(kleur.red(`Cannot read ${args.options.input}: ${(err as Error).message}\n`));
      return 1;
    }
  }
  urls = [...new Set(urls)];

  if (args.command === 'subdomains') return runSubdomains(urls, args);
  if (args.command === 'verify') return runVerify(urls, args);
  if (args.command === 'cve') return runCve(urls, args);
  if (args.command === 'watch') return runWatch(urls, args);
  if (args.command === 'reverse') return runReverse(args);

  if (args.showHelp || urls.length === 0) {
    process.stdout.write(`${HELP}\n`);
    return urls.length === 0 && !args.showHelp ? 2 : 0;
  }

  if (args.options.external === false) process.env['OPENTECHALYZER_NO_EXTERNAL'] = '1';

  // Warn early rather than after a slow scan silently missing half the stack.
  if (args.options.render && !(await isRenderAvailable())) {
    process.stderr.write(
      kleur.yellow(
        'Playwright is not installed, so --render will be skipped.\n' +
          'Install it with: npm i playwright && npx playwright install chromium\n\n',
      ),
    );
  }

  const isMachineFormat = args.options.format !== 'text';
  const onProgress =
    args.options.quiet || isMachineFormat
      ? undefined
      : (stage: string, detail?: string): void => {
          process.stderr.write(kleur.gray(`  ${stage}${detail ? ` ${detail}` : ''}\n`));
        };

  const scanOptions: AnalyzeOptions = {
    render: args.options.render,
    sourcemaps: args.options.sourcemaps,
    certs: args.options.certs,
    dns: args.options.dns,
    probe: args.options.probe,
    favicon: args.options.favicon,
    intrusiveProbes: args.options.intrusiveProbes,
    minConfidence: args.options.minConfidence,
    timeout: args.options.timeout,
    userAgent: args.options.userAgent,
    css: args.options.css,
    crawl: args.options.crawl,
    ...(args.options.fields ? { fields: args.options.fields } : {}),
  };
  if (onProgress) scanOptions.onProgress = onProgress;

  const results: AnalyzeResult[] = [];
  let failures = 0;

  if (urls.length === 1) {
    const only = urls[0] as string;
    try {
      results.push(await analyze(only, scanOptions));
    } catch (err) {
      process.stderr.write(kleur.red(`\n${only}: ${(err as Error).message}\n\n`));
      return 1;
    }
  } else {
    const batch = await analyzeMany(urls, { ...scanOptions, concurrency: args.options.jobs });
    for (const entry of batch) {
      if (entry.result) results.push(entry.result);
      else {
        failures++;
        process.stderr.write(kleur.red(`${entry.url}: ${entry.error}\n`));
      }
    }
  }

  const formatOptions = {
    verbose: args.options.verbose,
    noColor: args.options.noColor,
    ...(args.options.only ? { only: args.options.only } : {}),
  };

  switch (args.options.format) {
    case 'json':
      process.stdout.write(
        `${JSON.stringify(urls.length === 1 ? results[0] : results, null, 2)}\n`,
      );
      break;
    case 'markdown':
    case 'md':
      process.stdout.write(results.map((r) => formatMarkdown(r, formatOptions)).join('\n---\n\n'));
      break;
    case 'csv':
      process.stdout.write(`${formatCsv(results)}\n`);
      break;
    case 'summary':
      for (const r of results) {
        process.stdout.write(`${new URL(r.finalUrl).hostname}\n${summarise(r)}\n\n`);
      }
      break;
    case 'text':
      for (const r of results) process.stdout.write(formatTerminal(r, formatOptions));
      break;
    default:
      process.stderr.write(kleur.red(`Unknown format: ${args.options.format}\n`));
      return 2;
  }

  return failures > 0 && results.length === 0 ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    process.stderr.write(kleur.red(`\nUnexpected error: ${(err as Error).stack ?? String(err)}\n`));
    process.exit(1);
  });
