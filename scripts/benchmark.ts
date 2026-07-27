#!/usr/bin/env node
/**
 * Accuracy benchmark.
 *
 * Scans a fixed set of sites whose stacks were verified by hand (response headers, cookies
 * and `meta[generator]`, checked with curl) and scores what the detector reports against
 * that ground truth.
 *
 * Two things are measured, and the second matters more:
 *
 *   Recall    - of the technologies we know are present, how many were found?
 *   Hard FPs  - how many times did it name the WRONG platform or framework?
 *
 * A hard false positive is far more damaging than a miss. "We could not tell" is a usable
 * answer; "this Wix site runs Laravel" poisons a lead list and destroys trust in every other
 * row. So the run fails on a single hard false positive, while misses are budgeted.
 *
 * Run it with:  npm run benchmark
 * Add --json for machine-readable output, or --jobs N to change concurrency.
 *
 * This is a LIVE network test against third-party sites. It is deliberately not part of
 * `npm test`: results drift when those sites re-platform, and a green CI run must never
 * depend on someone else's deploy schedule. Run it after any fingerprint or engine change.
 */
import { analyzeMany } from '../src/analyze.js';
import type { AnalyzeResult } from '../src/types.js';

interface Case {
  url: string;
  /** Technologies that are definitely present. Verified by hand, see `evidence`. */
  must: string[];
  /** Technologies that are definitely NOT present. Catching one of these is a hard failure. */
  mustNot: string[];
  /** How the ground truth was established, so a future maintainer can re-verify it. */
  evidence: string;
}

/**
 * Ground truth, verified 2026-07-25.
 *
 * Every entry was confirmed against the live site, not assumed from brand knowledge. Several
 * were counter-intuitive and would have been "fixed" as false positives without checking:
 * ghost.org is built with Hugo, not Ghost; laravel.com runs Statamic; discourse.org's
 * marketing site is Jekyll, not Discourse.
 */
const CASES: Case[] = [
  {
    url: 'gitlab.com',
    must: ['Nuxt', 'Vue.js', 'Cloudflare'],
    mustNot: ['WordPress', 'Shopify', 'Django', 'Laravel', 'Ruby on Rails'],
    evidence: 'about.gitlab.com serves /_nuxt/ bundles behind Cloudflare. The GitLab app itself is Rails, the marketing site is not.',
  },
  {
    url: 'discourse.org',
    must: ['Jekyll', 'Amazon CloudFront'],
    mustNot: ['WordPress', 'Shopify', 'Django'],
    evidence: 'meta[generator] reports Jekyll; served from CloudFront + S3. The forum software is Rails, this marketing site is not.',
  },
  {
    url: 'djangoproject.com',
    must: ['Django', 'Python', 'Fastly', 'Nginx'],
    mustNot: ['WordPress', 'Laravel', 'Ruby on Rails'],
    evidence: '/admin/login/ returns the Django admin with csrfmiddlewaretoken. Homepage alone is anonymous-cached by Fastly and leaks nothing, so this case specifically exercises probe collection.',
  },
  {
    url: 'laravel.com',
    must: ['Laravel', 'Statamic', 'PHP', 'Cloudflare', 'Tailwind CSS'],
    mustNot: ['Ruby on Rails', 'Django', 'WordPress'],
    evidence: 'x-powered-by: Statamic, which is built on Laravel. Regression guard: the cookie "laravelcom_session" once matched an unanchored Rails pattern and reported Rails at 94%.',
  },
  {
    url: 'vercel.com',
    must: ['Next.js', 'React', 'Vercel', 'Node.js'],
    mustNot: ['WordPress', 'Django', 'Laravel', 'Ruby on Rails'],
    evidence: 'x-vercel-id header, /_next/static chunks.',
  },
  {
    url: 'squarespace.com',
    must: ['Squarespace'],
    mustNot: ['WordPress', 'Shopify', 'Wix'],
    evidence: 'Static.SQUARESPACE_CONTEXT global and squarespace-cdn assets.',
  },
  {
    url: 'wix.com',
    must: ['Wix', 'React'],
    mustNot: ['WordPress', 'Shopify', 'Django', 'Ruby on Rails', 'Squarespace'],
    evidence: 'static.parastorage.com assets. Regression guard: a bare XSRF-TOKEN cookie (an Angular/Axios convention) once reported Laravel at 94% on this Java/Scala stack.',
  },
  {
    url: 'bigcommerce.com',
    must: ['Next.js', 'Vercel', 'React'],
    mustNot: ['WordPress', 'Shopify', 'Django'],
    evidence: 'Their marketing site is Next.js on Vercel; the commerce platform itself is not what this URL serves.',
  },
  {
    url: 'ghost.org',
    must: ['Hugo', 'Netlify'],
    mustNot: ['WordPress', 'Shopify', 'Django'],
    evidence: 'meta[generator] content="Hugo 0.119.0", server: Netlify. Counter-intuitive but verified: Ghost do not run their marketing site on Ghost.',
  },
  {
    url: 'basecamp.com',
    must: ['Cloudflare'],
    mustNot: ['WordPress', 'Shopify', 'Django', 'Laravel'],
    evidence: 'Behind Cloudflare. Basecamp is famously Rails, but anonymous pages set no session cookie and expose no Rails header, so Rails is genuinely undetectable here and is deliberately not in `must`.',
  },
];

/** A miss is tolerable; a wrong platform is not. */
const MIN_RECALL = 90;
const MAX_HARD_FALSE_POSITIVES = 0;

interface CaseResult {
  url: string;
  found: string[];
  missed: string[];
  wrong: string[];
  error?: string;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const jobsFlag = args.indexOf('--jobs');
  const concurrency = jobsFlag >= 0 ? Number(args[jobsFlag + 1] ?? 5) : 5;

  if (!json) {
    process.stdout.write(`\nOpentechalyzer accuracy benchmark\n`);
    process.stdout.write(`${CASES.length} sites, concurrency ${concurrency}, live network\n\n`);
  }

  const batch = await analyzeMany(
    CASES.map((c) => c.url),
    { concurrency, timeout: 20_000 },
  );

  const results: CaseResult[] = [];
  let tp = 0;
  let fn = 0;
  let hardFp = 0;

  for (const [i, entry] of batch.entries()) {
    const testCase = CASES[i] as Case;
    if (!entry.result) {
      results.push({ url: testCase.url, found: [], missed: testCase.must, wrong: [], error: entry.error ?? 'unknown' });
      fn += testCase.must.length;
      continue;
    }
    const names = new Set((entry.result as AnalyzeResult).detections.map((d) => d.name));
    const found = testCase.must.filter((t) => names.has(t));
    const missed = testCase.must.filter((t) => !names.has(t));
    const wrong = testCase.mustNot.filter((t) => names.has(t));
    tp += found.length;
    fn += missed.length;
    hardFp += wrong.length;
    results.push({ url: testCase.url, found, missed, wrong });
  }

  const recall = tp + fn === 0 ? 0 : (tp / (tp + fn)) * 100;
  const passed = recall >= MIN_RECALL && hardFp <= MAX_HARD_FALSE_POSITIVES;

  if (json) {
    process.stdout.write(
      `${JSON.stringify({ recall: Number(recall.toFixed(1)), truePositives: tp, missed: fn, hardFalsePositives: hardFp, passed, results }, null, 2)}\n`,
    );
    return passed ? 0 : 1;
  }

  const pad = Math.max(...CASES.map((c) => c.url.length)) + 2;
  process.stdout.write(`${'site'.padEnd(pad)}${'found'.padEnd(9)}notes\n`);
  process.stdout.write(`${'-'.repeat(pad + 9 + 40)}\n`);
  for (const [i, r] of results.entries()) {
    const total = (CASES[i] as Case).must.length;
    const notes: string[] = [];
    if (r.error) notes.push(`ERROR ${r.error}`);
    if (r.missed.length > 0) notes.push(`missed ${r.missed.join(', ')}`);
    if (r.wrong.length > 0) notes.push(`WRONG ${r.wrong.join(', ')}`);
    process.stdout.write(
      `${r.url.padEnd(pad)}${`${r.found.length}/${total}`.padEnd(9)}${notes.join(' | ') || 'clean'}\n`,
    );
  }

  process.stdout.write(`${'-'.repeat(pad + 9 + 40)}\n`);
  process.stdout.write(`Recall                 ${tp}/${tp + fn} = ${recall.toFixed(0)}%  (threshold ${MIN_RECALL}%)\n`);
  process.stdout.write(`Hard false positives   ${hardFp}          (threshold ${MAX_HARD_FALSE_POSITIVES})\n`);
  process.stdout.write(`\n${passed ? 'PASS' : 'FAIL'}\n\n`);

  if (!passed) {
    process.stdout.write(
      'A hard false positive means a wrong platform or framework was reported. Find the\n' +
        'offending pattern with:  node dist/cli.js <url> --verbose\n' +
        'The evidence trail names the exact pattern responsible.\n\n',
    );
  }
  return passed ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    process.stderr.write(`Benchmark failed to run: ${(err as Error).stack ?? String(err)}\n`);
    process.exit(1);
  });
