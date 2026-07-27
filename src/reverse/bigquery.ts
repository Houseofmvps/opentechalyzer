/**
 * Reverse lookup: find every site using a given technology.
 *
 * This is the one capability a live scanner structurally cannot provide. Detecting the stack
 * of a URL you already have is a single HTTP request; answering "which sites run Shopify"
 * requires having already crawled the web. Commercial vendors sell access to their own crawl.
 *
 * HTTP Archive does that crawl monthly across ~16 million pages, publishes it free on BigQuery,
 * and includes a Wappalyzer-derived `technologies` column. So the data is public: what was
 * missing is a way to query it without writing SQL. That is what this module is.
 *
 * ## The honest trade-offs, stated up front
 *
 *  - **It is not our detection.** HTTP Archive runs their own Wappalyzer fork, so a reverse
 *    lookup reflects *their* fingerprints, not the 588 in this project. Results can therefore
 *    disagree with a direct `analyze()` of the same URL. Both are reported honestly rather
 *    than blended into a false single number.
 *  - **It costs money past the free tier.** BigQuery gives 1 TB/month free; a careless query
 *    over this dataset can scan several TB in one go. Every query here is dry-run first, the
 *    estimate is shown, and execution is refused above a byte ceiling unless raised
 *    explicitly. Nothing bills silently.
 *  - **Coverage is CrUX-based**, so it skews to sites with real Chrome traffic. Small or new
 *    stores may be absent entirely. It is a sampling frame, not a census.
 *  - **Monthly snapshots**, so the data lags by weeks, not minutes.
 */

const BQ_API = 'https://bigquery.googleapis.com/bigquery/v2';

/** Default ceiling on bytes billed. 200 GB is a fifth of the monthly free tier. */
const DEFAULT_MAX_BYTES = 200 * 1024 ** 3;

export interface ReverseOptions {
  /** Technologies that must ALL be present, e.g. ['Shopify', 'Klaviyo']. */
  tech?: string[];
  /** Technologies that must NOT be present. */
  notTech?: string[];
  /** Technology category to match instead of a name, e.g. 'Ecommerce'. */
  category?: string;
  /** Only sites ranked within this CrUX popularity bucket (1000, 10000, 100000, 1000000...). */
  rank?: number;
  client?: 'desktop' | 'mobile';
  /** Crawl month, first of the month, e.g. '2025-06-01'. */
  date?: string;
  limit?: number;
  /** Google Cloud project id used for billing. */
  projectId?: string;
  /** OAuth access token. Falls back to gcloud. */
  accessToken?: string;
  /** Refuse to run if the dry run estimates more than this many bytes. */
  maxBytes?: number;
  /** Estimate only, never execute. */
  dryRun?: boolean;
  onProgress?: (msg: string) => void;
}

export interface ReverseResult {
  query: string;
  estimatedBytes: number;
  estimatedCostUsd: number;
  /** Absent when dryRun was requested. */
  rows?: Array<{ page: string; rank?: number; technologies?: string[] }>;
  totalRows?: number;
  date: string;
  /** Present when the query was not executed, explaining why. */
  notRun?: string;
}

/** BigQuery on-demand pricing, USD per TiB scanned. Used only for the estimate shown to users. */
const USD_PER_TIB = 6.25;

function humanBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(value < 10 ? 2 : 0)} ${units[i]}`;
}

/**
 * The most recent crawl is typically 1-2 months behind, so default to two months back rather
 * than returning an empty result that looks like "no sites use this".
 */
export function defaultCrawlDate(now = new Date()): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 2, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-01`;
}

/** Resolve an access token from the environment, then from the gcloud CLI. */
export async function resolveAccessToken(explicit?: string): Promise<string | null> {
  if (explicit) return explicit;
  const fromEnv = process.env['GOOGLE_ACCESS_TOKEN'] ?? process.env['GCP_ACCESS_TOKEN'];
  if (fromEnv) return fromEnv;
  try {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const run = promisify(execFile);
    const { stdout } = await run('gcloud', ['auth', 'print-access-token'], { timeout: 20_000 });
    const token = stdout.trim();
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

/** Resolve the billing project from the environment, then from the gcloud CLI. */
export async function resolveProjectId(explicit?: string): Promise<string | null> {
  if (explicit) return explicit;
  const fromEnv =
    process.env['GOOGLE_CLOUD_PROJECT'] ??
    process.env['GCLOUD_PROJECT'] ??
    process.env['BIGQUERY_PROJECT_ID'];
  if (fromEnv) return fromEnv;
  try {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const run = promisify(execFile);
    const { stdout } = await run('gcloud', ['config', 'get-value', 'project'], { timeout: 20_000 });
    const id = stdout.trim();
    return id && id !== '(unset)' ? id : null;
  } catch {
    return null;
  }
}

/** Escape a string literal for embedding in SQL. */
function sqlString(value: string): string {
  return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

/**
 * Build the SQL.
 *
 * Filters are ordered to exploit the table's clustering (`client`, `is_root_page`, `rank`,
 * `page`) and its `date` partitioning, because that is what keeps the scan affordable. Only
 * `page`, `rank` and the technology array are selected: pulling `custom_metrics` or
 * `lighthouse` would multiply the bytes scanned by orders of magnitude.
 */
export function buildReverseQuery(options: ReverseOptions): { sql: string; date: string } {
  const date = options.date ?? defaultCrawlDate();
  const client = options.client ?? 'mobile';
  const limit = Math.min(Math.max(options.limit ?? 100, 1), 10_000);

  const where: string[] = [
    `date = ${sqlString(date)}`,
    `client = ${sqlString(client)}`,
    // Root pages only: without this the same site appears once per crawled inner page.
    `is_root_page = TRUE`,
  ];
  if (options.rank) where.push(`\`rank\` <= ${Math.floor(options.rank)}`);

  const having: string[] = [];
  for (const tech of options.tech ?? []) {
    having.push(`LOGICAL_OR(t.technology = ${sqlString(tech)})`);
  }
  for (const tech of options.notTech ?? []) {
    having.push(`LOGICAL_OR(t.technology = ${sqlString(tech)}) = FALSE`);
  }
  if (options.category) {
    having.push(`LOGICAL_OR(${sqlString(options.category)} IN UNNEST(t.categories))`);
  }
  if (having.length === 0) {
    throw new Error('Specify at least one --tech, --not-tech or --category filter.');
  }

  // Grouping per page and filtering with HAVING is what makes multi-technology AND queries
  // work: a single WHERE over the unnested array can only ever test one element at a time.
  // `rank` is backticked throughout: BigQuery also has a RANK() window function, and leaving
  // the column bare invites an ambiguity error that only shows up at query time.
  const sql = `SELECT
  page,
  ANY_VALUE(\`rank\`) AS \`rank\`,
  ARRAY_AGG(DISTINCT t.technology IGNORE NULLS ORDER BY t.technology LIMIT 40) AS technologies
FROM \`httparchive.crawl.pages\`, UNNEST(technologies) AS t
WHERE ${where.join('\n  AND ')}
GROUP BY page
HAVING ${having.join('\n  AND ')}
ORDER BY \`rank\` NULLS LAST
LIMIT ${limit}`;

  return { sql, date };
}

interface BqQueryResponse {
  totalBytesProcessed?: string;
  totalRows?: string;
  jobComplete?: boolean;
  schema?: { fields?: Array<{ name?: string }> };
  rows?: Array<{ f?: Array<{ v?: unknown }> }>;
  error?: { message?: string };
  errors?: Array<{ message?: string }>;
}

async function bqQuery(
  projectId: string,
  token: string,
  sql: string,
  opts: { dryRun: boolean; maxBytes?: number },
): Promise<BqQueryResponse> {
  const body: Record<string, unknown> = {
    query: sql,
    useLegacySql: false,
    dryRun: opts.dryRun,
    timeoutMs: 120_000,
  };
  // maximumBytesBilled is the hard stop: BigQuery itself refuses the job rather than trusting
  // our own pre-check, which protects against an estimate that turns out to be wrong.
  if (!opts.dryRun && opts.maxBytes) body['maximumBytesBilled'] = String(Math.floor(opts.maxBytes));

  const res = await fetch(`${BQ_API}/projects/${encodeURIComponent(projectId)}/queries`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  const json = (await res.json()) as BqQueryResponse;
  if (!res.ok) {
    const message = json.error?.message ?? json.errors?.[0]?.message ?? `HTTP ${res.status}`;
    throw new Error(`BigQuery: ${message}`);
  }
  return json;
}

/**
 * Run a reverse lookup.
 *
 * Always dry-runs first so the cost is known before anything is billed.
 */
export async function reverseLookup(options: ReverseOptions = {}): Promise<ReverseResult> {
  const progress = options.onProgress ?? (() => undefined);
  const { sql, date } = buildReverseQuery(options);

  const projectId = await resolveProjectId(options.projectId);
  if (!projectId) {
    throw new Error(
      'No Google Cloud project. Set GOOGLE_CLOUD_PROJECT, pass --project, or run `gcloud config set project <id>`.\n' +
        'BigQuery bills the querying project, so one is required even though the HTTP Archive dataset itself is public.',
    );
  }
  const token = await resolveAccessToken(options.accessToken);
  if (!token) {
    throw new Error(
      'No Google Cloud credentials. Run `gcloud auth login` (or `gcloud auth application-default login`), ' +
        'or set GOOGLE_ACCESS_TOKEN to a valid OAuth token.',
    );
  }

  progress('estimating query cost');
  const dry = await bqQuery(projectId, token, sql, { dryRun: true });
  const estimatedBytes = Number(dry.totalBytesProcessed ?? 0);
  const estimatedCostUsd = (estimatedBytes / 1024 ** 4) * USD_PER_TIB;

  const result: ReverseResult = { query: sql, estimatedBytes, estimatedCostUsd, date };

  if (options.dryRun) {
    result.notRun = 'Dry run only, nothing was billed.';
    return result;
  }

  const ceiling = options.maxBytes ?? DEFAULT_MAX_BYTES;
  if (estimatedBytes > ceiling) {
    result.notRun =
      `Query would scan ${humanBytes(estimatedBytes)}, above the ${humanBytes(ceiling)} safety ceiling, so it was NOT run. ` +
      `Narrow it with --rank (e.g. --rank 100000), or raise the ceiling with --max-bytes if you accept the cost.`;
    return result;
  }

  progress(`running query (${humanBytes(estimatedBytes)} to scan)`);
  const run = await bqQuery(projectId, token, sql, { dryRun: false, maxBytes: ceiling });

  const fields = (run.schema?.fields ?? []).map((f) => f.name ?? '');
  const rows = (run.rows ?? []).map((row) => {
    const cells = row.f ?? [];
    const record: { page: string; rank?: number; technologies?: string[] } = { page: '' };
    fields.forEach((name, i) => {
      const raw = cells[i]?.v;
      if (name === 'page') record.page = String(raw ?? '');
      else if (name === 'rank' && raw != null) record.rank = Number(raw);
      else if (name === 'technologies' && Array.isArray(raw)) {
        record.technologies = (raw as Array<{ v?: unknown }>).map((x) => String(x?.v ?? ''));
      }
    });
    return record;
  });

  result.rows = rows;
  result.totalRows = Number(run.totalRows ?? rows.length);
  return result;
}

export { humanBytes, DEFAULT_MAX_BYTES };
