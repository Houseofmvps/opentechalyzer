/**
 * Opentechalyzer core types.
 *
 * The detection model has three layers:
 *   1. Evidence  - raw observations collected from a target (headers, DOM, DNS, ...)
 *   2. Signals   - declarative patterns on a Fingerprint that match Evidence
 *   3. Detection - a technology plus the confidence and the evidence trail behind it
 *
 * Every detection carries its full evidence trail. A result you cannot audit is a
 * result you cannot trust, so nothing is reported without saying why.
 */

export type Category =
  | 'platform'
  | 'cms'
  | 'ecommerce'
  | 'ecommerce-app'
  | 'static-site-generator'
  | 'js-framework'
  | 'ui-framework'
  | 'css-framework'
  | 'js-library'
  | 'web-server'
  | 'backend-framework'
  | 'language'
  | 'runtime'
  | 'hosting'
  | 'cdn'
  | 'paas'
  | 'database'
  | 'baas'
  | 'analytics'
  | 'product-analytics'
  | 'tag-manager'
  | 'advertising'
  | 'marketing-automation'
  | 'email'
  | 'crm'
  | 'payment'
  | 'auth'
  | 'search'
  | 'support'
  | 'chat'
  | 'reviews'
  | 'apm'
  | 'error-tracking'
  | 'feature-flags'
  | 'ab-testing'
  | 'personalisation'
  | 'cookie-consent'
  | 'security'
  | 'captcha'
  | 'bot-protection'
  | 'font'
  | 'media'
  | 'maps'
  | 'video'
  | 'build-tool'
  | 'documentation'
  | 'shipping'
  | 'loyalty'
  | 'subscription'
  | 'accessibility'
  | 'translation'
  | 'mail-provider'
  | 'devops'
  | 'ai'
  | 'misc';

/**
 * Where an observation came from. Each source has an intrinsic reliability, because
 * a framework-specific session cookie is far stronger evidence than a substring in
 * minified HTML.
 */
export type SignalSource =
  | 'header'
  | 'cookie'
  | 'meta'
  | 'html'
  | 'dom'
  | 'js-global'
  | 'script-src'
  | 'script-content'
  | 'stylesheet-src'
  | 'css-content'
  | 'request-host'
  | 'url'
  | 'dns-txt'
  | 'dns-mx'
  | 'dns-cname'
  | 'dns-ns'
  | 'cert-subdomain'
  | 'probe'
  | 'favicon'
  | 'sourcemap-dep'
  | 'robots'
  | 'implied';

/**
 * Intrinsic reliability of each source, expressed as the probability that a single
 * match from that source is a true positive.
 *
 * These are deliberately conservative. Weak sources are kept in the model because
 * several weak signals combining is genuinely informative, but no single weak signal
 * should be enough to report a technology as present.
 */
export const SOURCE_RELIABILITY: Record<SignalSource, number> = {
  cookie: 0.94,
  'js-global': 0.9,
  meta: 0.9,
  probe: 0.9,
  'sourcemap-dep': 0.95,
  header: 0.88,
  dom: 0.82,
  'script-src': 0.8,
  'request-host': 0.8,
  'stylesheet-src': 0.78,
  // Compiled CSS is authoritative for CSS frameworks: Tailwind's `--tw-` custom properties
  // and Bootstrap's `--bs-` variables only exist if the framework actually generated the file.
  'css-content': 0.85,
  'cert-subdomain': 0.72,
  'dns-txt': 0.75,
  'dns-cname': 0.85,
  'dns-mx': 0.9,
  'dns-ns': 0.85,
  favicon: 0.7,
  'script-content': 0.66,
  robots: 0.7,
  html: 0.55,
  url: 0.6,
  implied: 0.0, // handled separately by the implication resolver
};

/**
 * A single pattern. `re` is a JS regular expression source string.
 *
 * `version` is a template resolved against the match, so `"$1"` yields capture
 * group 1 and `"$1.$2"` composes two groups. `versionFromKey` instead reads the
 * version out of the matched key (used for things like `/_next/static/v13.4.1/`).
 */
export interface Pattern {
  re: string;
  /** Version template, e.g. "$1" or "$1.$2". */
  version?: string;
  /**
   * Account or property identifier template, e.g. "$1" for a GTM container ID.
   *
   * Kept separate from `version` because `GTM-M92FB6B` is not a version, and reporting it
   * as one is actively misleading. Account IDs are independently useful: they link a site
   * to an advertiser, and two sites sharing one are usually the same operator.
   */
  id?: string;
  /** Override the confidence contribution of this specific pattern (0-1). */
  confidence?: number;
  /**
   * Match case-sensitively. Patterns are case-insensitive by default because HTML is, but
   * identifier formats like `G-XXXXXXXX` or `GTM-XXXXXXX` must be case-sensitive or they
   * match unrelated lowercase text such as `g-recaptcha`.
   */
  caseSensitive?: boolean;
  /** Human note explaining what this pattern proves. Surfaced in verbose output. */
  note?: string;
}

export type PatternInput = string | Pattern;

/** A probe request against a well-known path. */
export interface ProbeSignal {
  path: string;
  /** Accepted status codes. Defaults to [200]. */
  status?: number[];
  /** Pattern that must match the response body. */
  body?: PatternInput;
  /** Pattern that must match a response header, as "name:pattern". */
  header?: string;
  /** Skip this probe unless the user opted into active probing. */
  intrusive?: boolean;
}

/**
 * A technology definition. All signal fields are optional; a fingerprint matches
 * when at least one of its patterns matches the collected evidence.
 */
export interface Fingerprint {
  /** Canonical display name, unique across the database. */
  name: string;
  categories: Category[];
  website?: string;
  /** Short description shown in verbose output. */
  description?: string;

  // --- passive signals, available from a single HTTP GET ---
  /** Response header name -> pattern. Header names are matched case-insensitively. */
  headers?: Record<string, PatternInput>;
  /** Cookie name pattern -> value pattern. Use "" to match on name alone. */
  cookies?: Record<string, PatternInput>;
  /** <meta name|property> -> content pattern. */
  meta?: Record<string, PatternInput>;
  /** Patterns matched against the whole HTML document. */
  html?: PatternInput[];
  /** Patterns matched against <script src> values. */
  scriptSrc?: PatternInput[];
  /** Patterns matched against inline <script> bodies. */
  scriptContent?: PatternInput[];
  /** Patterns matched against <link rel=stylesheet href> values. */
  stylesheetSrc?: PatternInput[];
  /** Patterns matched against the contents of first-party stylesheets. */
  cssContent?: PatternInput[];
  /** Patterns matched against the final URL. */
  url?: PatternInput[];
  /** Patterns matched against robots.txt. */
  robots?: PatternInput[];

  // --- signals that need a rendered page ---
  /** CSS selectors that must be present in the rendered DOM. */
  dom?: string[];
  /**
   * Dotted paths on `window` that must exist, mapped to an optional pattern the
   * stringified value must match. Use "" to test existence only.
   */
  js?: Record<string, PatternInput>;
  /** Hostnames contacted at runtime (XHR, fetch, beacons, subresources). */
  requestHost?: PatternInput[];

  // --- signals that need out-of-band lookups ---
  dnsTxt?: PatternInput[];
  dnsMx?: PatternInput[];
  dnsCname?: PatternInput[];
  dnsNs?: PatternInput[];
  /** Subdomain patterns found in certificate transparency logs. */
  certSubdomain?: PatternInput[];
  /** md5 hashes of /favicon.ico. */
  faviconMd5?: string[];
  /** npm package names recovered from sourcemaps or bundle contents. */
  npmDep?: PatternInput[];
  probe?: ProbeSignal[];

  // --- relationships ---
  /** Technologies necessarily present when this one is. */
  implies?: string[];
  /** This fingerprint only counts if one of these is also detected. */
  requires?: string[];
  /** If this is detected with higher confidence, suppress these. */
  excludes?: string[];

  /** Multiplier on every signal from this fingerprint (default 1). */
  weight?: number;
}

/** One matched observation supporting a detection. */
export interface Evidence {
  source: SignalSource;
  /** What was inspected, e.g. "set-cookie", "script[src]", "TXT". */
  subject: string;
  /** The pattern that matched. */
  pattern: string;
  /** The matched text, truncated for display. */
  match: string;
  /** Reliability contribution of this single piece of evidence (0-1). */
  reliability: number;
  version?: string;
  /** Account or property identifier captured by this pattern. */
  accountId?: string;
  note?: string;
}

export interface Detection {
  name: string;
  categories: Category[];
  website?: string;
  description?: string;
  /** 0-100. */
  confidence: number;
  version?: string;
  /** Account, container or property IDs found for this technology (e.g. GTM-XXXXXXX). */
  accountIds?: string[];
  /** True when the technology was inferred through `implies` rather than observed. */
  inferred: boolean;
  /** Name of the technology that implied this one. */
  impliedBy?: string;
  evidence: Evidence[];
}

/** Everything observed about a target, before any matching happens. */
export interface Evidence_Bundle {
  url: string;
  finalUrl: string;
  status: number;
  /** Lowercased header names -> value (repeated headers joined with ", "). */
  headers: Record<string, string>;
  /** Raw set-cookie lines. */
  setCookies: string[];
  html: string;
  /** Rendered HTML when a browser was used, otherwise undefined. */
  renderedHtml?: string;
  scriptSrcs: string[];
  scriptContents: string[];
  stylesheetSrcs: string[];
  /** Contents of first-party stylesheets, when CSS collection ran. */
  cssContents: string[];
  metas: Record<string, string>;
  /** Hostnames observed at runtime. Only populated when rendering. */
  requestHosts: string[];
  /** Dotted window paths that exist, mapped to a stringified value. */
  jsGlobals: Record<string, string>;
  /** CSS selectors that matched in the rendered DOM. Populated lazily by the engine. */
  domSelectors: Set<string>;
  robots?: string;
  dns: {
    txt: string[];
    mx: string[];
    cname: string[];
    ns: string[];
    a: string[];
  };
  certSubdomains: string[];
  faviconMd5?: string;
  npmDeps: string[];
  probes: Record<string, { status: number; body: string; headers: Record<string, string> }>;
  /** Non-fatal problems encountered while collecting. */
  warnings: string[];
  timings: Record<string, number>;
}

export interface AnalyzeOptions {
  /** Render with a headless browser to collect DOM, JS globals and runtime hosts. */
  render?: boolean;
  /** Perform DNS lookups. Default true. */
  dns?: boolean;
  /** Query crt.sh for subdomains. Slow, so default false. */
  certs?: boolean;
  /** Request well-known paths. Default true for non-intrusive probes. */
  probe?: boolean;
  /** Include probes marked intrusive (e.g. /.git/HEAD). Default false. */
  intrusiveProbes?: boolean;
  /** Download and parse sourcemaps to recover dependency names. Default false. */
  sourcemaps?: boolean;
  /** Download first-party stylesheets so CSS frameworks can be detected properly. Default true. */
  css?: boolean;
  /**
   * Follow internal links to widen coverage. `true` uses the default of 5 pages, a number sets
   * the page budget. Off by default because it multiplies request count.
   */
  crawl?: boolean | number;
  /** Enrichment field sets to compute, e.g. ['meta','contact','social']. */
  fields?: string[];
  /** Fetch and hash /favicon.ico. Default true. */
  favicon?: boolean;
  /** Minimum confidence to report. Default 25. */
  minConfidence?: number;
  /** Per-request timeout in ms. Default 15000. */
  timeout?: number;
  /** User agent string. */
  userAgent?: string;
  /** Extra request headers. */
  headers?: Record<string, string>;
  /** Max sourcemaps/bundles to inspect. Default 8. */
  maxBundles?: number;
  /** Called with progress messages. */
  onProgress?: (stage: string, detail?: string) => void;
}

export interface AnalyzeResult {
  url: string;
  finalUrl: string;
  status: number;
  detections: Detection[];
  /** Detections grouped by category, sorted by confidence. */
  byCategory: Partial<Record<Category, Detection[]>>;
  warnings: string[];
  timings: Record<string, number>;
  meta: {
    title?: string;
    description?: string;
    generator?: string;
    ip?: string;
  };
  /** Enrichment field sets, present only for the sets that were requested. */
  enrichment?: import('./enrich/index.js').Enrichment;
  /** URLs visited beyond the entry point when crawling was enabled. */
  crawledPages?: string[];
  /** Fingerprint database version used. */
  databaseVersion: string;
  fingerprintCount: number;
  analyzedAt: string;
}
