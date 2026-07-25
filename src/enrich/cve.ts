import type { Detection } from '../types.js';

/**
 * CPE names and CVE lookup.
 *
 * A CPE (Common Platform Enumeration) name is the identifier that links a detected technology
 * and version to published vulnerabilities. Commercial tools expose the CPE string and stop
 * there; because NVD's API is free and unauthenticated, this goes one step further and can
 * fetch the actual CVEs, which is the outcome a user actually wants.
 *
 * Version accuracy is the limiting factor. A CPE without a version matches every version ever
 * released, so `lookupCves` refuses to report vulnerabilities for a versionless detection
 * rather than producing a scary and meaningless list.
 */

/** vendor:product pairs for technologies whose CVEs matter in practice. */
const CPE_MAP: Record<string, string> = {
  WordPress: 'wordpress:wordpress',
  Drupal: 'drupal:drupal',
  Joomla: 'joomla:joomla',
  Magento: 'magento:magento',
  WooCommerce: 'woocommerce:woocommerce',
  PrestaShop: 'prestashop:prestashop',
  TYPO3: 'typo3:typo3',
  'Craft CMS': 'craftcms:craft_cms',
  Umbraco: 'umbraco:umbraco_cms',
  Ghost: 'ghost:ghost',
  Strapi: 'strapi:strapi',
  Nginx: 'f5:nginx',
  'Apache HTTP Server': 'apache:http_server',
  'Apache Tomcat': 'apache:tomcat',
  'Microsoft IIS': 'microsoft:internet_information_services',
  LiteSpeed: 'litespeedtech:openlitespeed',
  OpenResty: 'openresty:openresty',
  Caddy: 'caddyserver:caddy',
  Varnish: 'varnish-cache:varnish',
  Envoy: 'envoyproxy:envoy',
  Traefik: 'traefik:traefik',
  PHP: 'php:php',
  Python: 'python:python',
  Java: 'oracle:jdk',
  'Node.js': 'nodejs:node.js',
  Ruby: 'ruby-lang:ruby',
  Go: 'golang:go',
  Django: 'djangoproject:django',
  Flask: 'palletsprojects:flask',
  Laravel: 'laravel:laravel',
  Symfony: 'sensiolabs:symfony',
  'Ruby on Rails': 'rubyonrails:rails',
  Express: 'openjsf:express',
  'Next.js': 'vercel:next.js',
  Nuxt: 'nuxt:nuxt',
  'ASP.NET': 'microsoft:asp.net',
  Spring: 'vmware:spring_framework',
  jQuery: 'jquery:jquery',
  'jQuery UI': 'jquery:jquery_ui',
  Bootstrap: 'getbootstrap:bootstrap',
  Angular: 'angular:angular',
  React: 'facebook:react',
  'Vue.js': 'vuejs:vue',
  'Lodash': 'lodash:lodash',
  'Moment.js': 'momentjs:moment',
  'Three.js': 'threejs:three.js',
  'Video.js': 'videojs:video.js',
  'CKEditor': 'ckeditor:ckeditor',
  TinyMCE: 'tiny:tinymce',
  Prism: 'prismjs:prism',
  'highlight.js': 'highlightjs:highlight.js',
  Grafana: 'grafana:grafana',
  Jenkins: 'jenkins:jenkins',
  GitLab: 'gitlab:gitlab',
  Gitea: 'gitea:gitea',
  Kibana: 'elastic:kibana',
  Elasticsearch: 'elastic:elasticsearch',
  Nextcloud: 'nextcloud:nextcloud',
  phpMyAdmin: 'phpmyadmin:phpmyadmin',
  'HashiCorp Vault': 'hashicorp:vault',
  Keycloak: 'keycloak:keycloak',
  MinIO: 'minio:minio',
  'Apache Airflow': 'apache:airflow',
  'Apache Superset': 'apache:superset',
  Portainer: 'portainer:portainer',
  Mattermost: 'mattermost:mattermost',
  'Rocket.Chat': 'rocket.chat:rocket.chat',
  Jellyfin: 'jellyfin:jellyfin',
  Plex: 'plex:plex_media_server',
  Odoo: 'odoo:odoo',
  Shopware: 'shopware:shopware',
  'Adobe Experience Manager': 'adobe:experience_manager',
  Sitecore: 'sitecore:experience_platform',
  MySQL: 'oracle:mysql',
  PostgreSQL: 'postgresql:postgresql',
  SQLite: 'sqlite:sqlite',
};

/** Build the CPE 2.3 name for a detection, using its version when one was found. */
export function cpeFor(detection: Detection): string | undefined {
  const pair = CPE_MAP[detection.name];
  if (!pair) return undefined;
  const version = detection.version ? sanitiseVersion(detection.version) : '*';
  return `cpe:2.3:a:${pair}:${version}:*:*:*:*:*:*:*`;
}

function sanitiseVersion(version: string): string {
  const cleaned = version.trim().replace(/[^0-9A-Za-z.\-_]/g, '');
  return cleaned.length > 0 ? cleaned : '*';
}

export interface Cve {
  id: string;
  cvss?: number;
  severity?: string;
  published?: string;
  summary: string;
  url: string;
}

export interface CveResult {
  technology: string;
  version?: string;
  cpe: string;
  cves: Cve[];
  /** Set when a lookup was deliberately not performed. */
  skipped?: string;
}

/**
 * Query the NVD API for CVEs affecting the detected technologies.
 *
 * NVD allows unauthenticated use at roughly one request every six seconds, so requests are
 * serialised with a delay. Supplying `apiKey` (free from nvd.nist.gov) raises that limit
 * considerably.
 */
export async function lookupCves(
  detections: Detection[],
  options: { apiKey?: string; max?: number; timeout?: number; onProgress?: (msg: string) => void } = {},
): Promise<CveResult[]> {
  const progress = options.onProgress ?? (() => undefined);
  const candidates = detections
    .filter((d) => !d.inferred && CPE_MAP[d.name])
    .slice(0, options.max ?? 8);

  const results: CveResult[] = [];

  for (const [index, det] of candidates.entries()) {
    const cpe = cpeFor(det);
    if (!cpe) continue;

    if (!det.version) {
      results.push({
        technology: det.name,
        cpe,
        cves: [],
        skipped:
          'No version was detected. A versionless CPE matches every release ever published, so a CVE list would be meaningless. Re-run with --render or --sourcemaps to improve version detection.',
      });
      continue;
    }

    // Serialise and pace requests to respect the public rate limit.
    if (index > 0) await sleep(options.apiKey ? 700 : 6500);
    progress(`querying NVD for ${det.name} ${det.version}`);

    try {
      const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
      url.searchParams.set('cpeName', cpe);
      url.searchParams.set('resultsPerPage', '20');

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), options.timeout ?? 20_000);
      const headers: Record<string, string> = { 'user-agent': 'Opentechalyzer/0.1' };
      if (options.apiKey) headers['apiKey'] = options.apiKey;

      const res = await fetch(url, { headers, signal: controller.signal });
      clearTimeout(timer);

      if (!res.ok) {
        results.push({
          technology: det.name,
          version: det.version,
          cpe,
          cves: [],
          skipped: `NVD returned HTTP ${res.status}`,
        });
        continue;
      }

      const body = (await res.json()) as {
        vulnerabilities?: Array<{
          cve?: {
            id?: string;
            published?: string;
            descriptions?: Array<{ lang?: string; value?: string }>;
            metrics?: Record<string, Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>>;
          };
        }>;
      };

      const cves: Cve[] = [];
      for (const entry of body.vulnerabilities ?? []) {
        const cve = entry.cve;
        if (!cve?.id) continue;
        const english = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? '';
        const metricSets = Object.values(cve.metrics ?? {});
        const first = metricSets.flat()[0]?.cvssData;
        const item: Cve = {
          id: cve.id,
          summary: english.slice(0, 300),
          url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        };
        if (cve.published) item.published = cve.published;
        if (first?.baseScore !== undefined) item.cvss = first.baseScore;
        if (first?.baseSeverity) item.severity = first.baseSeverity;
        cves.push(item);
      }

      cves.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
      results.push({ technology: det.name, version: det.version, cpe, cves });
    } catch (err) {
      results.push({
        technology: det.name,
        version: det.version,
        cpe,
        cves: [],
        skipped: `Lookup failed: ${(err as Error).message}`,
      });
    }
  }

  return results;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
