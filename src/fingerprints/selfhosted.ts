import type { Fingerprint } from '../types.js';

/**
 * Self-hosted and internal software.
 *
 * These are detected from probes, response headers and login-page markup rather than from
 * favicon hashes. Favicon hashing is fully supported by the engine (`faviconMd5`), but no
 * hashes are shipped here: a hash has to be computed from a real running instance to be
 * correct, and a guessed hash is worse than no signal at all because it produces confident
 * false positives. Contributions of verified hashes are welcome, see CONTRIBUTING.md.
 */
export const selfHosted: Fingerprint[] = [
  {
    name: 'Grafana',
    categories: ['devops'],
    website: 'https://grafana.com',
    html: ['grafana-app', 'window\\.grafanaBootData'],
    js: { grafanaBootData: '' },
    probe: [{ path: '/api/health', body: '"database"\\s*:\\s*"ok"' }],
  },
  {
    name: 'Jenkins',
    categories: ['devops'],
    website: 'https://www.jenkins.io',
    headers: { 'x-jenkins': { re: '([\\d.]+)', version: '$1' } },
    html: ['Jenkins ver\\.', '/static/[0-9a-f]+/jsbundles/'],
  },
  {
    name: 'GitLab',
    categories: ['devops'],
    website: 'https://about.gitlab.com',
    html: ['gon\\.gitlab_url', 'gitlab-ui', 'data-page="projects:'],
    headers: { 'x-gitlab-meta': '' },
    probe: [{ path: '/-/manifest.json', body: 'GitLab' }],
    implies: ['Ruby on Rails'],
  },
  {
    name: 'Gitea',
    categories: ['devops'],
    website: 'https://about.gitea.com',
    meta: { keywords: 'gitea' },
    html: ['gitea-', 'Powered by Gitea'],
    probe: [{ path: '/api/v1/version', body: '"version"' }],
  },
  {
    name: 'Forgejo',
    categories: ['devops'],
    website: 'https://forgejo.org',
    html: ['Powered by Forgejo', 'forgejo'],
  },
  {
    name: 'Metabase',
    categories: ['devops'],
    website: 'https://www.metabase.com',
    html: ['Metabase', 'window\\.MetabaseBootstrap'],
    probe: [{ path: '/api/health', body: '"status"\\s*:\\s*"ok"' }],
  },
  {
    name: 'Kibana',
    categories: ['devops'],
    website: 'https://www.elastic.co/kibana',
    headers: { 'kbn-name': '', 'kbn-license-sig': '' },
    html: ['kbn-injected-metadata'],
    implies: ['Elasticsearch'],
  },
  {
    name: 'Prometheus',
    categories: ['devops'],
    website: 'https://prometheus.io',
    probe: [{ path: '/-/healthy', body: 'Prometheus (?:Server )?is Healthy' }],
  },
  {
    name: 'Portainer',
    categories: ['devops'],
    website: 'https://www.portainer.io',
    html: ['portainer', 'ng-app="portainer"'],
  },
  {
    name: 'Uptime Kuma',
    categories: ['devops'],
    website: 'https://uptime.kuma.pet',
    html: ['Uptime Kuma'],
    meta: { description: 'Uptime Kuma' },
  },
  {
    name: 'n8n',
    categories: ['devops'],
    website: 'https://n8n.io',
    html: ['n8n-', 'window\\.BASE_PATH'],
    probe: [{ path: '/rest/settings', body: '"data"' }],
  },
  {
    name: 'Apache Airflow',
    categories: ['devops'],
    website: 'https://airflow.apache.org',
    html: ['Airflow', 'airflow/static'],
    implies: ['Python', 'Flask'],
  },
  {
    name: 'Apache Superset',
    categories: ['devops'],
    website: 'https://superset.apache.org',
    html: ['superset', 'appbuilder'],
    implies: ['Python', 'Flask'],
  },
  {
    name: 'MinIO',
    categories: ['hosting'],
    website: 'https://min.io',
    headers: { server: 'MinIO', 'x-amz-request-id': '' },
  },
  {
    name: 'Nextcloud',
    categories: ['misc'],
    website: 'https://nextcloud.com',
    html: ['data-requesttoken', 'core/js/dist/main', 'Nextcloud'],
    headers: { 'x-nextcloud-': '' },
    implies: ['PHP'],
  },
  {
    name: 'Home Assistant',
    categories: ['misc'],
    website: 'https://www.home-assistant.io',
    html: ['<home-assistant\\b', 'hass-|/frontend_latest/'],
    probe: [{ path: '/api/', status: [200, 401], body: '"message"\\s*:\\s*"API running' }],
  },
  {
    name: 'phpMyAdmin',
    categories: ['devops'],
    website: 'https://www.phpmyadmin.net',
    html: ['phpMyAdmin', 'pma_password'],
    cookies: { '^pma[A-Za-z]*$': '' },
    implies: ['PHP', 'MySQL'],
  },
  {
    name: 'HashiCorp Vault',
    categories: ['security', 'devops'],
    website: 'https://www.vaultproject.io',
    probe: [{ path: '/v1/sys/health', body: '"sealed"' }],
    headers: { 'x-vault-': '' },
  },
  {
    name: 'Argo CD',
    categories: ['devops'],
    website: 'https://argo-cd.readthedocs.io',
    html: ['argocd', 'Argo CD'],
  },
  {
    name: 'Traefik',
    categories: ['web-server', 'devops'],
    website: 'https://traefik.io',
    headers: { 'x-traefik-': '' },
    probe: [{ path: '/api/version', body: '"Version"' }],
  },
  {
    name: 'Jellyfin',
    categories: ['media'],
    website: 'https://jellyfin.org',
    html: ['Jellyfin', 'jellyfin-web'],
    probe: [{ path: '/System/Info/Public', body: '"ServerName"' }],
  },
  {
    name: 'Plex',
    categories: ['media'],
    website: 'https://www.plex.tv',
    headers: { 'x-plex-protocol': '' },
    html: ['plex-web', 'Plex Media Server'],
  },
  {
    name: 'Immich',
    categories: ['media'],
    website: 'https://immich.app',
    html: ['immich'],
    probe: [{ path: '/api/server-info/ping', body: '"res"\\s*:\\s*"pong"' }],
  },
  {
    name: 'Mattermost',
    categories: ['chat'],
    website: 'https://mattermost.com',
    headers: { 'x-version-id': '' },
    html: ['mattermost'],
  },
  {
    name: 'Rocket.Chat',
    categories: ['chat'],
    website: 'https://www.rocket.chat',
    html: ['rocket\\.chat', '__meteor_runtime_config__'],
  },
  {
    name: 'Odoo Community',
    categories: ['misc'],
    website: 'https://www.odoo.com',
    probe: [{ path: '/web/webclient/version_info', status: [200, 405], body: 'server_version|jsonrpc' }],
    requires: ['Odoo'],
  },
  {
    name: 'Exposed Git repository',
    categories: ['security'],
    website: 'https://git-scm.com',
    description: 'A .git directory is publicly readable, which usually exposes full source history',
    probe: [{ path: '/.git/HEAD', body: 'ref:\\s*refs/', intrusive: true }],
  },
  {
    name: 'Exposed .env file',
    categories: ['security'],
    description: 'A .env file is publicly readable, which usually exposes credentials',
    probe: [{ path: '/.env', body: '(?:^|\\n)[A-Z_]{3,}=', intrusive: true }],
  },
];
