import type { Fingerprint } from '../types.js';

/**
 * Hosting platforms, CDNs and edge networks.
 *
 * Infrastructure is almost entirely header-driven, which makes it the most reliable
 * category in the database: request-id headers are set by the platform itself and cannot
 * be faked by a site author without deliberate effort.
 */
export const infrastructure: Fingerprint[] = [
  {
    name: 'Cloudflare',
    categories: ['cdn', 'security'],
    website: 'https://www.cloudflare.com',
    headers: { 'cf-ray': '', server: '^cloudflare$', 'cf-cache-status': '' },
  },
  {
    name: 'Cloudflare Pages',
    categories: ['hosting', 'paas'],
    website: 'https://pages.cloudflare.com',
    headers: { 'cf-pages': '' },
    implies: ['Cloudflare'],
  },
  {
    name: 'Cloudflare Workers',
    categories: ['paas'],
    website: 'https://workers.cloudflare.com',
    headers: { 'cf-worker': '' },
    implies: ['Cloudflare'],
  },
  {
    name: 'Vercel',
    categories: ['hosting', 'paas', 'cdn'],
    website: 'https://vercel.com',
    headers: { 'x-vercel-id': '', server: '^Vercel$', 'x-vercel-cache': '' },
  },
  {
    name: 'Netlify',
    categories: ['hosting', 'paas', 'cdn'],
    website: 'https://www.netlify.com',
    headers: { 'x-nf-request-id': '', server: '^Netlify$' },
  },
  {
    name: 'Fastly',
    categories: ['cdn'],
    website: 'https://www.fastly.com',
    headers: { 'x-fastly-request-id': '', 'x-served-by': 'cache-', 'fastly-restarts': '' },
  },
  {
    name: 'Amazon CloudFront',
    categories: ['cdn'],
    website: 'https://aws.amazon.com/cloudfront/',
    headers: { 'x-amz-cf-id': '', via: 'CloudFront', 'x-cache': 'cloudfront' },
    implies: ['Amazon Web Services'],
  },
  {
    name: 'Amazon Web Services',
    categories: ['hosting'],
    website: 'https://aws.amazon.com',
    headers: { 'x-amz-request-id': '', 'x-amzn-requestid': '', 'x-amzn-trace-id': '' },
  },
  {
    name: 'Amazon S3',
    categories: ['hosting'],
    website: 'https://aws.amazon.com/s3/',
    headers: { server: 'AmazonS3', 'x-amz-bucket-region': '' },
    implies: ['Amazon Web Services'],
  },
  {
    name: 'Akamai',
    categories: ['cdn'],
    website: 'https://www.akamai.com',
    headers: { server: 'AkamaiGHost|AkamaiNetStorage', 'x-akamai-transformed': '', 'akamai-grn': '' },
  },
  {
    name: 'Google Cloud',
    categories: ['hosting'],
    website: 'https://cloud.google.com',
    headers: { server: 'Google Frontend|gws', 'x-goog-': '' },
  },
  {
    name: 'Firebase Hosting',
    categories: ['hosting', 'paas'],
    website: 'https://firebase.google.com/products/hosting',
    headers: { 'x-firebase-': '' },
    implies: ['Google Cloud'],
  },
  {
    name: 'Microsoft Azure',
    categories: ['hosting'],
    website: 'https://azure.microsoft.com',
    headers: { 'x-azure-ref': '', 'x-msedge-ref': '', 'x-ms-request-id': '' },
  },
  {
    name: 'GitHub Pages',
    categories: ['hosting'],
    website: 'https://pages.github.com',
    headers: { server: 'GitHub\\.com', 'x-github-request-id': '' },
  },
  {
    name: 'GitLab Pages',
    categories: ['hosting'],
    website: 'https://docs.gitlab.com/ee/user/project/pages/',
    headers: { 'gitlab-lb': '', 'x-gitlab-': '' },
  },
  {
    name: 'Heroku',
    categories: ['paas'],
    website: 'https://www.heroku.com',
    headers: { via: 'vegur', server: 'Cowboy' },
  },
  {
    name: 'Fly.io',
    categories: ['paas'],
    website: 'https://fly.io',
    headers: { 'fly-request-id': '', server: '^Fly/' },
  },
  {
    name: 'Render',
    categories: ['paas'],
    website: 'https://render.com',
    headers: { 'x-render-origin-server': '', server: 'Render' },
  },
  {
    name: 'Railway',
    categories: ['paas'],
    website: 'https://railway.app',
    headers: { 'x-railway-request-id': '', server: 'railway' },
  },
  {
    name: 'DigitalOcean',
    categories: ['hosting'],
    website: 'https://www.digitalocean.com',
    headers: { 'x-do-app-origin': '', server: 'DigitalOcean' },
  },
  {
    name: 'Bunny CDN',
    categories: ['cdn'],
    website: 'https://bunny.net',
    headers: { server: 'BunnyCDN', 'cdn-pullzone': '' },
  },
  {
    name: 'KeyCDN',
    categories: ['cdn'],
    website: 'https://www.keycdn.com',
    headers: { server: 'keycdn-engine' },
  },
  {
    name: 'Imperva',
    categories: ['security', 'cdn'],
    website: 'https://www.imperva.com',
    headers: { 'x-iinfo': '', 'x-cdn': 'Incapsula' },
    cookies: { '^incap_ses_': '', '^visid_incap_': '' },
  },
  {
    name: 'Sucuri',
    categories: ['security', 'cdn'],
    website: 'https://sucuri.net',
    headers: { 'x-sucuri-id': '', 'x-sucuri-cache': '' },
  },
  {
    name: 'Vercel Edge Network',
    categories: ['cdn'],
    website: 'https://vercel.com/docs/edge-network',
    headers: { 'x-vercel-cache': '' },
    requires: ['Vercel'],
  },
  {
    name: 'jsDelivr',
    categories: ['cdn'],
    website: 'https://www.jsdelivr.com',
    scriptSrc: ['cdn\\.jsdelivr\\.net'],
    requestHost: ['cdn\\.jsdelivr\\.net'],
  },
  {
    name: 'unpkg',
    categories: ['cdn'],
    website: 'https://unpkg.com',
    scriptSrc: ['unpkg\\.com'],
    requestHost: ['unpkg\\.com'],
  },
  {
    name: 'cdnjs',
    categories: ['cdn'],
    website: 'https://cdnjs.com',
    scriptSrc: ['cdnjs\\.cloudflare\\.com'],
    requestHost: ['cdnjs\\.cloudflare\\.com'],
  },
];

/** Mail providers, identified from MX and SPF records. */
export const mail: Fingerprint[] = [
  {
    name: 'Google Workspace',
    categories: ['mail-provider'],
    website: 'https://workspace.google.com',
    dnsMx: ['aspmx\\.l\\.google\\.com', 'googlemail\\.com'],
    dnsTxt: ['include:_spf\\.google\\.com'],
  },
  {
    name: 'Microsoft 365',
    categories: ['mail-provider'],
    website: 'https://www.microsoft.com/microsoft-365',
    dnsMx: ['mail\\.protection\\.outlook\\.com'],
    dnsTxt: ['include:spf\\.protection\\.outlook\\.com'],
  },
  {
    name: 'Zoho Mail',
    categories: ['mail-provider'],
    website: 'https://www.zoho.com/mail/',
    dnsMx: ['mx\\d?\\.zoho'],
    dnsTxt: ['include:zoho'],
  },
  {
    name: 'Proton Mail',
    categories: ['mail-provider'],
    website: 'https://proton.me/mail',
    dnsMx: ['protonmail\\.ch|mail\\.protonmail\\.ch'],
    dnsTxt: ['include:_spf\\.protonmail\\.ch'],
  },
  {
    name: 'Fastmail',
    categories: ['mail-provider'],
    website: 'https://www.fastmail.com',
    dnsMx: ['messagingengine\\.com'],
  },
  {
    name: 'SendGrid',
    categories: ['email'],
    website: 'https://sendgrid.com',
    dnsTxt: ['include:sendgrid\\.net'],
    dnsCname: ['sendgrid\\.net'],
  },
  {
    name: 'Mailgun',
    categories: ['email'],
    website: 'https://www.mailgun.com',
    dnsTxt: ['include:mailgun\\.org'],
  },
  {
    name: 'Amazon SES',
    categories: ['email'],
    website: 'https://aws.amazon.com/ses/',
    dnsTxt: ['include:amazonses\\.com'],
  },
  {
    name: 'Postmark',
    categories: ['email'],
    website: 'https://postmarkapp.com',
    dnsTxt: ['include:spf\\.mtasv\\.net'],
  },
  {
    name: 'Resend',
    categories: ['email'],
    website: 'https://resend.com',
    dnsTxt: ['include:(?:amazonses|_spf)\\..*resend|resend\\.com'],
    dnsMx: ['feedback-smtp\\..*amazonses\\.com'],
  },
  {
    name: 'Mailchimp Transactional',
    categories: ['email'],
    website: 'https://mailchimp.com/features/transactional-email/',
    dnsTxt: ['include:spf\\.mandrillapp\\.com'],
  },
  {
    name: 'Salesforce',
    categories: ['crm'],
    website: 'https://www.salesforce.com',
    dnsTxt: ['include:_spf\\.salesforce\\.com'],
  },
];

/** DNS and registrar infrastructure, from NS records. */
export const dnsProviders: Fingerprint[] = [
  {
    name: 'Cloudflare DNS',
    categories: ['devops'],
    website: 'https://www.cloudflare.com/dns/',
    dnsNs: ['\\.ns\\.cloudflare\\.com'],
  },
  {
    name: 'Amazon Route 53',
    categories: ['devops'],
    website: 'https://aws.amazon.com/route53/',
    dnsNs: ['awsdns'],
    implies: ['Amazon Web Services'],
  },
  {
    name: 'GoDaddy DNS',
    categories: ['devops'],
    website: 'https://www.godaddy.com',
    dnsNs: ['domaincontrol\\.com'],
  },
  {
    name: 'Google Cloud DNS',
    categories: ['devops'],
    website: 'https://cloud.google.com/dns',
    dnsNs: ['googledomains\\.com|ns-cloud-'],
  },
  {
    name: 'Vercel DNS',
    categories: ['devops'],
    website: 'https://vercel.com/docs/projects/domains',
    dnsNs: ['ns\\d?\\.vercel-dns\\.com'],
  },
  {
    name: 'DNSimple',
    categories: ['devops'],
    website: 'https://dnsimple.com',
    dnsNs: ['dnsimple\\.com'],
  },
  {
    name: 'NS1',
    categories: ['devops'],
    website: 'https://ns1.com',
    dnsNs: ['nsone\\.net'],
  },
];
