import type { Detection } from '../types.js';

export interface LocaleFields {
  language?: string;
  languages: string[];
  ipCountry?: string;
  ipCountries: string[];
  currencies: string[];
}

export type SpendLevel = 'very low' | 'low' | 'medium' | 'high' | 'very high';

export interface SignalFields {
  technologySpend: SpendLevel;
  /** Which detections drove the spend estimate, so the number is auditable. */
  technologySpendDrivers: string[];
  trafficRank?: number;
  trafficLevel?: 'very low' | 'low' | 'medium' | 'high' | 'very high';
}

/** ccTLDs that reliably indicate a country of operation. */
const CCTLD_COUNTRY: Record<string, string> = {
  au: 'AU', at: 'AT', be: 'BE', br: 'BR', ca: 'CA', ch: 'CH', cl: 'CL', cn: 'CN', co: 'CO',
  cz: 'CZ', de: 'DE', dk: 'DK', ee: 'EE', es: 'ES', fi: 'FI', fr: 'FR', gr: 'GR', hk: 'HK',
  hu: 'HU', id: 'ID', ie: 'IE', il: 'IL', in: 'IN', it: 'IT', jp: 'JP', kr: 'KR', mx: 'MX',
  my: 'MY', nl: 'NL', no: 'NO', nz: 'NZ', ph: 'PH', pl: 'PL', pt: 'PT', ro: 'RO', ru: 'RU',
  se: 'SE', sg: 'SG', th: 'TH', tr: 'TR', tw: 'TW', ua: 'UA', uk: 'GB', us: 'US', vn: 'VN',
  za: 'ZA', ae: 'AE', sa: 'SA', ng: 'NG', ke: 'KE', pk: 'PK', bd: 'BD', lk: 'LK', np: 'NP',
};

/** International dialling prefixes, longest first so +1-242 beats +1. */
const PHONE_COUNTRY: Array<[string, string]> = [
  ['+972', 'IL'], ['+971', 'AE'], ['+966', 'SA'], ['+886', 'TW'], ['+880', 'BD'], ['+852', 'HK'],
  ['+420', 'CZ'], ['+421', 'SK'], ['+372', 'EE'], ['+371', 'LV'], ['+370', 'LT'],
  ['+358', 'FI'], ['+357', 'CY'], ['+356', 'MT'], ['+354', 'IS'], ['+353', 'IE'], ['+352', 'LU'],
  ['+351', 'PT'], ['+350', 'GI'], ['+234', 'NG'], ['+254', 'KE'], ['+263', 'ZW'], ['+27', 'ZA'],
  ['+91', 'IN'], ['+92', 'PK'], ['+94', 'LK'], ['+95', 'MM'], ['+98', 'IR'], ['+90', 'TR'],
  ['+86', 'CN'], ['+84', 'VN'], ['+82', 'KR'], ['+81', 'JP'], ['+66', 'TH'], ['+65', 'SG'],
  ['+64', 'NZ'], ['+63', 'PH'], ['+62', 'ID'], ['+61', 'AU'], ['+60', 'MY'], ['+58', 'VE'],
  ['+57', 'CO'], ['+56', 'CL'], ['+55', 'BR'], ['+54', 'AR'], ['+52', 'MX'], ['+51', 'PE'],
  ['+49', 'DE'], ['+48', 'PL'], ['+47', 'NO'], ['+46', 'SE'], ['+45', 'DK'], ['+44', 'GB'],
  ['+43', 'AT'], ['+41', 'CH'], ['+40', 'RO'], ['+39', 'IT'], ['+36', 'HU'], ['+34', 'ES'],
  ['+33', 'FR'], ['+32', 'BE'], ['+31', 'NL'], ['+30', 'GR'], ['+20', 'EG'], ['+7', 'RU'],
  ['+1', 'US'],
];

/**
 * Determine language and country of operation.
 *
 * `ipCountry` in commercial products is a blend of signals rather than a pure IP lookup, and
 * that is what is reproduced here: the ccTLD, the certificate subject country, and the
 * international dialling prefixes on the contact page. No paid geolocation database is needed,
 * and each contributing signal is reported so the guess can be checked.
 */
export function extractLocale(
  html: string,
  metas: Record<string, string>,
  hostname: string,
  phones: string[],
  certCountry?: string,
  contentLanguageHeader?: string,
): LocaleFields {
  const languages = new Set<string>();

  const htmlLang = html.match(/<html[^>]+\blang=["']([a-zA-Z-]{2,10})["']/i)?.[1];
  if (htmlLang) languages.add(normaliseLang(htmlLang));

  if (contentLanguageHeader) {
    for (const part of contentLanguageHeader.split(',')) {
      const lang = part.trim().split(';')[0];
      if (lang) languages.add(normaliseLang(lang));
    }
  }

  const ogLocale = metas['og:locale'];
  if (ogLocale) languages.add(normaliseLang(ogLocale.replace('_', '-')));

  // hreflang alternates enumerate every language a site actually serves.
  for (const m of html.matchAll(/hreflang=["']([a-zA-Z-]{2,10})["']/gi)) {
    const lang = m[1];
    if (lang && lang.toLowerCase() !== 'x-default') languages.add(normaliseLang(lang));
  }

  const currencies = new Set<string>();
  for (const key of ['og:price:currency', 'product:price:currency']) {
    const value = metas[key];
    if (value) currencies.add(value.toUpperCase());
  }
  for (const m of html.matchAll(/"(?:currency|priceCurrency)"\s*:\s*"([A-Z]{3})"/g)) {
    if (m[1]) currencies.add(m[1]);
  }

  const countries = new Set<string>();
  const tld = hostname.split('.').at(-1)?.toLowerCase();
  const tldCountry = tld ? CCTLD_COUNTRY[tld] : undefined;
  if (tldCountry) countries.add(tldCountry);
  if (certCountry) countries.add(certCountry.toUpperCase());
  for (const phone of phones) {
    for (const [prefix, country] of PHONE_COUNTRY) {
      if (phone.startsWith(prefix)) {
        countries.add(country);
        break;
      }
    }
  }
  // A country stated in structured data outranks every inference above.
  const addressCountry = html.match(/"addressCountry"\s*:\s*"([A-Za-z ]{2,40})"/)?.[1];
  const structuredCountry = addressCountry && addressCountry.length === 2 ? addressCountry.toUpperCase() : undefined;
  if (structuredCountry) countries.add(structuredCountry);

  const out: LocaleFields = {
    languages: [...languages].sort(),
    ipCountries: [...countries].sort(),
    currencies: [...currencies].sort(),
  };
  const primaryLanguage = htmlLang ? normaliseLang(htmlLang) : out.languages[0];
  if (primaryLanguage) out.language = primaryLanguage;
  const primaryCountry = structuredCountry ?? tldCountry ?? out.ipCountries[0];
  if (primaryCountry) out.ipCountry = primaryCountry;
  return out;
}

function normaliseLang(input: string): string {
  const [base, region] = input.toLowerCase().split(/[-_]/);
  return region ? `${base}-${region.toUpperCase()}` : (base ?? input.toLowerCase());
}

/**
 * Technologies whose presence implies real recurring spend, with a rough monthly weight in
 * US dollars at the low end of each vendor's commercial pricing.
 *
 * The estimate is a floor, not a bill: it counts only what is visible from the outside, and it
 * uses entry-level pricing, so a large enterprise on the same tools will spend far more. It
 * exists to separate "hobby site on free tools" from "funded company buying software", which
 * is the only question this signal can honestly answer.
 */
const SPEND_WEIGHTS: Record<string, number> = {
  'Adobe Experience Manager': 8000, Sitecore: 4000, 'Salesforce Commerce Cloud': 5000,
  'Adobe Analytics': 3000, 'Shopify Plus': 2300, Magento: 1600, Bloomreach: 2000,
  'Dynamic Yield': 2500, Nosto: 1000, Coveo: 1500, Optimizely: 1500, 'AB Tasty': 1200,
  Kameleoon: 1000, Marketo: 1200, Pardot: 1200, Braze: 2000, Iterable: 1500, Emarsys: 1500,
  Yotpo: 500, Klaviyo: 150, Attentive: 500, Postscript: 200, HubSpot: 800, Salesforce: 1500,
  Intercom: 400, Zendesk: 250, Gorgias: 300, Drift: 500, 'Help Scout': 100, Freshchat: 100,
  Algolia: 500, Klevu: 500, Searchspring: 500, Elasticsearch: 200, Typesense: 100,
  Datadog: 800, 'New Relic': 500, Dynatrace: 1500, Sentry: 100, LogRocket: 300, FullStory: 800,
  Hotjar: 100, Amplitude: 600, Mixpanel: 400, Heap: 400, Segment: 700, RudderStack: 500,
  PostHog: 200, Snowplow: 500, LaunchDarkly: 400, Statsig: 300, Split: 400,
  Auth0: 250, Okta: 500, Clerk: 100, WorkOS: 250, Stytch: 200,
  Cloudflare: 20, Fastly: 100, Akamai: 500, Imperva: 500, DataDome: 1500, PerimeterX: 1500,
  Kasada: 2000, Vercel: 20, Netlify: 20,
  Contentful: 500, Sanity: 100, Storyblok: 200, Prismic: 100, 'HubSpot CMS': 400,
  Recharge: 100, 'Loyalty Lion': 400, LoyaltyLion: 400, 'Smile.io': 200, Rebuy: 200,
  OneTrust: 500, Usercentrics: 200, Didomi: 300, Cookiebot: 50,
  Mux: 200, Cloudinary: 200, imgix: 100, ImageKit: 50, Wistia: 100,
  Typeform: 50, Calendly: 20, accessiBe: 50, Weglot: 30, Shiprocket: 50, AfterShip: 50,
  GoKwik: 300, 'Verifast AI': 200, BiteSpeed: 100, Nector: 50, Flits: 20, 'Judge.me': 15,
  Trustpilot: 250, Bazaarvoice: 2000, Okendo: 200, 'Stamped.io': 50, Loox: 50,
  Mintlify: 150, GitBook: 100, ReadMe: 100, Discourse: 100,
};

const SPEND_BANDS: Array<[number, SpendLevel]> = [
  [8000, 'very high'],
  [2500, 'high'],
  [700, 'medium'],
  [100, 'low'],
  [0, 'very low'],
];

export function estimateSpend(detections: Detection[]): { level: SpendLevel; drivers: string[]; monthlyFloorUsd: number } {
  let total = 0;
  const drivers: Array<[string, number]> = [];
  const seen = new Set<string>();
  for (const det of detections) {
    if (det.inferred || seen.has(det.name)) continue;
    seen.add(det.name);
    const weight = SPEND_WEIGHTS[det.name];
    // Only count a paid tool when we are reasonably sure it is there, otherwise a weak
    // false positive inflates the estimate.
    if (weight && det.confidence >= 60) {
      total += weight;
      drivers.push([det.name, weight]);
    }
  }
  const level = SPEND_BANDS.find(([threshold]) => total >= threshold)?.[1] ?? 'very low';
  return {
    level,
    monthlyFloorUsd: total,
    drivers: drivers.sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, w]) => `${name} (~$${w}/mo)`),
  };
}

/** Bucket a Tranco rank into the same five-level scale a commercial traffic signal uses. */
export function trafficLevelFromRank(rank: number): SignalFields['trafficLevel'] {
  if (rank <= 10_000) return 'very high';
  if (rank <= 100_000) return 'high';
  if (rank <= 300_000) return 'medium';
  if (rank <= 1_000_000) return 'low';
  return 'very low';
}
