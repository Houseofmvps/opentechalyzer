import type { AnalyzeOptions, Detection } from '../types.js';
import { apexOf } from '../collect/http.js';
import {
  extractCompany,
  extractContact,
  extractMeta,
  extractSocial,
  type CompanyFields,
  type ContactFields,
  type MetaFields,
  type SocialFields,
} from './extract.js';
import { extractLocale, estimateSpend, trafficLevelFromRank, type LocaleFields, type SpendLevel } from './signals.js';
import { inspectCertificate, inspectDnsSecurity, type SecurityFields } from './tls.js';
import { trancoRank } from './tranco.js';
import { cpeFor } from './cve.js';

/** The optional field sets, named to match the documented sets of the commercial equivalent. */
export type FieldSet = 'meta' | 'company' | 'contact' | 'social' | 'signals' | 'locale' | 'security' | 'keywords';

export const ALL_FIELD_SETS: FieldSet[] = [
  'meta',
  'company',
  'contact',
  'social',
  'signals',
  'locale',
  'security',
  'keywords',
];

export interface Enrichment {
  meta?: MetaFields;
  company?: CompanyFields;
  contact?: ContactFields;
  social?: SocialFields;
  locale?: LocaleFields;
  security?: SecurityFields;
  signals?: {
    technologySpend: SpendLevel;
    technologySpendMonthlyFloorUsd: number;
    technologySpendDrivers: string[];
    trafficRank?: number;
    trafficLevel?: 'very low' | 'low' | 'medium' | 'high' | 'very high';
  };
  /** CPE 2.3 names for detected technologies, usable for CVE lookup. */
  cpes?: Array<{ technology: string; version?: string; cpe: string }>;
}

export interface EnrichInput {
  /** Homepage HTML plus any crawled pages, concatenated for extraction. */
  html: string;
  homepageHtml: string;
  metas: Record<string, string>;
  title?: string;
  hostname: string;
  finalUrl: string;
  contentLanguage?: string;
  detections: Detection[];
}

/**
 * Build the requested enrichment field sets.
 *
 * Each set is independent and failures are contained, so a TLS handshake that hangs cannot
 * prevent the contact details from being returned.
 */
export async function enrich(
  input: EnrichInput,
  sets: FieldSet[],
  options: AnalyzeOptions = {},
): Promise<{ enrichment: Enrichment; warnings: string[] }> {
  const wanted = new Set(sets);
  const enrichment: Enrichment = {};
  const warnings: string[] = [];
  const apex = apexOf(input.hostname);

  // `meta` underpins company inference and keywords, so it is computed whenever any of the
  // three is requested rather than duplicating the parsing work.
  const needsMeta = wanted.has('meta') || wanted.has('company') || wanted.has('keywords');
  const metaFields = needsMeta
    ? extractMeta(input.homepageHtml, input.metas, input.title)
    : undefined;

  if (metaFields && (wanted.has('meta') || wanted.has('keywords'))) {
    const scoped: MetaFields = wanted.has('meta')
      ? metaFields
      : { schemaOrgTypes: [], keywords: metaFields.keywords };
    enrichment.meta = scoped;
  }

  const contact =
    wanted.has('contact') || wanted.has('locale') ? extractContact(input.html, input.hostname) : undefined;
  if (contact && wanted.has('contact')) enrichment.contact = contact;

  if (wanted.has('social')) enrichment.social = extractSocial(input.html);

  if (wanted.has('company') && metaFields) {
    enrichment.company = extractCompany(input.html, input.metas, metaFields, input.hostname);
  }

  const jobs: Array<Promise<void>> = [];

  let certCountry: string | undefined;
  if (wanted.has('security') || wanted.has('locale')) {
    jobs.push(
      (async () => {
        try {
          const [certInfo, dns] = await Promise.all([
            inspectCertificate(input.hostname, Math.min(options.timeout ?? 15_000, 8000)),
            inspectDnsSecurity(apex),
          ]);
          certCountry = certInfo?.subjectCountry;
          if (wanted.has('security')) {
            const security: SecurityFields = { dns };
            if (certInfo) security.certInfo = certInfo;
            enrichment.security = security;
          }
        } catch (err) {
          warnings.push(`Security inspection failed: ${(err as Error).message}`);
        }
      })(),
    );
  }

  if (wanted.has('signals')) {
    jobs.push(
      (async () => {
        const spend = estimateSpend(input.detections);
        const signals: NonNullable<Enrichment['signals']> = {
          technologySpend: spend.level,
          technologySpendMonthlyFloorUsd: spend.monthlyFloorUsd,
          technologySpendDrivers: spend.drivers,
        };
        const rank = await trancoRank(apex);
        if (rank !== null) {
          signals.trafficRank = rank;
          signals.trafficLevel = trafficLevelFromRank(rank);
        }
        enrichment.signals = signals;
      })(),
    );
  }

  await Promise.allSettled(jobs);

  // Locale runs last because it consumes the certificate country and the phone numbers.
  if (wanted.has('locale')) {
    enrichment.locale = extractLocale(
      input.homepageHtml,
      input.metas,
      input.hostname,
      contact?.phone ?? [],
      certCountry,
      input.contentLanguage,
    );
  }

  const cpes = input.detections
    .filter((d) => !d.inferred)
    .map((d) => {
      const cpe = cpeFor(d);
      if (!cpe) return null;
      const entry: { technology: string; version?: string; cpe: string } = { technology: d.name, cpe };
      if (d.version) entry.version = d.version;
      return entry;
    })
    .filter((x): x is { technology: string; version?: string; cpe: string } => x !== null);
  if (cpes.length > 0) enrichment.cpes = cpes;

  if (wanted.has('signals') && !enrichment.signals?.trafficRank) {
    warnings.push(
      'trafficRank is unavailable because the Tranco list is not imported. Run `opentechalyzer db import-tranco` to enable it.',
    );
  }

  return { enrichment, warnings };
}

export { extractCompany, extractContact, extractMeta, extractSocial } from './extract.js';
export { extractLocale, estimateSpend, trafficLevelFromRank } from './signals.js';
export { inspectCertificate, inspectDnsSecurity } from './tls.js';
export { verifyEmail } from './verify-email.js';
export { findSubdomains } from './subdomains.js';
export { crawlAdditionalPages } from './crawl.js';
export { cpeFor, lookupCves } from './cve.js';
export { importTranco, trancoRank, trancoStatus } from './tranco.js';
export {
  diffSnapshots,
  listWatched,
  loadSnapshot,
  saveSnapshot,
  snapshotDir,
  toSnapshot,
} from './watch.js';
export type { CompanyFields, ContactFields, MetaFields, SocialFields } from './extract.js';
export type { LocaleFields, SignalFields, SpendLevel } from './signals.js';
export type { CertInfo, SecurityFields } from './tls.js';
export type { EmailVerification, Reachability } from './verify-email.js';
export type { SubdomainResult } from './subdomains.js';
export type { Cve, CveResult } from './cve.js';
export type { DiffResult, Snapshot, TechChange } from './watch.js';
