import { connect } from 'node:tls';
import { Resolver } from 'node:dns/promises';

export interface CertInfo {
  subjectOrg?: string;
  subjectCountry?: string;
  subjectState?: string;
  subjectLocality?: string;
  subjectCommonName?: string;
  issuer?: string;
  protocol?: string;
  cipher?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  altNames?: string[];
}

export interface SecurityFields {
  certInfo?: CertInfo;
  dns: {
    spf: boolean;
    spfRecord?: string;
    dmarc: boolean;
    dmarcRecord?: string;
    dmarcPolicy?: string;
    dkim?: boolean;
    caa: boolean;
  };
}

/**
 * Read the TLS certificate directly from the origin.
 *
 * The subject Organisation field is the single most reliable identity signal available for
 * free: an OV or EV certificate carries a legal entity name that a certificate authority
 * verified, which beats any name scraped out of a page title. It is absent on DV certificates
 * (Let's Encrypt and most modern issuers), so it is reported only when actually present.
 */
export async function inspectCertificate(hostname: string, timeoutMs = 8000): Promise<CertInfo | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: CertInfo | undefined): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const socket = connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        // We are reading the presented certificate, not establishing trust, so an expired or
        // self-signed certificate must still be inspectable. That is exactly the case where
        // the information is most useful.
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          const cipher = socket.getCipher();
          const info: CertInfo = {};

          const subject = (cert.subject ?? {}) as Record<string, string>;
          const issuer = (cert.issuer ?? {}) as Record<string, string>;
          if (subject['O']) info.subjectOrg = subject['O'];
          if (subject['C']) info.subjectCountry = subject['C'];
          if (subject['ST']) info.subjectState = subject['ST'];
          if (subject['L']) info.subjectLocality = subject['L'];
          if (subject['CN']) info.subjectCommonName = subject['CN'];
          if (issuer['O'] || issuer['CN']) info.issuer = issuer['O'] ?? issuer['CN'];

          const protocol = socket.getProtocol();
          if (protocol) info.protocol = protocol;
          if (cipher?.name) info.cipher = cipher.name;
          if (cert.valid_from) info.validFrom = new Date(cert.valid_from).toISOString();
          if (cert.valid_to) {
            const validTo = new Date(cert.valid_to);
            info.validTo = validTo.toISOString();
            info.daysUntilExpiry = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);
          }
          if (typeof cert.subjectaltname === 'string') {
            info.altNames = cert.subjectaltname
              .split(',')
              .map((s) => s.trim().replace(/^DNS:/, ''))
              .slice(0, 50);
          }

          done(Object.keys(info).length > 0 ? info : undefined);
        } catch {
          done(undefined);
        } finally {
          socket.destroy();
        }
      },
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      done(undefined);
    });
    socket.on('error', () => {
      socket.destroy();
      done(undefined);
    });
  });
}

/**
 * Check the email authentication posture from DNS.
 *
 * SPF and DMARC presence is a genuine quality signal about an organisation's email hygiene,
 * and the DMARC policy (`p=none` versus `p=reject`) says whether the records are decorative
 * or enforced. CAA presence indicates deliberate certificate-issuance control.
 */
export async function inspectDnsSecurity(apex: string, timeoutMs = 6000): Promise<SecurityFields['dns']> {
  const resolver = new Resolver({ timeout: 4000, tries: 2 });
  const out: SecurityFields['dns'] = { spf: false, dmarc: false, caa: false };

  const settle = async <T>(p: Promise<T>): Promise<T | null> => {
    try {
      return await p;
    } catch {
      return null;
    }
  };

  const tasks = [
    settle(resolver.resolveTxt(apex)).then((records) => {
      const flat = (records ?? []).map((chunks) => chunks.join(''));
      const spf = flat.find((r) => /^v=spf1/i.test(r));
      if (spf) {
        out.spf = true;
        out.spfRecord = spf.slice(0, 400);
      }
    }),
    settle(resolver.resolveTxt(`_dmarc.${apex}`)).then((records) => {
      const flat = (records ?? []).map((chunks) => chunks.join(''));
      const dmarc = flat.find((r) => /^v=DMARC1/i.test(r));
      if (dmarc) {
        out.dmarc = true;
        out.dmarcRecord = dmarc.slice(0, 400);
        out.dmarcPolicy = dmarc.match(/\bp=([a-z]+)/i)?.[1]?.toLowerCase();
      }
    }),
    settle(resolver.resolveCaa(apex)).then((records) => {
      if (records && records.length > 0) out.caa = true;
    }),
    // A DKIM selector cannot be enumerated from DNS, so the common defaults are probed.
    // A hit proves DKIM; a miss proves nothing, hence the field stays undefined rather
    // than false when nothing is found.
    Promise.all(
      ['default', 'google', 'selector1', 'k1', 'mail', 's1'].map((selector) =>
        settle(resolver.resolveTxt(`${selector}._domainkey.${apex}`)),
      ),
    ).then((results) => {
      if (results.some((r) => r && r.length > 0)) out.dkim = true;
    }),
  ];

  const guard = new Promise<void>((resolve) => setTimeout(resolve, timeoutMs));
  await Promise.race([Promise.allSettled(tasks), guard]);
  return out;
}
