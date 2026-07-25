import { Resolver } from 'node:dns/promises';
import { createConnection, type Socket } from 'node:net';

/**
 * Email address verification, matching the field shape of a commercial verification API.
 *
 * The method is the standard one: validate syntax, resolve MX, open an SMTP session and issue
 * `RCPT TO` without ever sending `DATA`. Nothing is delivered, so no recipient is contacted.
 *
 * Two honest caveats, both reported in the result rather than hidden:
 *
 *  1. Catch-all domains accept every address, so a positive result there means "the domain
 *     accepts mail", not "this mailbox exists". We detect this by probing a random address
 *     and downgrade the verdict to `risky` when it is accepted.
 *  2. Many networks, including most cloud providers, block outbound port 25. When that
 *     happens the verdict is `unknown` and `connection` is false, which is a transport
 *     failure and not evidence about the address.
 */

export type Reachability = 'safe' | 'risky' | 'invalid' | 'unknown';

export interface EmailVerification {
  email: string;
  domain: string;
  reachable: Reachability;
  syntaxValid: boolean;
  mxValid: boolean;
  mxHosts: string[];
  connection: boolean;
  deliverable: boolean;
  catchAll: boolean;
  disposable: boolean;
  roleAccount: boolean;
  freeProvider: boolean;
  inboxFull: boolean;
  disabled: boolean;
  /** Why the verdict is what it is. Present when the result is not a clean pass. */
  reason?: string;
}

/**
 * Role accounts belong to a function rather than a person. They are valid but poor outreach
 * targets, which is why they are flagged separately instead of being rejected.
 */
const ROLE_LOCAL_PARTS = new Set([
  'admin', 'administrator', 'billing', 'careers', 'compliance', 'contact', 'enquiries', 'enquiry',
  'finance', 'help', 'hello', 'hi', 'hr', 'info', 'information', 'jobs', 'legal', 'mail',
  'marketing', 'media', 'newsletter', 'noreply', 'no-reply', 'office', 'orders', 'partners',
  'postmaster', 'press', 'privacy', 'sales', 'security', 'support', 'team', 'webmaster',
  'accounts', 'accounting', 'abuse', 'feedback', 'general', 'inquiries', 'service', 'services',
]);

const FREE_PROVIDERS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.in', 'hotmail.com',
  'outlook.com', 'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
  'protonmail.com', 'proton.me', 'gmx.com', 'gmx.de', 'yandex.com', 'yandex.ru', 'mail.com',
  'zoho.com', 'rediffmail.com', 'qq.com', '163.com', '126.com', 'naver.com', 'daum.net',
]);

/**
 * Known disposable providers. This list is intentionally partial and self-documenting:
 * a complete list is a moving target, so `disposable: false` means "not on our list", not
 * "definitely permanent".
 */
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', '10minutemail.com', 'tempmail.com',
  'temp-mail.org', 'throwawaymail.com', 'yopmail.com', 'trashmail.com', 'sharklasers.com',
  'getnada.com', 'dispostable.com', 'maildrop.cc', 'fakeinbox.com', 'mytemp.email',
  'mohmal.com', 'emailondeck.com', 'tempinbox.com', 'spamgourmet.com', 'mailnesia.com',
  'discard.email', 'mailcatch.com', 'inboxbear.com', 'harakirimail.com', 'moakt.com',
  'burnermail.io', 'anonaddy.com', 'simplelogin.io', 'relay.firefox.com', 'duck.com',
]);

// Deliberately strict but not RFC-exhaustive: quoted local parts and IP-literal domains are
// legal but essentially never appear in real prospect data, and allowing them widens the
// surface for injection into the SMTP dialogue below.
const SYNTAX_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export interface VerifyOptions {
  /** Skip the SMTP conversation and report only syntax plus MX. Default false. */
  dnsOnly?: boolean;
  /** SMTP timeout in ms. Default 10000. */
  timeout?: number;
  /** HELO name and MAIL FROM domain. Should be a domain you control. */
  heloDomain?: string;
  mailFrom?: string;
}

export async function verifyEmail(
  email: string,
  options: VerifyOptions = {},
): Promise<EmailVerification> {
  const normalised = email.trim().toLowerCase();
  const domain = normalised.split('@')[1] ?? '';
  const localPart = normalised.split('@')[0] ?? '';

  const result: EmailVerification = {
    email: normalised,
    domain,
    reachable: 'unknown',
    syntaxValid: SYNTAX_RE.test(normalised),
    mxValid: false,
    mxHosts: [],
    connection: false,
    deliverable: false,
    catchAll: false,
    disposable: DISPOSABLE_DOMAINS.has(domain),
    roleAccount: ROLE_LOCAL_PARTS.has(localPart.replace(/[.+].*$/, '')),
    freeProvider: FREE_PROVIDERS.has(domain),
    inboxFull: false,
    disabled: false,
  };

  if (!result.syntaxValid) {
    result.reachable = 'invalid';
    result.reason = 'Address is not syntactically valid';
    return result;
  }

  const resolver = new Resolver({ timeout: 4000, tries: 2 });
  try {
    const mx = await resolver.resolveMx(domain);
    result.mxHosts = mx.sort((a, b) => a.priority - b.priority).map((r) => r.exchange).slice(0, 5);
    result.mxValid = result.mxHosts.length > 0;
  } catch {
    result.mxValid = false;
  }

  if (!result.mxValid) {
    result.reachable = 'invalid';
    result.reason = 'Domain has no MX records, so it cannot receive mail';
    return result;
  }

  if (options.dnsOnly) {
    result.reason = 'DNS-only mode: SMTP verification was not attempted';
    return result;
  }

  const host = result.mxHosts[0] as string;
  const probe = await smtpProbe(host, normalised, domain, options);
  result.connection = probe.connected;

  if (!probe.connected) {
    result.reachable = 'unknown';
    result.reason =
      'Could not open an SMTP session. Outbound port 25 is blocked on most cloud networks, ' +
      'so this is a transport limitation rather than a finding about the address.';
    return result;
  }

  result.deliverable = probe.accepted;
  result.catchAll = probe.catchAll;
  result.inboxFull = probe.inboxFull;
  result.disabled = probe.disabled;

  if (probe.inboxFull) {
    result.reachable = 'risky';
    result.reason = 'Mailbox is full';
  } else if (probe.disabled) {
    result.reachable = 'invalid';
    result.reason = 'Mailbox is disabled';
  } else if (!probe.accepted) {
    result.reachable = 'invalid';
    result.reason = probe.lastResponse ? `Server rejected the recipient: ${probe.lastResponse}` : 'Server rejected the recipient';
  } else if (probe.catchAll) {
    result.reachable = 'risky';
    result.reason =
      'Domain is catch-all: it accepts every address, so acceptance does not prove this mailbox exists';
  } else if (result.disposable) {
    result.reachable = 'risky';
    result.reason = 'Disposable email provider';
  } else if (result.roleAccount) {
    result.reachable = 'risky';
    result.reason = 'Role account rather than an individual mailbox';
  } else {
    result.reachable = 'safe';
  }

  return result;
}

interface SmtpProbeResult {
  connected: boolean;
  accepted: boolean;
  catchAll: boolean;
  inboxFull: boolean;
  disabled: boolean;
  lastResponse?: string;
}

/**
 * Hold one SMTP conversation and test both the real address and a random one.
 *
 * The random probe is what distinguishes a real mailbox from a catch-all domain, and doing
 * both in a single session avoids being rate-limited into a false negative.
 */
async function smtpProbe(
  host: string,
  email: string,
  domain: string,
  options: VerifyOptions,
): Promise<SmtpProbeResult> {
  const timeout = options.timeout ?? 10_000;
  const helo = options.heloDomain ?? 'opentechalyzer.local';
  const mailFrom = options.mailFrom ?? `verify@${helo}`;
  const out: SmtpProbeResult = {
    connected: false,
    accepted: false,
    catchAll: false,
    inboxFull: false,
    disabled: false,
  };

  // A fixed-length pseudo-random local part. Any address that does not plausibly exist works;
  // the point is only that the server has no such mailbox.
  const randomLocal = `ota-probe-${Array.from({ length: 12 }, (_, i) => 'abcdefghijklmnopqrstuvwxyz0123456789'[(email.charCodeAt(i % email.length) * (i + 7)) % 36]).join('')}`;
  const randomAddress = `${randomLocal}@${domain}`;

  return new Promise<SmtpProbeResult>((resolve) => {
    let socket: Socket;
    try {
      socket = createConnection({ host, port: 25 });
    } catch {
      resolve(out);
      return;
    }

    let buffer = '';
    let stage = 0;
    let finished = false;

    const finish = (): void => {
      if (finished) return;
      finished = true;
      try {
        socket.write('QUIT\r\n');
      } catch {
        /* already closed */
      }
      socket.destroy();
      resolve(out);
    };

    const send = (line: string): void => {
      try {
        socket.write(`${line}\r\n`);
      } catch {
        finish();
      }
    };

    socket.setTimeout(timeout, finish);
    socket.on('error', finish);
    socket.on('close', () => {
      if (!finished) {
        finished = true;
        resolve(out);
      }
    });

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      // SMTP replies can be multi-line; only act on the final line of a reply.
      if (!/\r\n$/.test(buffer)) return;
      const lines = buffer.trim().split(/\r\n/);
      const last = lines.at(-1) ?? '';
      if (/^\d{3}-/.test(last)) return; // continuation, wait for more
      const code = Number(last.slice(0, 3));
      out.lastResponse = last.slice(0, 160);
      buffer = '';

      switch (stage) {
        case 0: // greeting
          out.connected = code === 220;
          if (!out.connected) return finish();
          stage = 1;
          send(`EHLO ${helo}`);
          return;
        case 1: // EHLO
          if (code >= 500) {
            stage = 2;
            send(`HELO ${helo}`);
            return;
          }
          stage = 3;
          send(`MAIL FROM:<${mailFrom}>`);
          return;
        case 2: // HELO fallback
          stage = 3;
          send(`MAIL FROM:<${mailFrom}>`);
          return;
        case 3: // MAIL FROM
          if (code !== 250) return finish();
          stage = 4;
          send(`RCPT TO:<${email}>`);
          return;
        case 4: // RCPT TO for the real address
          out.accepted = code === 250 || code === 251;
          if (/full|quota|over.?quota|insufficient system storage/i.test(last)) out.inboxFull = true;
          if (/disabled|inactive|suspended/i.test(last)) out.disabled = true;
          stage = 5;
          send(`RCPT TO:<${randomAddress}>`);
          return;
        case 5: // RCPT TO for the random address
          if (code === 250 || code === 251) out.catchAll = true;
          return finish();
        default:
          return finish();
      }
    });
  });
}
