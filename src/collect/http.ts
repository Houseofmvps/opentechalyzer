import type { AnalyzeOptions } from '../types.js';

export const DEFAULT_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Opentechalyzer/0.1';

export interface FetchedPage {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
}

export function normaliseUrl(input: string): string {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

/** Fetch with a hard timeout, returning headers, raw Set-Cookie lines and the body. */
export async function fetchPage(
  url: string,
  opts: AnalyzeOptions = {},
  init: RequestInit = {},
): Promise<FetchedPage> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeout ?? 15_000);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': opts.userAgent ?? DEFAULT_UA,
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        ...(opts.headers ?? {}),
        ...((init.headers as Record<string, string>) ?? {}),
      },
      ...init,
    });

    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    let setCookies: string[] = [];
    const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] })
      .getSetCookie;
    if (typeof getSetCookie === 'function') {
      setCookies = getSetCookie.call(res.headers);
    } else if (headers['set-cookie']) {
      setCookies = [headers['set-cookie']];
    }

    const contentType = headers['content-type'] ?? '';
    const isText = /text|json|xml|javascript|ecmascript/i.test(contentType) || contentType === '';
    const body = isText ? await res.text() : '';

    return { finalUrl: res.url || url, status: res.status, headers, setCookies, body };
  } finally {
    clearTimeout(timer);
  }
}

/** Fetch raw bytes, used for favicon hashing. */
export async function fetchBuffer(
  url: string,
  opts: AnalyzeOptions = {},
): Promise<Uint8Array | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeout ?? 15_000);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'user-agent': opts.userAgent ?? DEFAULT_UA },
    });
    if (!res.ok) return null;
    return new Uint8Array(await res.arrayBuffer());
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const SCRIPT_SRC_RE = /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
const INLINE_SCRIPT_RE = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]{0,20000}?)<\/script>/gi;
const LINK_HREF_RE = /<link\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
const META_RE = /<meta\b[^>]*>/gi;
const ATTR_RE = /([a-zA-Z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;

function attrs(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  ATTR_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ATTR_RE.exec(tag)) !== null) {
    const key = (m[1] ?? '').toLowerCase();
    out[key] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return out;
}

export interface ParsedHtml {
  scriptSrcs: string[];
  scriptContents: string[];
  stylesheetSrcs: string[];
  metas: Record<string, string>;
  title?: string;
}

/**
 * Extract the structural signals we match against.
 *
 * A full HTML parser is deliberately avoided: the input is arbitrary, often malformed,
 * frequently multi-megabyte, and we only need attribute values. Regex extraction keeps
 * the dependency tree at effectively zero and is a few hundred times faster.
 */
export function parseHtml(html: string, baseUrl: string): ParsedHtml {
  const scriptSrcs: string[] = [];
  const scriptContents: string[] = [];
  const stylesheetSrcs: string[] = [];
  const metas: Record<string, string> = {};

  let m: RegExpExecArray | null;

  SCRIPT_SRC_RE.lastIndex = 0;
  while ((m = SCRIPT_SRC_RE.exec(html)) !== null) {
    const raw = m[1] ?? m[2] ?? m[3];
    if (raw) scriptSrcs.push(absolutise(raw, baseUrl));
  }

  INLINE_SCRIPT_RE.lastIndex = 0;
  while ((m = INLINE_SCRIPT_RE.exec(html)) !== null) {
    const body = m[1];
    if (body && body.trim()) scriptContents.push(body);
  }

  LINK_HREF_RE.lastIndex = 0;
  while ((m = LINK_HREF_RE.exec(html)) !== null) {
    const tag = m[0];
    const raw = m[1] ?? m[2] ?? m[3];
    if (!raw) continue;
    const a = attrs(tag);
    const rel = (a['rel'] ?? '').toLowerCase();
    if (rel.includes('stylesheet') || rel.includes('preload') || rel.includes('modulepreload')) {
      stylesheetSrcs.push(absolutise(raw, baseUrl));
    }
  }

  META_RE.lastIndex = 0;
  while ((m = META_RE.exec(html)) !== null) {
    const a = attrs(m[0]);
    const key = a['name'] ?? a['property'] ?? a['http-equiv'] ?? a['itemprop'];
    const content = a['content'];
    if (key && content !== undefined) metas[key.toLowerCase()] = content;
  }

  const titleMatch = html.match(/<title\b[^>]*>([\s\S]{0,300}?)<\/title>/i);
  const rawTitle = titleMatch?.[1]?.replace(/\s+/g, ' ').trim();

  return {
    scriptSrcs,
    scriptContents,
    stylesheetSrcs,
    metas,
    title: rawTitle ? decodeEntities(rawTitle) : undefined,
  };
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  ndash: '-',
  mdash: '-',
  hellip: '...',
  rsquo: "'",
  lsquo: "'",
  rdquo: '"',
  ldquo: '"',
  trade: '(TM)',
  reg: '(R)',
  copy: '(C)',
};

/** Decode the handful of HTML entities that actually show up in titles and meta content. */
export function decodeEntities(input: string): string {
  return input
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => safeCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => safeCodePoint(parseInt(dec, 10)))
    .replace(/&([a-z]+);/gi, (whole, name: string) => NAMED_ENTITIES[name.toLowerCase()] ?? whole);
}

function safeCodePoint(code: number): string {
  if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return '';
  try {
    return String.fromCodePoint(code);
  } catch {
    return '';
  }
}

export function absolutise(href: string, base: string): string {
  try {
    return new URL(href, base).toString();
  } catch {
    return href;
  }
}

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

/** Registrable-ish domain, good enough for grouping first vs third party. */
export function apexOf(hostname: string): string {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return hostname;
  const twoLevelTlds = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.in', 'net.in', 'org.in', 'co.jp',
    'com.au', 'net.au', 'org.au', 'co.nz', 'com.br', 'com.mx', 'co.za', 'com.sg',
    'com.tr', 'co.kr', 'com.cn', 'com.hk', 'com.tw',
  ]);
  const lastTwo = parts.slice(-2).join('.');
  if (twoLevelTlds.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}
