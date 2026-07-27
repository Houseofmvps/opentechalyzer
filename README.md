# Opentechalyzer

**Free, open source website technology detection. No subscription, no API key, no per-lookup credits.**

Point it at any URL and it tells you what the site is built with: platform, framework, backend,
hosting, CDN, payment processor, analytics, every installed Shopify app, and more. Then it goes
further than a stack list: contact details, social handles, TLS posture, estimated software
spend, known CVEs, subdomains, and technology changes over time.

It runs as a **CLI**, as a **TypeScript library**, and as an **MCP server** so Claude, Claude Code,
Codex, ChatGPT, Cursor and any other MCP client can use all of it directly.

```bash
npx opentechalyzer stripe.com
```

---

## Why this exists

Commercial technology-detection services put the useful parts behind a Business plan and meter
every lookup by credit. The detection itself is not the hard part, though: it is pattern matching
over signals any HTTP client can collect. What you are paying for is a fingerprint database and
a hosted crawl.

So this ships an MIT-licensed fingerprint database, collects a **wider set of signals** than the
commercial tools do, and gives you the whole thing for nothing. Where a paid service is genuinely
ahead, [that is stated plainly](#what-this-cannot-do) rather than glossed over.

## Install

```bash
npm install -g opentechalyzer
```

Or run it without installing:

```bash
npx opentechalyzer example.com
```

Two optional add-ons unlock more. Both are one-time and free:

```bash
npm i playwright && npx playwright install chromium
```

```bash
opentechalyzer db import && opentechalyzer db import-tranco
```

- **Playwright** enables `--render`, which roughly doubles what gets found. Tag managers, injected
  widgets and framework globals only exist after JavaScript runs.
- **`db import`** merges a community fingerprint dataset for long-tail coverage. **`db import-tranco`**
  enables traffic ranking from the free Tranco research list.

## Use it from Claude, Claude Code, Codex or ChatGPT

Opentechalyzer speaks MCP, so any MCP client gets all ten tools.

**Claude Code**

```bash
claude mcp add opentechalyzer -- npx -y opentechalyzer-mcp
```

**Claude Desktop**, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "opentechalyzer": {
      "command": "npx",
      "args": ["-y", "opentechalyzer-mcp"]
    }
  }
}
```

**Codex CLI**, in `~/.codex/config.toml`:

```toml
[mcp_servers.opentechalyzer]
command = "npx"
args = ["-y", "opentechalyzer-mcp"]
```

**Cursor, Windsurf and Zed** take the same command/args pair in their own MCP config.

### ChatGPT and claude.ai (browser clients)

These run in a browser and cannot spawn a local process, so the stdio command above will not
work for them. They need a reachable HTTPS endpoint instead:

```bash
opentechalyzer-mcp --http --port 3000
```

Then expose it and register the resulting `https://<your-url>/mcp` as a connector:

```bash
cloudflared tunnel --url http://localhost:3000
```

`GET /health` returns server status, which is handy for checking a tunnel is live.

> **The HTTP endpoint is unauthenticated.** Anyone who discovers the URL can run scans through
> your machine. Keep it behind a tunnel you control, put auth in front of it, or shut it down
> when you are finished. Do not park it on a public IP.

### Which clients work how

| Client | Transport | Works today |
| --- | --- | --- |
| Claude Code | stdio | Yes |
| Claude Desktop | stdio | Yes |
| Codex CLI | stdio | Yes |
| Cursor / Windsurf / Zed | stdio | Yes |
| ChatGPT (Developer Mode connectors) | HTTP | Yes, via `--http` + a public HTTPS URL |
| claude.ai (Custom Connectors) | HTTP | Yes, via `--http` + a public HTTPS URL |

Then just ask:

> What's shopify.com built with?
>
> Compare our stack against competitor.com and tell me what they have that we don't.
>
> Here are 20 prospect domains. Which ones run Shopify Plus, and what's their contact email?
>
> Does example.com have any known CVEs?

### Tools exposed over MCP

| Tool | What it does |
| --- | --- |
| `detect_tech_stack` | Full stack of one URL, with confidence and evidence per detection |
| `detect_tech_stack_batch` | Up to 25 URLs concurrently — bulk lookup |
| `compare_tech_stacks` | Two sites diffed into shared / only-A / only-B |
| `tech_stack_report` | Full markdown report, ready to paste into a doc |
| `find_subdomains` | Subdomain discovery via certificate transparency + DNS |
| `verify_email` | SMTP email verification without sending anything |
| `find_vulnerabilities` | CPE mapping plus live CVE lookup against NVD |
| `track_tech_changes` | Diff against a stored baseline to catch stack changes |
| `opentechalyzer_status` | Which capabilities and datasets are available |
| `import_external_database` | Pull in the optional wider fingerprint dataset |

## CLI

```bash
ota example.com                                   # quick scan
ota example.com --render --crawl --fields all -v  # everything
ota example.com -f json > stack.json
ota -i domains.txt -f csv -j 10 > stacks.csv      # bulk lookup
ota example.com --only cms,payment,analytics
ota subdomains example.com
ota verify sales@example.com
ota cve example.com
ota watch example.com                             # run on a cron for change alerts
```

`ota` is a short alias for `opentechalyzer`. Run `ota --help` for the full flag list.

### Bulk lookup

Put one domain per line in a file and pick a concurrency:

```bash
ota -i domains.txt -f csv -j 10 --fields contact,social,signals > enriched.csv
```

The CSV has one row per technology per URL, with version, account IDs and confidence. Failures are
reported per URL on stderr so one dead host never aborts a batch of thousands.

## Library

```ts
import { analyze } from 'opentechalyzer';

const result = await analyze('https://example.com', {
  render: true,
  crawl: 5,
  sourcemaps: true,
  fields: ['contact', 'social', 'security', 'signals'],
});

for (const tech of result.detections) {
  console.log(tech.name, tech.version ?? '', `${tech.confidence}%`, tech.evidence[0]?.match);
}
```

## What it detects

**588 built-in fingerprints** across 55 categories, plus whatever the optional external dataset adds.

- **Platforms and CMS** — Shopify, WordPress, Wix, Squarespace, Webflow, Ghost, Drupal, Magento,
  BigCommerce, Salesforce Commerce Cloud, AEM, Sitecore, Contentful, Sanity, Framer, Odoo, and more
- **Frameworks** — Next.js, Nuxt, Remix, SvelteKit, Astro, Gatsby, React, Vue, Angular, Svelte,
  Qwik, Solid, htmx, Alpine, Rails, Django, Laravel, Spring, ASP.NET, Phoenix, FastAPI
- **Infrastructure** — Cloudflare, Vercel, Netlify, Fastly, CloudFront, Akamai, Fly.io, Railway,
  Render, nginx, Apache, IIS, LiteSpeed, Caddy, plus DNS host and mail provider from DNS records
- **Global ecommerce platforms** — VTEX, commercetools, SAP Commerce Cloud, Elastic Path, Spryker,
  Medusa, Saleor, Swell, Vendure, Ecwid, Tiendanube/Nuvemshop, SHOPLINE, Big Cartel, Lightspeed,
  Shift4Shop, Volusion, OpenCart, nopCommerce, CS-Cart, Dukaan, StoreHippo, Shopify Hydrogen and
  Oxygen, Vue Storefront, Shogun
- **Ecommerce app ecosystem** — Shopify app blocks are enumerated by their extension handle, which
  is the most reliable way to list a store's installed apps: Judge.me, Yotpo, Recharge, Klaviyo,
  Gorgias, BOGOS, Rebuy, Loop Returns, Smile.io, Rivo, PushOwl, Swym, Videowise, Superfiliate,
  Redo, Tapcart, SearchTap, Reelfy, GoKwik, Shiprocket, AfterShip and many more
- **Global payments** — Mercado Pago, PayU, Paystack, Flutterwave, Midtrans, Xendit, dLocal, EBANX,
  Airwallex, Razorpay, Juspay, Simpl, CCAvenue, Instamojo, Amazon Pay, Google Pay, Authorize.net,
  Worldpay, Bolt, Klarna, Afterpay, Affirm
- **Logistics and tax** — ShipStation, Shippo, Sendcloud, Narvar, Loop Returns, ReturnGO, Delhivery,
  Nimbuspost, ClickPost, Avalara, TaxJar
- **Growth and CDP** — MoEngage, CleverTap, WebEngage, mParticle, Branch, AppsFlyer, Sprinklr,
  Fueled, Transcend
- **Everything else** — payments, auth, analytics, ad pixels, support widgets, search, APM, feature
  flags, A/B testing, consent tools, CAPTCHAs, bot protection, CSS/UI frameworks, JS libraries,
  fonts, media and maps

Account IDs are captured too, so you get `GTM-M92FB6B`, `G-MFK23BV2BG` or a Klaviyo public key
rather than just "Google Tag Manager is present".

## How it works

Nine signal sources, matched against the fingerprint database:

| Source | What it catches |
| --- | --- |
| Response headers | Server, framework, hosting, CDN, cache layer |
| Cookies | Framework session names — near-unique and hard to fake |
| HTML and meta | Generators, asset path conventions, inline markers |
| Rendered DOM and JS globals | Everything injected after load *(needs `--render`)* |
| Runtime network requests | Beacons and APIs that never appear in the DOM |
| First-party CSS | CSS frameworks, from the compiled output rather than class names |
| Sourcemaps and bundles | Exact npm dependency names and versions |
| DNS records | Mail provider, DNS host, and SaaS named in SPF includes |
| Well-known probes and favicon hash | Self-hosted software with no client-side fingerprint |

Three design decisions are worth knowing about, because they are where accuracy actually comes from:

**Confidence is combined probabilistically, not summed.** Each signal has a reliability, and
overall confidence is `1 - Π(1 - reliability)`. Repeated matches from the *same* source are damped,
so ten HTML regexes for one library cannot masquerade as ten independent observations. Summing
saturates at 100% as soon as you add enough weak matches, which is exactly how detectors end up
confidently wrong.

**CSS frameworks are detected from compiled CSS, not class names.** `flex items-center` looks like
Tailwind but any codebase can define those names. So Opentechalyzer downloads first-party
stylesheets and looks for `--tw-*` and `--bs-*` custom properties, which only exist if the
framework itself generated the file.

**Every detection carries its evidence.** `--verbose` shows exactly which header, cookie, selector
or dependency triggered each result. A result you cannot audit is a result you cannot trust.

## What this cannot do

Being straight about the limits, because a detector that overstates itself is worse than useless.

- **Backend is largely invisible.** A clean Go or Rails API serving JSON leaves no fingerprint. We
  report backend when it leaks through a header, cookie or error page, and stay quiet otherwise.
  For real backend intel, read the target's job listings.
- **No reverse lookup.** You cannot ask "list every site using Shopify". That needs a web-scale
  crawl of hundreds of millions of domains, which is the one thing a paid service genuinely has and
  this does not. For that, query the free [HTTP Archive](https://httparchive.org/) dataset on
  BigQuery, which is the same substrate those products are built on.
- **No company or people data.** Employee counts, revenue and org charts come from data brokers.
  Company name, locations and founding year are extracted when the site publishes them in
  structured data, and are labelled `inferred` when guessed.
- **Traffic rank comes from Tranco**, a free research list, not a proprietary panel.
- **Technology spend is a floor, not a bill.** It sums entry-level list prices for the paid tools we
  can see, to separate "hobby site" from "funded company buying software". Every contributing tool
  is listed so you can check the arithmetic.
- **Results are vantage-dependent.** Geo-redirects, device targeting and logged-in state change what
  a site serves. This tool was written after a scan from a US IP returned a completely different
  Shopify store than the same URL from India. Check more than one vantage point before you trust a
  single scan.
- **Email verification needs port 25.** Most cloud networks block outbound 25, in which case the
  verdict is `unknown` rather than a false negative. Use `--dns-only` for syntax and MX only.
- **Catch-all domains cannot be verified.** If a domain accepts every address, acceptance proves the
  domain works, not that the mailbox exists. Those are reported `risky`, never `safe`.
- **CVE results depend on version accuracy.** Versionless detections are skipped rather than matched
  against every release ever published. Confirm a version before acting on a CVE.

## Fingerprint database and licensing

The built-in database in `src/fingerprints/` is **written for this project and MIT licensed**. It is
not a copy of anyone else's dataset.

The most complete open dataset available is the community-maintained Wappalyzer technologies set
([enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)), which is **GPL-3.0**. Vendoring
GPL-3.0 data here would force this entire project to become GPL-3.0 and stop you embedding it in
your own products, which is the exact freedom this exists to provide. So it is never redistributed:
`opentechalyzer db import` fetches it to *your* machine, at *your* request, and it stays under its
own licence. Everything works without it.

## Contributing

Adding a technology is one object in the right file under `src/fingerprints/`:

```ts
{
  name: 'Your Technology',
  categories: ['analytics'],
  website: 'https://example.com',
  scriptSrc: ['cdn\\.example\\.com/tracker\\.js'],
  js: { yourGlobal: '' },
  cookies: { '^_yt_session$': '' },
  implies: ['JavaScript'],
}
```

Guidelines that keep accuracy up:

1. **Prefer specific signals.** A cookie name or JS global beats an HTML substring.
2. **Never use a bare status-code probe.** Always require a body pattern; a 401 from `/api/` proves
   nothing and produced several false positives during development.
3. **Set `caseSensitive: true` for identifier patterns.** `G-[A-Z0-9]{9,12}` matched `g-recaptcha`
   until this existed.
4. **Use `id` for account identifiers, `version` for versions.** `GTM-M92FB6B` is not a version.
5. **Verify favicon hashes against a real instance.** A guessed hash is worse than no signal.

`npm test` enforces unique names, valid regexes, resolvable `implies`/`requires` targets, and that
every `version` template has a matching capture group.

## Accuracy benchmark

Accuracy is measured, not asserted. The benchmark scans a fixed set of sites whose stacks were
verified by hand (headers, cookies, `meta[generator]`, checked with curl) and scores the output
against that ground truth:

```bash
npm run benchmark
```

```
site                found    notes
------------------------------------------------------
gitlab.com          3/3      clean
discourse.org       2/2      clean
djangoproject.com   4/4      clean
laravel.com         5/5      clean
vercel.com          4/4      clean
squarespace.com     1/1      clean
wix.com             2/2      clean
bigcommerce.com     3/3      clean
ghost.org           2/2      clean
basecamp.com        1/1      clean
------------------------------------------------------
Recall                 27/27 = 100%  (threshold 90%)
Hard false positives   0             (threshold 0)
```

It fails on a **single** hard false positive, and only budgets misses. That asymmetry is
deliberate: "we could not tell" is a usable answer, while "this Wix site runs Laravel" poisons a
lead list and discredits every other row.

Running it is the fastest way to catch a regression after editing fingerprints, and it is how
every accuracy bug fixed so far was found, including one where bulk mode silently dropped
detections at `-j 5` because probes were timing out. It is intentionally **not** part of
`npm test`: it hits live third-party sites, so a green CI run must never depend on someone
else's deploy schedule.

`--json` gives machine-readable output; `--jobs N` changes concurrency. Ground truth lives in
`scripts/benchmark.ts`, each case annotated with how it was verified.

## Development

```bash
npm install && npm run build && npm test
npm run benchmark   # live accuracy check, needs network
```

## Licence

MIT. Use it commercially, embed it, fork it, resell it. No attribution required.
