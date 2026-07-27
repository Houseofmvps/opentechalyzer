# Opentechalyzer

**Free, open source website technology detection. No subscription, no API key, no per-lookup credits.**

Point it at any URL and it tells you what the site is built with, who they buy software from, how
to contact them, what security posture they have, and which known CVEs affect their stack. Point it
the other way and it tells you every site running a given technology.

Runs as a **CLI**, a **TypeScript library**, and an **MCP server** so Claude, Claude Code, Codex,
ChatGPT and Cursor can use all of it directly.

```bash
npx opentechalyzer stripe.com
```

> **Cost:** everything runs on your machine. No hosted service, no account, no API key, nothing to
> pay. The single exception is [`ota reverse`](#does-this-cost-me-anything), which queries a public
> dataset on **your own** Google Cloud project and is free under Google's 1 TB monthly allowance.

---

## Contents

- [What you get](#what-you-get)
- [Install](#install)
- [Commands](#commands)
- [Enrichment field sets](#enrichment-field-sets)
- [Use it from Claude, ChatGPT, Codex](#use-it-from-claude-chatgpt-codex)
- [Library API](#library-api)
- [Output formats](#output-formats)
- [Reverse lookup](#reverse-lookup-find-every-site-using-a-technology)
- [What it detects](#what-it-detects)
- [How it works](#how-it-works)
- [Accuracy benchmark](#accuracy-benchmark)
- [What it cannot do](#what-it-cannot-do)
- [Contributing](#contributing)

---

## What you get

| Capability | Command | What comes back |
| --- | --- | --- |
| **Full tech stack** of a URL | `ota example.com` | 588 fingerprints across 55 categories, each with a confidence score and the evidence behind it |
| **Bulk lookup** | `ota -i domains.txt -f csv -j 10` | One row per technology per URL. Thousands of domains, no rate limit, no credits |
| **Contact details** | `ota example.com --crawl --fields contact` | Emails, phone numbers, WhatsApp, found by crawling contact and about pages |
| **Social handles** | `--fields social` | X, LinkedIn, Instagram, Facebook, YouTube, TikTok, GitHub, Pinterest |
| **Company info** | `--fields company` | Name, locations, founding year, description, from structured data |
| **Security posture** | `--fields security` | TLS certificate, issuer, expiry, plus SPF, DMARC, DKIM and CAA records |
| **Software spend estimate** | `--fields signals` | A floor estimate in USD/month, itemised by the paid tools detected |
| **Traffic rank** | `--fields signals` | Popularity rank via the free Tranco list |
| **Locale** | `--fields locale` | Language, all languages served, country, currencies |
| **Metadata** | `--fields meta` | Title, description, copyright year, schema.org types, keywords |
| **Known CVEs** | `ota cve example.com` | CPE identifiers mapped to live CVE data from NVD |
| **Subdomains** | `ota subdomains example.com` | Certificate transparency plus DNS probing, each result resolve-checked |
| **Email verification** | `ota verify sales@example.com` | SMTP check without sending. safe / risky / invalid, plus catch-all and role flags |
| **Change tracking** | `ota watch example.com` | Diff against a stored baseline. Run on a cron for buying-signal alerts |
| **Reverse lookup** | `ota reverse --tech Shopify` | Every site running a technology, via HTTP Archive |
| **Compare two sites** | MCP `compare_tech_stacks` | Shared / only-A / only-B |
| **Markdown report** | `ota example.com -f markdown` | Tables grouped by category, ready to paste into a doc |

Every detection carries an **auditable evidence trail**. Run with `--verbose` and you see exactly
which header, cookie, DOM selector or npm dependency triggered each result.

---

## Install

```bash
npm install -g opentechalyzer
```

Or without installing:

```bash
npx opentechalyzer example.com
```

Requires Node 18.17 or newer. Two optional add-ons unlock more, both free and one-time:

```bash
npm i playwright && npx playwright install chromium
```

```bash
opentechalyzer db import && opentechalyzer db import-tranco
```

| Add-on | Unlocks | Why bother |
| --- | --- | --- |
| **Playwright** | `--render` | Roughly doubles what is found. Tag managers, injected widgets and framework globals only exist after JavaScript runs |
| **`db import`** | Wider fingerprint coverage | Merges a community dataset for long-tail technologies |
| **`db import-tranco`** | `trafficRank` | Popularity ranking from the free Tranco research list |

---

## Commands

### Scan a site

```bash
ota example.com                                    # quick scan
ota example.com --render                           # + JS-injected technologies
ota example.com --crawl                            # + inner pages (checkout, contact, about)
ota example.com --sourcemaps                       # + exact npm dependencies from sourcemaps
ota example.com --fields all --verbose             # everything, with evidence
ota example.com --only cms,payment,analytics       # just the categories you care about
```

### Bulk lookup

```bash
ota -i domains.txt -f csv -j 10 > stacks.csv
ota -i domains.txt --fields contact,social -f csv -j 10 > enriched.csv
```

One domain per line, `#` for comments. Failures are reported per URL on stderr, so one dead host
never aborts a batch of thousands. Bare apex domains that only serve `www` are retried
automatically, and the substitution is recorded as a warning.

### Subdomain discovery

```bash
ota subdomains example.com
ota subdomains example.com -f json
```

Combines certificate transparency logs with DNS probing of common labels, then resolves every
result so dead entries are marked rather than silently included. Often surfaces internal tooling
that is not linked from anywhere: `grafana.`, `jenkins.`, `metabase.`, `argocd.`, `vault.`

### Email verification

```bash
ota verify sales@example.com
ota verify a@x.com b@y.com --dns-only
```

Validates syntax, resolves MX, then opens an SMTP session and issues `RCPT TO` without ever sending
`DATA`. Nothing is delivered. Returns `safe` / `risky` / `invalid` / `unknown` plus catch-all,
role-account, disposable and free-provider flags.

Two honest caveats, both reported in the result rather than hidden. Most networks block outbound
port 25, in which case the verdict is `unknown` and not a false negative, so use `--dns-only` there.
And catch-all domains accept every address, so acceptance proves the domain works, not that the
mailbox exists; those are always reported `risky`, never `safe`.

### Vulnerability lookup

```bash
ota cve example.com
NVD_API_KEY=... ota cve example.com     # free key raises the rate limit
```

Maps detected technologies to CPE identifiers and queries the public NVD database. Technologies
without a confidently detected **version** are skipped rather than matched against every release
ever published, because that would produce a long and meaningless list.

### Change tracking

```bash
ota watch example.com        # first run stores a baseline
ota watch example.com        # later runs report what changed
ota watch --list
```

Reports technologies added, removed or version-changed since the last run. Snapshots are stored
locally; nothing is uploaded. Put it on a cron for competitor buying signals, for example a
competitor adding Klaviyo or dropping Shopify Plus.

### Reverse lookup

```bash
ota reverse --tech Shopify --tech Klaviyo --rank 100000
```

See [the full section below](#reverse-lookup-find-every-site-using-a-technology).

### Database management

```bash
ota db status              # what is installed
ota db import              # wider fingerprint coverage
ota db import-tranco       # traffic ranking
```

### Full flag reference

| Flag | Effect |
| --- | --- |
| `-r, --render` | Headless browser render. Needs playwright |
| `-s, --sourcemaps` | Parse sourcemaps for exact npm dependency names |
| `-w, --crawl [n]` | Follow up to n internal pages, default 5 |
| `-F, --fields <sets>` | Enrichment sets, comma separated, or `all` |
| `-c, --certs` | Certificate transparency subdomain lookup |
| `--intrusive` | Include probes for `/.git/HEAD` and `/.env` |
| `--no-dns` `--no-probe` `--no-favicon` `--no-css` | Skip individual collectors |
| `--no-external` | Ignore any imported external database |
| `-f, --format <fmt>` | `text` `json` `markdown` `csv` `summary` |
| `-o, --only <cats>` | Restrict output to categories |
| `-m, --min <n>` | Minimum confidence, default 25 |
| `-v, --verbose` | Show the evidence behind every detection |
| `-q, --quiet` | Suppress progress output |
| `-t, --timeout <ms>` | Per-request timeout, default 15000 |
| `-j, --jobs <n>` | Concurrency for multiple URLs, default 5 |
| `-i, --input <file>` | Read newline-separated URLs from a file |
| `-A, --user-agent <ua>` | Override the User-Agent |
| `--categories` | List all 55 categories |

---

## Enrichment field sets

Pass with `--fields`, comma separated, or `all`.

| Set | Fields returned |
| --- | --- |
| `meta` | title, description, copyright, copyrightYear, schemaOrgTypes |
| `keywords` | Content keywords, declared plus frequency-derived |
| `company` | companyName, inferredCompanyName, about, locations, companyFounded |
| `contact` | email, phone, whatsapp |
| `social` | x, facebook, instagram, linkedin, github, youtube, tiktok, pinterest |
| `locale` | language, languages, ipCountry, ipCountries, currencies |
| `security` | certInfo (org, country, issuer, protocol, expiry, altNames), dns.spf, dns.dmarc, dns.dkim, dns.caa |
| `signals` | technologySpend, technologySpendMonthlyFloorUsd, spend drivers, trafficRank, trafficLevel |

**Pair `--fields contact,social` with `--crawl`.** Contact details and social handles live on
contact and about pages, essentially never on the homepage.

`companyName` comes from structured data and is trustworthy. `inferredCompanyName` is a best guess
from the page title and is labelled as such, because the difference matters when it feeds a CRM.

---

## Use it from Claude, ChatGPT, Codex

Opentechalyzer speaks MCP, so any MCP client gets all eleven tools.

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

These run in a browser and cannot spawn a local process, so the stdio command above will not work
for them. They need a reachable HTTPS endpoint:

```bash
opentechalyzer-mcp --http --port 3000
```

Expose it and register the resulting `https://<your-url>/mcp` as a connector:

```bash
cloudflared tunnel --url http://localhost:3000
```

`GET /health` returns server status, handy for checking a tunnel is live.

> **The HTTP endpoint is unauthenticated.** Anyone who discovers the URL can run scans through your
> machine. Keep it behind a tunnel you control, put auth in front of it, or shut it down when you
> are finished. Do not park it on a public IP.

| Client | Transport | Works |
| --- | --- | --- |
| Claude Code | stdio | Yes |
| Claude Desktop | stdio | Yes |
| Codex CLI | stdio | Yes |
| Cursor / Windsurf / Zed | stdio | Yes |
| ChatGPT (Developer Mode) | HTTP | Yes, via `--http` and a public HTTPS URL |
| claude.ai (Custom Connectors) | HTTP | Yes, via `--http` and a public HTTPS URL |

### The eleven MCP tools

| Tool | What it does |
| --- | --- |
| `detect_tech_stack` | Full stack of one URL, with confidence and evidence |
| `detect_tech_stack_batch` | Up to 25 URLs concurrently |
| `compare_tech_stacks` | Two sites diffed into shared / only-A / only-B |
| `tech_stack_report` | Full markdown report |
| `reverse_lookup` | Every site using a technology, via HTTP Archive |
| `find_subdomains` | Certificate transparency plus DNS discovery |
| `verify_email` | SMTP verification without sending |
| `find_vulnerabilities` | CPE mapping plus live NVD CVE lookup |
| `track_tech_changes` | Diff against a stored baseline |
| `opentechalyzer_status` | Which capabilities and datasets are available |
| `import_external_database` | Pull in the optional wider dataset |

Then just ask:

> What's shopify.com built with?
>
> Compare our stack against competitor.com and tell me what they have that we don't.
>
> Here are 20 prospect domains. Which run Shopify Plus, and what's their contact email?
>
> Find 200 Shopify stores in the top 100k using Klaviyo but not Gorgias.
>
> Does example.com have any known CVEs?

---

## Library API

```ts
import { analyze, analyzeMany } from 'opentechalyzer';

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

Exports: `analyze`, `analyzeMany`, `detect`, `combineConfidence`, `getFingerprints`,
`BUILTIN_FINGERPRINTS`, `DATABASE_VERSION`, `listCategories`, `clearFingerprintCache`,
`importExternalDatabase`, `loadExternalDatabase`, `externalDatabaseStatus`, `externalDbPath`,
`EXTERNAL_DB_LICENSE_NOTICE`, `isRenderAvailable`, `formatTerminal`, `formatMarkdown`, `formatCsv`,
`summarise`, plus all types.

---

## Output formats

| Format | Use for |
| --- | --- |
| `text` | Reading in a terminal. Grouped by category, colour-coded by confidence |
| `json` | Piping into `jq` or a script. Full evidence trail and timings included |
| `markdown` | Pasting into a doc or ticket. Tables per category |
| `csv` | Spreadsheets and CRMs. One row per technology per URL |
| `summary` | Compact one-line-per-category. Ideal for LLM context |

The JSON shape:

```jsonc
{
  "url": "…", "finalUrl": "…", "status": 200,
  "detections": [{
    "name": "Shopify", "categories": ["ecommerce", "platform"],
    "version": "…", "accountIds": ["GTM-M92FB6B"],
    "confidence": 100, "inferred": false,
    "evidence": [{ "source": "header", "subject": "powered-by", "match": "Shopify", "reliability": 0.88 }]
  }],
  "byCategory": { "ecommerce": [ "…" ] },
  "enrichment": { "contact": {}, "social": {}, "security": {}, "signals": {}, "cpes": [] },
  "crawledPages": ["…"],
  "meta": { "title": "…", "description": "…", "ip": "…" },
  "warnings": ["…"],
  "timings": { "fetch": 518, "css": 282, "dns": 290, "probe": 3688, "detect": 551 },
  "databaseVersion": "0.2.0", "fingerprintCount": 588, "analyzedAt": "…"
}
```

---

## Reverse lookup: find every site using a technology

The inverse of a scan. Instead of "what does this site run?", ask "which sites run this?", the
question that turns a detector into a lead-sourcing tool.

### Examples

**Build a prospect list.** Shopify stores also running Klaviyo, inside the top 100k:

```bash
ota reverse --tech Shopify --tech Klaviyo --rank 100000
```

**Competitive displacement.** Sites on a competitor's tool but not yours:

```bash
ota reverse --tech Yotpo --not-tech "Judge.me" --limit 500 -f csv > switch-targets.csv
```

**Market sizing.** How much of the top 10k is in a given category:

```bash
ota reverse --category Ecommerce --rank 10000 --limit 10000 -f json | jq '.rows | length'
```

**Agency prospecting.** Old stack, no analytics, usually means somebody needs help:

```bash
ota reverse --tech WooCommerce --not-tech "Google Analytics" --rank 1000000 --limit 1000
```

**Cost-check first.** Prints the SQL and byte estimate, bills nothing:

```bash
ota reverse --tech Shopify --dry-run
```

**Chain it into a real scan.** Reverse lookup finds candidates, a direct scan verifies them and
pulls contact details. This is the full lead pipeline:

```bash
ota reverse --tech Shopify --tech Recharge --rank 100000 -f json | jq -r '.rows[].page' > leads.txt
ota -i leads.txt --crawl --fields contact,social,signals -f csv -j 10 > enriched.csv
```

### Reverse lookup flags

| Flag | Effect |
| --- | --- |
| `--tech <name>` | Must be present. Repeatable, ANDed |
| `--not-tech <name>` | Must be absent. Repeatable |
| `--category <name>` | Match a category instead, e.g. `Ecommerce` |
| `--rank <n>` | Only sites within the top n by popularity. **Biggest lever on cost** |
| `--client <c>` | `desktop` or `mobile`, default mobile |
| `--date <YYYY-MM-01>` | Crawl month, default two months back |
| `-l, --limit <n>` | Max sites, default 100, max 10000 |
| `--max-bytes <n>` | Cost ceiling, default 200 GB |
| `--dry-run` | Estimate and print SQL, run nothing |

### Does this cost me anything?

**Opentechalyzer itself is free and always will be.** It is MIT, runs entirely on your machine, with
no hosted service, no account and no API key. We run no servers, so there is nothing for us to
charge for and nothing for us to pay for. Every other command, scanning, enrichment, subdomains, CVE
lookup, email verification, change tracking, costs exactly nothing.

`ota reverse` is the single exception, and the cost is neither ours nor for hosting:

- Answering "which sites use Shopify" requires a crawl of the whole web. Nobody does that from a
  laptop.
- HTTP Archive already does it, monthly, across roughly 16 million pages, and publishes the results
  as a **free public dataset** on Google BigQuery. Google stores that data at no cost to you or us.
- But BigQuery charges for **compute, not storage**, specifically bytes scanned by a query, billed to
  whoever runs it. The query runs on Google's machines and Google bills **your** Google Cloud
  project. Not this repo, not GitHub, not us.

Think of `ota reverse` as a free SQL client. The client costs nothing; the database it talks to
meters query compute.

**In practice most people pay nothing**, because Google gives every account **1 TB of free query
volume per month** and a well-filtered query is far smaller. A `--rank 100000` lookup typically
scans a few hundred MB to a few GB, so dozens of them fit inside the free tier.

Costs only appear with broad, unfiltered queries run repeatedly. Hence the guard rails, on by
default:

| Guard | What it does |
| --- | --- |
| Automatic dry run | Every query is estimated before it runs, and the estimate printed |
| 200 GB ceiling | Execution refused above it unless you raise `--max-bytes` |
| Server-side `maximumBytesBilled` | BigQuery itself rejects the job, rather than trusting our estimate |
| `--dry-run` | Prints SQL and cost, bills nothing |
| `--rank` | The single biggest lever on cost. Use it |

**If you never want to touch BigQuery, never run `ota reverse`.** Nothing else uses it, and no other
command will ask for cloud credentials.

### Setup

```bash
gcloud auth login && gcloud config set project YOUR_PROJECT
```

Alternatively set `GOOGLE_CLOUD_PROJECT` and `GOOGLE_ACCESS_TOKEN`. No `@google-cloud/bigquery`
dependency is needed; the tool uses the REST API directly.

### What it is not

Results come from HTTP Archive's own Wappalyzer fork, not this project's 588 fingerprints, so they
can disagree with a direct scan. Coverage follows CrUX, so it skews to sites with real Chrome
traffic and small or new stores may be absent. The crawl is monthly, so data lags by weeks. Treat it
as a sampling frame for building a prospect list, then verify each prospect with a real scan.

---

## What it detects

**588 built-in fingerprints** across **55 categories**, plus whatever the optional external dataset
adds.

| Area | Count | Examples |
| --- | --- | --- |
| JS libraries | 60 | jQuery, Swiper, GSAP, Three.js, D3, Chart.js, Lodash, Axios, Splide |
| Ecommerce apps | 55 | Judge.me, Yotpo, Recharge, Klaviyo, Gorgias, Rivo, PushOwl, Swym, Videowise, Loop Returns, BOGOS, Tapcart |
| Platforms | 45 | Shopify, WordPress, Wix, Squarespace, Webflow, Ghost, Drupal, Magento, VTEX, SHOPLINE, Tiendanube |
| Payments | 39 | Stripe, PayPal, Adyen, Klarna, Razorpay, GoKwik, Mercado Pago, Paystack, Flutterwave, Midtrans |
| Ecommerce platforms | 37 | BigCommerce, commercetools, SAP Commerce, Medusa, Saleor, Swell, Ecwid, OpenCart, Shopify Hydrogen |
| CMS | 28 | Contentful, Sanity, Storyblok, Strapi, Sitecore, AEM, Payload, TYPO3, Craft |
| Marketing automation | 25 | Klaviyo, HubSpot, Marketo, Braze, MoEngage, CleverTap, Attentive, Postscript, BiteSpeed |
| DevOps and self-hosted | 24 | Grafana, Jenkins, GitLab, Metabase, Kibana, Vault, Argo CD, n8n, Airflow |
| Analytics | 24 | GA4, GTM, Plausible, PostHog, Mixpanel, Amplitude, Segment, Clarity, Hotjar, Snowplow |
| Backend frameworks | 20 | Rails, Django, Laravel, Spring, ASP.NET, Phoenix, FastAPI, Express, NestJS, Statamic |
| UI frameworks | 20 | Material UI, Chakra, Ant Design, Mantine, Radix, shadcn/ui, Vuetify, Ionic |
| JS frameworks | 18 | Next.js, Nuxt, Remix, SvelteKit, Astro, Gatsby, React, Vue, Angular, Qwik |
| Advertising | 16 | Meta Pixel, Google Ads, TikTok, Pinterest, LinkedIn, Reddit, Bing UET, Criteo |
| CDN | 15 | Cloudflare, Fastly, Akamai, CloudFront, Bunny, jsDelivr, unpkg |
| Auth | 15 | Auth0, Clerk, WorkOS, Okta, Cognito, NextAuth, Better Auth, Keycloak, KwikPass |
| Shipping and logistics | 14 | Shiprocket, AfterShip, ShipStation, Sendcloud, Narvar, Delhivery, ClickPost |
| Web servers | 14 | nginx, Apache, IIS, LiteSpeed, Caddy, OpenResty, Envoy, Tomcat |
| Search | 13 | Algolia, Typesense, Meilisearch, Elasticsearch, Klevu, Coveo, Pagefind |
| Support and chat | 13 | Intercom, Zendesk, Crisp, Drift, Tawk.to, Gorgias, Freshchat, Verifast AI |
| Hosting and PaaS | 13 | Vercel, Netlify, Fly.io, Railway, Render, Heroku, Cloudflare Pages, Shopify Oxygen |

Plus databases, BaaS, APM, error tracking, feature flags, A/B testing, CAPTCHAs, bot protection,
cookie consent, fonts, media, maps, video, translation, accessibility, mail providers and DNS hosts.
Run `ota --categories` for the full list.

**Account IDs are captured too**, so you get `GTM-M92FB6B`, `G-MFK23BV2BG` or a Klaviyo public key,
not just "Google Tag Manager is present".

---

## How it works

Nine signal sources, matched against the fingerprint database:

| Source | What it catches |
| --- | --- |
| Response headers | Server, framework, hosting, CDN, cache layer |
| Cookies | Framework session names, near-unique and hard to fake |
| HTML and meta | Generators, asset path conventions, inline markers |
| Rendered DOM and JS globals | Everything injected after load, needs `--render` |
| Runtime network requests | Beacons and APIs that never appear in the DOM |
| First-party CSS | CSS frameworks, from compiled output rather than class names |
| Sourcemaps and bundles | Exact npm dependency names and versions |
| DNS records | Mail provider, DNS host, SaaS named in SPF includes |
| Well-known probes and favicon hash | Self-hosted software with no client-side fingerprint |

Three design decisions produce the accuracy:

**Confidence combines probabilistically, never by summing.** Each signal has a reliability and
overall confidence is `1 - Π(1 - reliability)`. Repeated matches from the *same* source are damped,
so ten HTML regexes for one library cannot masquerade as ten independent observations. Summing
saturates at 100% as soon as you add enough weak matches, which is exactly how detectors end up
confidently wrong.

**CSS frameworks come from compiled CSS, not class names.** `flex items-center` looks like Tailwind
but any codebase can define those names. So first-party stylesheets are downloaded and matched for
`--tw-*` and `--bs-*` custom properties, which only exist if the framework generated the file.

**Every detection carries its evidence.** `--verbose` shows the exact header, cookie, selector or
dependency responsible. A result you cannot audit is a result you cannot trust.

---

## Accuracy benchmark

Accuracy is measured, not asserted:

```bash
npm run benchmark
```

Scans a fixed set of sites whose stacks were verified by hand (headers, cookies, `meta[generator]`,
checked with curl) and scores the output against that ground truth.

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

It fails on a **single** hard false positive and only budgets misses. That asymmetry is deliberate:
"we could not tell" is a usable answer, while "this Wix site runs Laravel" poisons a lead list and
discredits every other row.

Running it is the fastest way to catch a regression after editing fingerprints, and it is how every
accuracy bug so far was found, including one where bulk mode silently dropped detections at `-j 5`
because probes were timing out. It is intentionally **not** part of `npm test`: it hits live
third-party sites, so a green CI run must never depend on someone else's deploy schedule.

---

## What it cannot do

Stated plainly, because a detector that overstates itself is worse than useless.

- **Backend is largely invisible.** A clean Go or Rails API serving JSON leaves no fingerprint.
  Backend is reported when it leaks through a header, cookie or error page, and stays quiet
  otherwise. For real backend intel, read the target's job listings.
- **Reverse lookup is not our own crawl.** It queries HTTP Archive, whose technology column comes
  from *their* Wappalyzer fork. Results can disagree with a direct scan, coverage is CrUX-based, and
  the data is a monthly snapshot.
- **No company firmographics.** Employee counts and revenue come from data brokers. Company name,
  locations and founding year are extracted only when the site publishes them in structured data,
  and are labelled `inferred` when guessed.
- **Traffic rank comes from Tranco**, a free research list, not a proprietary panel.
- **Technology spend is a floor, not a bill.** It sums entry-level list prices for the paid tools
  visible from outside, to separate "hobby site" from "funded company buying software". Every
  contributing tool is listed so you can check the arithmetic.
- **Results are vantage-dependent.** Geo-redirects, device targeting and logged-in state change what
  a site serves. This tool was written after a scan from a US IP returned a completely different
  Shopify store than the same URL from India. Check more than one vantage point before trusting a
  single scan.
- **Email verification needs port 25**, blocked on most cloud networks, in which case the verdict is
  `unknown` rather than a false negative.
- **Catch-all domains cannot be verified.** Acceptance proves the domain works, not that the mailbox
  exists. Always reported `risky`.
- **CVE results depend on version accuracy.** Versionless detections are skipped rather than matched
  against every release. Confirm a version before acting on a CVE.

---

## Fingerprint database and licensing

The built-in database in `src/fingerprints/` is **written for this project and MIT licensed**. It is
not a copy of anyone else's dataset. Shopify app handles were harvested from live storefronts rather
than guessed.

The most complete open dataset available is the community-maintained Wappalyzer technologies set
([enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)), which is **GPL-3.0**. Vendoring
GPL-3.0 data here would force this entire project to become GPL-3.0 and stop you embedding it in
your own products, which is the exact freedom this exists to provide. So it is never redistributed:
`opentechalyzer db import` fetches it to *your* machine, at *your* request, and it stays under its
own licence. Everything works without it.

---

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
}
```

Rules that keep accuracy up, each of which caught a real false positive:

1. **Prefer specific signals.** A cookie name or JS global beats an HTML substring.
2. **Never use a bare brand name in HTML.** `ecwid` or `shopline` matches any page mentioning the
   product. Use a hostname or asset path.
3. **Anchor cookie patterns at both ends.** An unanchored `_session$` matched Laravel's own cookie
   and reported Rails at 94% on laravel.com.
4. **Never write a status-only probe.** Always require a body pattern; a 401 from `/api/` proves
   nothing and once reported Home Assistant on Vercel and Stripe.
5. **Set `caseSensitive: true` for identifier patterns.** `G-[A-Z0-9]{9,12}` matched `g-recaptcha`
   until that existed.
6. **Use `id` for account identifiers, `version` for versions.** `GTM-M92FB6B` is not a version.
7. **Verify on real merchant sites, not the vendor's own site.** Grepping "shopline" on shopline.hk
   proves nothing.
8. **Verify favicon hashes against a real instance.** A guessed hash is worse than no signal.

`npm test` enforces unique names, valid regexes, resolvable `implies`/`requires` targets, and that
every `version` template has a matching capture group.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more.

---

## Development

```bash
npm install
npm run build
npm test           # 45 unit tests, no network
npm run benchmark  # live accuracy check, needs network
npm run typecheck
```

---

## Licence

MIT. Use it commercially, embed it, fork it, resell it. No attribution required.
