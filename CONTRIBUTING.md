# Contributing to Opentechalyzer

Thanks for helping. The highest-value contribution is almost always **a new fingerprint** or **a
fix to an inaccurate one**.

## Adding a technology

Find the right file in `src/fingerprints/` and add one object:

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

Then verify against a real site:

```bash
npm run build && node dist/cli.js some-site-using-it.com --verbose
```

## Accuracy rules

These exist because each one caught a real false positive during development.

1. **Prefer specific signals.** Cookie names, JS globals and `meta[generator]` are strong. Bare
   substrings in HTML are weak; give them a low `confidence` if you must use them.
2. **Never write a status-only probe.** Always include a `body` pattern. `{ path: '/api/', status: [200, 401] }`
   matched every site with an API and reported Home Assistant on Vercel and Stripe.
3. **Set `caseSensitive: true` on identifier patterns.** Patterns are case-insensitive by default
   because HTML is. `\b(G-[A-Z0-9]{9,12})\b` matched `g-recaptcha` before this flag existed.
4. **Use `id` for account identifiers, not `version`.** `GTM-M92FB6B` and a Klaviyo public key are
   identifiers. Reporting them as versions is misleading.
5. **Detect CSS frameworks from `cssContent`, not class names.** `flex items-center` is not evidence
   of Tailwind. `--tw-ring-inset` in compiled CSS is.
6. **Favicon hashes must come from a real running instance.** Compute with
   `curl -s https://host/favicon.ico | md5`. A guessed hash produces confident false positives, which
   is worse than having no signal at all.
7. **Use `requires` for dependent technologies.** WooCommerce requires WordPress; without that,
   any page merely mentioning the word matches.

## Tests

```bash
npm test
```

The database test enforces unique names, valid regexes, at least one signal and one category per
fingerprint, resolvable `implies`/`requires`/`excludes` targets, and that every `version` template
has a matching capture group. Add a case to `test/engine.test.ts` for any new engine behaviour.

## Reporting a false positive

Open an issue with the URL, the technology wrongly reported, and the output of:

```bash
npx opentechalyzer <url> --verbose
```

The evidence trail in that output names the exact pattern at fault, which usually makes the fix a
one-liner.
