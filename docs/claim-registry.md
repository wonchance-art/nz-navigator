# Claim registry verification

`data/claims.json` is the machine-readable source of truth for factual values
shown on the site. The verifier uses only the Python standard library and the
default CI check makes no network requests.

## Registry shape

The root object has these fields:

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-07-19T00:00:00Z",
  "claims": []
}
```

Every claim requires:

- `id`, `country`, `locale`, `category`, `label`
- `value`, `status`, `severity`
- `verifiedAt`, `sourceUrl`, `pages`

Every claim must use exactly one effective-date mode:

- Use `effectiveFrom` when the official source supplies a defensible start
  date. `effectiveTo` may be added when the source also supplies an end date.
- If the source only confirms that a value is current, use `currentAsOf` and a
  non-empty `effectiveFromUnknownReason`. Do not copy the verification date
  into `effectiveFrom`. `effectiveTo` is not allowed in this mode.

Other optional fields are `unit`, `parityKey`, `notes`, and
`parityExemptReason`. `value` is a finite JSON scalar. Dates use `YYYY-MM-DD`;
`generatedAt` is an ISO 8601 timestamp with a timezone.

Allowed `status` values are `official`, `derived`, `estimated`, and
`unverified`. Allowed `severity` values are `critical`, `medium`, and `minor`.
Critical claims become stale after 45 days; all other claims become stale
after 90 days. The boundary itself is valid, so a critical claim verified
exactly 45 days ago passes.

## Official source policy

Host matching is exact or by true subdomain suffix. A lookalike such as
`immigration.govt.nz.example.com` does not pass.

| Country | Approved country domains |
| --- | --- |
| `NZ` | `immigration.govt.nz`, `employment.govt.nz`, `ird.govt.nz` |
| `CA` | `canada.ca`, `ircc.canada.ca` |
| `AU` | `immi.homeaffairs.gov.au`, `ato.gov.au`, `fairwork.gov.au` |
| `COMMON` | the common domains below |

The separately reviewed common allowlist is `oecd.org`, `worldbank.org`,
`ilo.org`, and `un.org`. These common domains may also source a country claim.
Any addition to either allowlist requires a code review.

## Page linkage and translation parity

Every path in `pages` must be a repository-relative existing HTML file. The
element that displays the value must carry the matching marker:

```html
<span data-claim-id="nz.minimum-wage">NZD 23.95/hour</span>
```

For claims with the same `parityKey`, all `official` and `derived` entries must
have the same `value` and `unit`. A deliberately different entry must include
a non-empty `parityExemptReason`; the explanation is reviewed as data rather
than silently weakening parity checks.

## Commands

Run the complete unit suite:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Run the deterministic, offline registry check used by CI:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_claims.py data/claims.json
```

Run the six calculator samples against the JavaScript embedded in the built
NZ, Japanese, Canada, and Australia pages:

```sh
node scripts/verify_calculators.mjs
```

The calculator check reads the expected values from the same claim registry.
It currently covers NZD 72,800 net pay in both NZ locales, the Canada CRS
core sample and Ontario CAD 60,000 net pay, and the two Australia tax samples.

Optionally verify live URLs with one `HEAD` request and a `GET` fallback:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_claims.py data/claims.json --check-links
```

`--check-links` is intentionally excluded from the default GitHub Actions job
so source-site outages, rate limits, or network restrictions cannot make the
deterministic integrity check flaky. Link failures still return exit code 1
when the option is explicitly used.

The verifier reports the claim id, failing field, reason, and a concrete fix.
It exits with code 1 for malformed JSON, missing or mistyped fields, duplicate
ids, invalid or future dates, ambiguous effective-date modes, reversed
effective ranges, invalid enums,
unapproved source hosts, stale claims, unsafe or missing page paths, missing
`data-claim-id` markers, parity mismatches, and requested link-check failures.
