# Source attestation and drift contract

`scripts/verify_source_attestations.py` verifies that every reviewed boundary
leaf, and every claim explicitly placed in `claimScope`, is backed by a
fingerprinted official-source fixture. Pull-request verification is offline.
Scheduled or manually dispatched verification may fetch the same official
sources and produces a structured drift report.

## Registry schema

The production path is `data/source-attestations.json`. Schema version 1 has
exact root keys:

```json
{
  "schemaVersion": 1,
  "boundaryManifest": "data/boundary-executions.json",
  "claimScope": ["au-ko-whv-fee"],
  "attestations": [
    {
      "id": "au-home-affairs-417-first",
      "jurisdiction": "AU",
      "sourceUrl": "https://immi.homeaffairs.gov.au/visas/getting-a-visa/fees-and-charges",
      "request": {
        "method": "POST",
        "url": "https://immi.homeaffairs.gov.au/_layouts/15/api/data.aspx/GetPriceList",
        "jsonBody": {"onshore": "All", "category": "Visa"}
      },
      "verifiedAt": "2026-07-19",
      "effectiveFrom": "2026-07-01",
      "reviewAfterDays": 90,
      "claims": [{"claimId": "au-ko-whv-fee", "expectedPath": "/"}],
      "extractor": {
        "mode": "api-json-record",
        "params": {
          "arrayPointer": "/d/data",
          "match": {"visaSubclassCode": "417-A"},
          "valuePointer": "/basePrice",
          "transform": "currency-to-number"
        }
      },
      "expected": {"type": "number", "unit": "AUD", "value": 840},
      "fixture": {
        "path": "data/attestation-fixtures/au-visa-prices.json",
        "mediaType": "application/json",
        "sha256": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
        "httpStatus": 200,
        "finalUrl": "https://immi.homeaffairs.gov.au/_layouts/15/api/data.aspx/GetPriceList"
      }
    }
  ]
}
```

`effectiveTo` is the only optional date field. `targets` and `claims` are
individually optional, but at least one must be a non-empty array. All other
entry keys above are required. A target mapping is exactly
`{targetId,reviewedPath}`. A claim mapping is `{claimId}` or
`{claimId,expectedPath}`; `/` is the default expected path.

Every boundary reviewed scalar leaf must be covered exactly once. Parent
pointers may cover a cohort, but overlapping parent/child mappings are
rejected. `claimScope`, when present, contains unique official or derived claim
IDs. Each scoped claim must be mapped exactly once, and mappings outside the
scope fail. The selected expected value and unit must exactly equal the claim's
`value` and `unit`; its `sourceUrl` must exactly equal the attestation citation
URL. One attestation may therefore cover multiple NZ/JA claims with the same
official source, value, and unit.

`expected.type` is `number`, `string`, `array`, or `object`. Values must be
finite. `unit` may be one non-empty string or a string-leaf object/array tree
whose shape exactly aligns with `value`. A scalar unit applies to the complete
value.

`verifiedAt + reviewAfterDays` is inclusive: the attestation passes on that
date and becomes stale on the next day. Future verification dates, reversed or
expired effective ranges, unknown fields, duplicate IDs, orphan mappings,
non-finite values, and non-official URLs fail closed.

## Citation URL and request transport

`sourceUrl` is the human-readable citation and remains the value checked
against each claim. It must be HTTPS on the jurisdiction allowlist with no
userinfo.

A GET request is exactly `{"method":"GET"}` and fetches `sourceUrl`. GET may
not override the URL. A POST request is exactly:

```json
{
  "method": "POST",
  "url": "https://immi.homeaffairs.gov.au/_layouts/15/api/data.aspx/GetPriceList",
  "jsonBody": {"onshore": "All", "category": "Visa"}
}
```

POST is limited to a 2,048-character HTTPS official URL on the exact canonical
host of `sourceUrl`, and a flat 1–16 key scalar JSON object whose canonical
form is at most 4 KiB. Arbitrary headers, bodies, methods, and cross-host
requests are not accepted. Home Affairs publishes this endpoint and its
`endpointParm` in the human price page's `configJson`; the citation page
preserves user evidence and the same-host endpoint supplies deterministic
machine evidence.

The cache key is request URL, method, and canonical JSON body. An identical
request is fetched once. Redirect final hosts are rechecked against the
official jurisdiction allowlist. Reports preserve both `source` and
`requestUrl`.

## Reviewed extractors

Registry data never supplies a regular expression, CSS selector, XPath, or
code. Only these code-reviewed modes and bounded parameters run:

- `html-table-record`: exact `section`, exact `headers`, `result` (`scalar` or
  `object`), and 1–24 `fields`. A field is exactly
  `{key,rowLabels,valueHeader,transform,unit}`. The table must be immediately
  associated with the exact preceding heading/paragraph, and section, header,
  row, and column cardinality must be unique and complete.
- `html-labelled-values`: exact outer `anchor`, `result`, and fields
  `{key,label,transform,unit}`. It handles INZ `h4` plus following `p`
  structures. All bounded paragraphs under the label are tested; exactly one
  must satisfy the fixed transform. Thus helper text such as `Up to` cannot be
  mistaken for `12 months`.
- `html-text-anchor`: one exact normalized `p` or `li` block (up to 2,000
  characters), one fixed transform, and one unit. Nested block parents are not
  duplicated.
- `api-json-record`: `arrayPointer`, 1–3 exact string `match` fields,
  `valuePointer`, and optional fixed transform. Zero or multiple matching
  records is drift. `currency-to-number` requires an actual `AUD`, `CAD`, or
  `NZD` prefix and returns that observed unit.
- `json-pointer` / `api-json-pointer`: the pointer must resolve to an exact
  finite `{unit,value}` record; aligned unit trees are supported.
- `html-table`, `html-definition`, and `pdf-table`: restricted legacy fixture
  parsers. The PDF parser accepts only bounded, unencrypted literal-text PDFs
  and rejects compression/object-stream features it cannot safely interpret.

HTML field transforms are fixed enums:

- `number`, `integer`, `currency-to-number`, `percent-to-decimal`
- `duration-months`, `duration-weeks`
- `inclusive-range`, which accepts one `N to M` or dash range and returns
  canonical `N-M`
- `final-inclusive-range`, which requires exactly two ranges and returns the
  last as `N-M`
- `leading-currency-to-number`, which requires the block's sole ISO-prefixed
  currency token at the beginning
- `embedded-percent` and `embedded-percent-to-decimal`, which accept only
  `$N per $100 (P%)`, require `N == P`, and return `P` or `P/100`
- `tax-brackets`, which returns the v4 reviewed shape
  `[[upper,rate],...,[null,rate]]`, checks zero start, continuity, and an open
  last cap
- `tax-brackets-serialization`, which applies the same checks and emits the
  claim form `cap@rate;...;above@rate`

The API record transform enum is `identity` or `currency-to-number`.
`identity` requires the selected value itself to be exact `{unit,value}`.

## Fixture and live semantics

`fixture.sha256` protects the exact checked-in raw fixture. It is compared only
in offline mode. Live mode does not compare a full page hash, so unrelated
banners and scripts do not create drift. Instead, the reviewed anchor/table
structure and extracted value/unit must match exactly. A bounded
`contextFingerprint` is included for reports and issue diffs.

Every result is one of:

- `match`: structure, value, and unit match.
- `changed`: policy value/unit, expected structure/cardinality, 4xx location,
  empty response, or fixture content changed.
- `blocked`: authentication, bot protection, CAPTCHA, 401, or 403 prevented a
  check. This does not assert that a policy value changed.
- `transient`: 429, 5xx, network, DNS, TLS, or timeout failure. Retry before
  factual review.
- `unsupported`: media, redirect policy, schema, or safe extraction capability
  cannot verify the source. This does not assert that a policy value changed.

Only `match` is green. All other statuses are non-match and fail scheduled
verification.

Successful reports deterministically include:

```json
{
  "attestationCount": 35,
  "claimCount": 42,
  "reviewedLeafCount": 136,
  "liveCapableCount": 35
}
```

If `data/claims.json` contains `audit.sourceAttestations`, it must exactly equal
these four generated counts.

## Commands and operations

Offline verification:

```sh
python3 scripts/verify_source_attestations.py \
  --attestations data/source-attestations.json \
  --claims data/claims.json \
  --mode offline \
  --today 2026-07-19
```

Live verification is deliberately limited to schedule/manual operation:

```sh
python3 scripts/verify_source_attestations.py \
  --attestations data/source-attestations.json \
  --claims data/claims.json \
  --mode live \
  --output source-attestation-report.json
```

The pull-request workflow always runs fixture and reducer units, then runs the
production registry offline when present. The separate scheduled workflow has
`contents: read` and `issues: write`, one concurrency group, and no pull-request
trigger. It fetches each canonical request once, reduces the report to one
exact-title issue, and creates, updates, reopens, closes, or no-ops
idempotently. Duplicate exact-title issues fail closed. Changed, blocked,
transient, and unsupported results render in distinct issue sections. The
reducer returns `bodyFingerprint`, computed from sorted substantive findings
and audit data while excluding volatile `generatedAt`. The same fingerprint is
embedded in the issue body; an open issue with the same marker is a `noop` even
when the next report has a new timestamp or result order.

To migrate a cohort:

1. Capture the smallest faithful official HTML/PDF/JSON response or a
   human-reviewed structured extract when the safe parser cannot consume the
   official representation.
2. Record its raw SHA-256 and request final URL.
3. Add non-overlapping target pointers and scoped claim mappings.
4. Choose only a reviewed extractor enum and exact bounded parameters.
5. Run offline verification and copy its four audit counts into the claims
   audit.
6. Review the first scheduled live report; never promote blocked, transient,
   or unsupported to match.

Known limits: the HTML parser intentionally ignores styling and client-side
rendering; the PDF parser is not a general PDF engine; bot-protected sources
may remain blocked; and a human-reviewed structured PDF extract can prove
fixture integrity offline but may be unsupported against the live PDF until a
bounded extractor is reviewed.
