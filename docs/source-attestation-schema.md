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
      "livePolicy": {
        "mode": "extract",
        "reason": "Official bounded JSON representation is available.",
        "manualReviewDays": 7
      },
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

Each attestation must use exactly one effective-date mode: `effectiveFrom`
(with optional `effectiveTo`) when the official start date is known, or
`currentAsOf` plus a non-empty `effectiveFromUnknownReason` when the source
only confirms the current value. The latter mode forbids `effectiveTo`; it
prevents a verification date from being presented as a policy start date.

`livePolicy`, `requestCandidates`, `candidatePolicy`, and root
`targetComponents` are optional. `targets` and `claims` are individually optional, but at least one
must be a non-empty array. All other entry keys above are required. A target
mapping is `{targetId,reviewedPath}` or
`{targetId,reviewedPath,expectedPath}`; component-scoped mappings additionally
require `componentId`. `/` is the default expected path and
the selected expected subtree must exactly equal the reviewed subtree. A claim
mapping is `{claimId}` or
`{claimId,expectedPath}`; `/` is the default expected path.

`livePolicy`, when present, is exactly
`{mode,reason,manualReviewDays}`. `mode` is `extract` or `fixture-only`,
`reason` is non-empty bounded text, and `manualReviewDays` is an integer from
1 through 30. Omission is backward-compatible `extract`. `fixture-only`
continues to require an exact offline fixture match, but live mode does not
request or extract that source: it emits `unsupported` with the reason and
manual-review SLA and can never become `match`. This is used for official
representations such as compressed PDFs that the reviewed parser cannot
safely consume.

For `fixture-only`, `verifiedAt + manualReviewDays` is the inclusive manual
evidence due date. Offline mode still validates the fixture and extractor
first, then changes an otherwise matching result to `unsupported` on the next
day. The result records `verifiedAt`, `dueDate`, `daysOverdue`, and the current
raw fixture SHA-256. A review therefore updates both the date and reviewed
evidence fingerprint. This deadline is independent of `reviewAfterDays`.

Every boundary reviewed scalar leaf must be covered exactly once. Parent
pointers may cover a cohort, but overlapping parent/child mappings are
rejected. `claimScope`, when present, contains unique official or derived claim
IDs. Each scoped claim must be mapped exactly once, and mappings outside the
scope fail. The selected expected value and unit must exactly equal the claim's
`value` and `unit`; its `sourceUrl` must exactly equal the attestation citation
URL. One attestation may therefore cover multiple NZ/JA claims with the same
official source, value, and unit.

### Component target coverage

Large reviewed objects can opt into an explicit source-component partition:

```json
{
  "targetComponents": [{
    "targetId": "ca-tax",
    "components": [
      {"id": "cra-8.1-federal", "reviewedPaths": ["/federal/brackets", "/federal/creditRate"]},
      {"id": "cra-t4032-on-derived", "reviewedPaths": ["/ontario/taxReduction", "/ontario/health"]}
    ]
  }]
}
```

A scoped target requires 2–64 components. Each component ID is a stable slug
and owns 1–64 exact RFC 6901 reviewed paths. Root `/` ownership is forbidden.
Declared paths may not overlap as parent/child and, together, must cover every
reviewed scalar leaf exactly once. Every attestation target mapping must name
the declared `componentId` and an exact path owned by it; undeclared paths,
wrong owners, duplicate mappings, partial components, and missing leaves fail
closed. Targets without `targetComponents` retain the v7 mapping contract.

This is the production migration boundary for `ca-tax.reviewed`: it permits
the former 92-leaf root fixture to be replaced by independently reviewed CRA
cohorts without changing the boundary manifest itself.

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

A legacy GET request is exactly `{"method":"GET"}` and fetches `sourceUrl`.
A machine-readable representation on the same canonical official host may
instead use exactly:

```json
{
  "method": "GET",
  "url": "https://www.ato.gov.au/api/public/content/REVIEWED-ID"
}
```

The override is HTTPS, at most 2,048 characters, contains no userinfo, query,
fragment, body, or arbitrary headers, and has exactly the same canonical
hostname as `sourceUrl`. This keeps the human citation distinct from a
site-published machine representation. A POST request is exactly:

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
request is fetched once per attempt and is shared by every linked attestation.
Redirect final hosts are rechecked against the official jurisdiction
allowlist. Reports preserve both `source` and `requestUrl`.

### Representation candidates

The required root `request`, `extractor`, and `fixture` preserve the v5/v6
single-request contract. An attestation may additionally contain one to three
`requestCandidates` and `candidatePolicy`:

```json
{
  "candidatePolicy": {"mode": "available-parity"},
  "requestCandidates": [
    {
      "id": "en",
      "sourceRelation": "citation",
      "request": {"method": "GET"},
      "mediaType": "text/html",
      "fixture": {
        "path": "data/attestation-fixtures/iec-korea-en.html",
        "mediaType": "text/html",
        "sha256": "sha256:REVIEWED_RAW_SHA256",
        "httpStatus": 200,
        "finalUrl": "https://www.canada.ca/en/.../eligibility-by-country.html"
      }
    },
    {
      "id": "fr",
      "sourceRelation": "same-host",
      "request": {
        "method": "GET",
        "url": "https://www.canada.ca/fr/.../admissibilite-par-pays-categorie.html"
      },
      "mediaType": "text/html",
      "extractor": {
        "mode": "html-section-text",
        "params": {
          "heading": "République de Corée — Vacances-travail",
          "anchor": "être âgé de 18 à 35 ans, inclusivement",
          "transform": "inclusive-range",
          "unit": "years"
        }
      },
      "fixture": {
        "path": "data/attestation-fixtures/iec-korea-fr.html",
        "mediaType": "text/html",
        "sha256": "sha256:REVIEWED_RAW_SHA256",
        "httpStatus": 200,
        "finalUrl": "https://www.canada.ca/fr/.../admissibilite-par-pays-categorie.html"
      }
    }
  ]
}
```

Each candidate has exactly `id`, `sourceRelation`, `request`, `mediaType`,
`fixture`, and optional `extractor`. The first candidate must exactly mirror
the root request/extractor/fixture. Every fixture final URL and exact media
type must match its candidate. Canonical duplicates inside a chain fail;
identical canonical requests across attestations share one fetch/retry
execution.

`sourceRelation` is `citation` (request URL equals `sourceUrl`), `same-host`
(canonical host equals the citation host), or `jurisdiction-official` (request
host is on the same jurisdiction allowlist). Explicit candidate GET URLs may
contain a reviewed query but never a fragment, credential, arbitrary header,
or body. Redirects remain allowlist-checked, and `citation`/`same-host`
candidates may not redirect to another canonical host.

`first-match` is the default. Only `transient`, `blocked`, or `unsupported`
advances to the next candidate; `changed` stops immediately and the first
match wins. `available-parity` evaluates all candidates: any `changed` stops
and fails, one or more matches produce a semantic match, and inaccessible
candidates remain visible in request trend/SLA telemetry. Every reachable
match must independently equal the same expected value and unit, giving
strict parity. With no match, the first candidate's deterministic non-match is
returned. This permits EN/FR failover without allowing fallback to hide
policy drift.

## Reviewed extractors

Registry data never supplies a regular expression, CSS selector, XPath, or
code. Only these code-reviewed modes and bounded parameters run:

- `html-table-record`: exact `section`, exact `headers`, `result` (`scalar` or
  `object`), and 1–24 `fields`. A field is exactly
  `{key,rowLabels,valueHeader,transform,unit}`. The table must be immediately
  associated with the exact preceding heading/paragraph, and section, header,
  row, and column cardinality must be unique and complete. Optional
  `detailsSummary` binds a table to one exact enclosing `details > summary`;
  this separates a current table from a historical table with identical
  headings and columns. Fixed English cohort labels (`From D Month YYYY` and
  `If you apply on or after Month D, YYYY`) also reject a same-shape table
  with a later date, so a retained historical table cannot false-green after
  a new policy cohort is published. Hidden, `aria-hidden`, `display:none`,
  `visibility:hidden`, and `History_` subtrees never contribute tables,
  headings, blocks, or anchors.
- `html-labelled-values`: exact outer `anchor`, `result`, and fields
  `{key,label,transform,unit}`. It handles INZ `h4` plus following `p`
  structures. All bounded paragraphs under the label are tested; exactly one
  must satisfy the fixed transform. Thus helper text such as `Up to` cannot be
  mistaken for `12 months`.
- `html-home-affairs-schema-anchor`: reads exactly one Home Affairs hidden
  PageSchema input, parses its value as finite JSON without evaluation,
  resolves one bounded JSON pointer, and then requires one exact leaf anchor
  inside the resulting HTML fragment. Duplicate/missing inputs, invalid JSON,
  missing pointers, and duplicate fragment anchors fail closed. This keeps
  long client-rendered visa pages tied to their government-published
  structured content rather than screen position.
- `html-text-anchor`: one exact normalized `p`, leaf `li`, heading, or
  non-empty loose text node outside tracked table/block containers (up to
  2,000 characters), one fixed transform, and one unit. Nested block parents
  are not duplicated. Split/nested loose text and duplicate nodes do not
  satisfy exact cardinality.
- `html-section-text`: one exact H3 and one exact leaf `p` or `li` before the
  next H3. Only `inclusive-range` and `duration-months` are allowed. English
  `be between the ages of N and M (inclusive)`, `N to M`, and French `N à M`
  normalize to `N-M`; `duration-months` accepts exactly one English
  `N month(s)` or French `N mois` token. A matching value in another country
  section cannot satisfy the extractor.
- `ato-lito`: exact heading `anchor` plus exactly three reviewed leaf `li`
  strings in order. Its code-fixed grammar accepts the indexed ATO wording
  `$37,500 or less ... get ...`, then the two `between $N and $M ... get ...`
  rules. It verifies integer continuity, the $325 intermediate amount, and a
  cut-out residual within one cent, then returns the reviewed LITO object and
  fixed unit tree. It remains available for a future safe HTML
  representation; production may mark the current PDF representation
  `fixture-only`.
- `ato-law-lito`: the current section 61-115 table with exact Act H1,
  one exact normalized `p` containing the two reviewed `strong` siblings
  `SECTION 61-115` and `Amount of the Low Income tax offset`, single-cell
  table title, headers, items 1–3, thresholds, amounts, and rates. It verifies
  taper continuity/arithmetic.
  Tables under an ancestor ID beginning `History_` or normalized inline style
  `display:none` are excluded; the accepted current table must be a direct
  child of exact allowlisted `div#lawBody` or `div#LawBody`.
- `ato-law-lito-serialization`: applies the same table, cardinality,
  continuity, and arithmetic checks as `ato-law-lito`, then emits only the
  canonical public claim string
  `700;37500;45000@0.05;66667@0.015`.
- `ato-law-resident-brackets`: the exact 2026–27 Schedule 1 clause 2 table,
  fixed headers, and complete items 1–4. It returns
  `[[45000,.15],[135000,.30],[190000,.37],[null,.45]]` only; it never
  synthesizes the separate tax-free threshold.
- `ato-tax-free-band`: exact H2 `What is the tax-free threshold` and exact
  reviewed paragraph including `before you pay tax` and `the first $N`. Only
  that fixed grammar can create `[N,0]` with unit `AUD/rate`.
- `iec-quota-xml`: accepts only a UTF-8 `temp` document without DTD/entity
  declarations, one exact country code/category/location row, and one exact
  quota. The scalar `chancesdate` and selected row's `first` date must both
  belong to the declared `seasonYear`; a retained or future season cannot
  satisfy the current-season claim even when its quota happens to be equal.
  declarations, selects exactly one `country` with reviewed lowercase
  `countryCode` and category, and reads one scalar comma-grouped integer
  `quota`. Extra attributes, duplicate country/category rows, malformed XML,
  or non-numeric quota text fail closed.
- `cra-t4127-version`: params are exactly `{"language":"en"}` or
  `{"language":"fr"}`. It requires one language-specific `T4127-JUL` H1,
  validates edition ordinal and effective date, and normalizes both pages to
  `T4127-123rd-2026-07` with unit `table version`.
- `cra-t4127-csv`: params are exactly
  `{publication,effectiveDate,encoding,cohort}`. `encoding` is one of
  `utf-8`, `utf-8-bom`, or `windows-1252`; BOM presence must agree exactly.
  Production CRA files use BOM-free `windows-1252`. The code binds each
  cohort to one reviewed `www.canada.ca` path, publication/date pair, table
  title, header, row labels, cardinality, and finite numeric grammar. Supported
  cohorts are Table 8.1 Federal/AB/ON rates, BC thresholds plus rates after
  the first band, Table 8.2 Federal/AB/BC/ON amounts, Tables 8.3–8.7 CPP/EI,
  and Table 8.9 federal maximum BPA. Registry data supplies no row selector.
  The BC CSV cohort deliberately returns
  `thresholds=[50363,100728,115648,140430,190405,265545,null]` and
  `ratesAfterFirst=[0.077,0.105,0.1229,0.147,0.168,0.205]`; it does not return
  the H2 payroll catch-up rate 6.14% as the annual statutory first rate.
- `cra-t4127-bc-annual-rate`: params are exactly `{"effectiveYear":2026}`.
  It requires the three reviewed CRA prose blocks establishing 5.60% for 2026
  and subsequent years, the separate 6.14% H2 payroll catch-up rate, and that
  Option 2 is not prorated. It returns only `{rate:0.056}`.
- `cra-t4032-on`: params are exactly `{"effectiveDate":"2026-01-01"}`.
  It requires the exact T4032ON H1, `T4032-ON(E) Rev. 26`, the
  `What's new as of January 1, 2026` heading, both exact `For 2026` health and
  tax-reduction lead paragraphs, all six ordered Ontario health-premium
  bullets, basic personal reduction amount `$300`, and the sentence that the
  reduction is twice personal amounts. Every year/revision anchor has
  cardinality one. It returns only
  `{taxReduction:600,health:{...}}`; Ontario brackets, BPA, and surtax remain
  separate CSV-owned components and cannot overlap this cohort.
- `api-json-record`: `arrayPointer`, 1–3 exact string `match` fields,
  `valuePointer`, and optional fixed transform. Zero or multiple matching
  records is drift. `currency-to-number` requires an actual `AUD`, `CAD`, or
  `NZD` prefix and returns that observed unit.
- `json-pointer` / `api-json-pointer`: the pointer must resolve to an exact
  finite `{unit,value}` record; aligned unit trees are supported.
- `html-table`, `html-definition`, and `pdf-table`: restricted legacy fixture
  parsers. The PDF parser accepts literal `Tj` and literal-only `TJ` array text
  inside balanced `BT/ET` objects in bounded direct streams with no filter or
  one `FlateDecode`. Exactly one valid classic xref/startxref is required. It
  caps body, objects, streams, object size, per-stream and aggregate
  decompressed bytes, token/nesting depth, and compression ratio. Encryption,
  `/DecodeParms`, xref/object streams (including whitespace variants), filter
  chains, hex text operands, ToUnicode/complex fonts, malformed streams,
  duplicate anchors, and partial tables fail closed. It is not a general PDF
  engine; reviewed official HTML is preferred.

HTML field transforms are fixed enums:

- `number`, `integer`, `currency-to-number`, `percent-to-decimal`
- `duration-months`, `duration-weeks`, `single-duration-days`,
  `single-duration-years`, and `single-duration-years-to-months`; every
  `single-*` form requires exactly one integer duration token
- `inclusive-range`, which accepts one `N to M`, French `N à M`, or dash
  range and returns canonical `N-M`
- `final-inclusive-range`, which requires exactly two ranges and returns the
  last as `N-M`
- `leading-currency-to-number`, which requires the block's sole ISO-prefixed
  currency token at the beginning
- `single-iso-amount-to-number`, which requires exactly one `NZD`, `CAD`, or
  `AUD` amount, with or without `$`, anywhere in the exact reviewed block
- `service-standard-months`, which requires exactly one `N-month service
  standard` token and the exact `80% of cases` target
- `no-tfn-whm-percent` and `whm-first-band-percent`, which accept only their
  code-fixed full ATO sentence grammars and reject threshold/rate ambiguity
- `embedded-percent` and `embedded-percent-to-decimal`, which accept only
  `$N per $100 (P%)`, require `N == P`, and return `P` or `P/100`
- `percentage-number-to-decimal`, which accepts one canonical unsigned finite
  numeric cell in `0..100` with no `%` token or leading zero and returns
  `P/100` (for example, ATO Super `12.00` becomes `0.12`)
- `ato-first-tax-band`, which accepts exactly one ATO WHM row label
  `0 – $N` and value `Pc for each $1`, returning
  `{cap:N,rate:P/100}` with fixed `{cap:"AUD",rate:"decimal rate"}` units.
  Comma grouping must be canonical (`45,000`, not `4,5000` or `045,000`);
  the lower bound, dash, `$1` base, and one-row cardinality are exact.
- `ato-law-first-tax-band`, which binds the current ATO law table titled
  `Tax rates for working holiday makers for the 2024-25 year of income or a
  later year of income`. It requires section `Repeal the table, substitute:`,
  the exact three headers, item `1`, middle cell `does not exceed $N`, and
  rate cell `P%`, then returns `{cap:N,rate:P/100}` with the same fixed unit
  tree. Exactly one title must match: either the caption or a header-width
  title row computed as `[TITLE] + [""] * (len(headers) - 1)` before the
  headers. Exactly one complete item row must also match. The guidance
  transform remains a regression check; production should prefer this law
  transform when binding 2026–27 applicability.
- `ato-law-first-tax-rate-percent`, which applies the identical reviewed ATO
  law title/header/item/threshold grammar but emits the public percentage
  value rather than the boundary object
- `tax-brackets`, which returns the v4 reviewed shape
  `[[upper,rate],...,[null,rate]]`, checks zero start, continuity, and an open
  last cap
- `tax-brackets-serialization`, which applies the same checks and emits the
  claim form `cap@rate;...;above@rate`

The API record transform enum is `identity` or `currency-to-number`.
`identity` requires the selected value itself to be exact `{unit,value}`.

### ATO contract gate

The focused network-free contract suite is:

```sh
python3 -m unittest tests.test_verify_ato_extractors -v
```

It fixes the guidance-table WHM object shape, its aligned value/unit trees,
Super's bare numeric percentage conversion, LITO list order/cardinality and
boundary arithmetic, and the body-free same-host ATO content GET override.
Missing or duplicate table/list records, non-canonical numeric grouping,
formula discontinuity, a mismatched unit-tree leaf, query/body/header
injection, or a different canonical host fails closed. The complete source
attestation suite and production offline registry check remain the authoritative
integration gate.

The guidance `ato-first-tax-band` and list `ato-lito` modes prove reviewed
fixture structures but do not by themselves guarantee that a live
representation is fetchable. A production entry marked `fixture-only` remains
`unsupported` in live mode until its source is migrated to a bounded,
live-readable representation. The law-table WHM and LITO extractors are the
preferred live contracts when their exact official HTML representations are
available.

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
  check. Body challenge detection applies only to successful 2xx responses;
  401/403 remain blocked. This does not assert that a policy value changed.
- `transient`: 429, 5xx, network, DNS, TLS, or timeout failure. Retry before
  factual review. HTTP 429/5xx takes precedence over challenge-like error
  bodies, so a 503 CAPTCHA page is retried as transient.
- `unsupported`: media, redirect policy, schema, or safe extraction capability
  cannot verify the source. This does not assert that a policy value changed.

Only `match` is green. All other statuses are non-match and fail scheduled
verification. A live `fixture-only` result is `unsupported` without a network
attempt; its reason and `manualReviewDays` are included in the result and
issue.

Candidate-backed results additionally include `selectedCandidate`,
`candidatePolicy`, and ordered `candidateChain` telemetry: candidate ID,
public request hash, official request URL/method, outcome/reason, attempts,
attempt status sequence, and content-free latency. Candidate IDs/order,
outcomes, reasons, and attempt statuses are substantive. Latency and matching
full-body context churn are excluded from observation and issue
fingerprinting. A fallback match may keep the value audit green while a
failed candidate request remains an active transport trend in the single
drift issue.

Successful reports deterministically include:

```json
{
  "attestationCount": 37,
  "claimCount": 43,
  "reviewedLeafCount": 136,
  "liveCapableCount": 37,
  "liveExtractableCount": 36,
  "fixtureOnlyCount": 1
}
```

If `data/claims.json` contains `audit.sourceAttestations`, it must exactly equal
these six generated counts.
`liveCapableCount` is retained as the legacy total attestation count; the
strict new partition is
`liveExtractableCount + fixtureOnlyCount == attestationCount`.

## Bounded retry and report v2

Live retries apply only when the request-level status is `transient`: network,
DNS, TLS, timeout, HTTP 429, or HTTP 5xx. `changed`, `blocked`,
`unsupported`, and successfully fetched responses are never retried.
`--max-attempts` is the total attempt count (`1..4`),
`--retry-backoff-ms` is the deterministic exponential base (`1..2000`), and
`--timeout` is finite, greater than zero, and no more than 60 seconds. There
is no jitter or registry-supplied code. `--request-budget-seconds` is finite
in `(0,60]` and caps one canonical request's total attempts plus deterministic
backoff. Each attempt receives the smaller of `--timeout` and the remaining
request budget. `--attestation-budget-seconds` is finite, at least the request
budget, and at most 120 seconds. Before a fresh canonical request begins, its
full request budget is reserved against this attestation total; a candidate
that would exceed the total is recorded as `transient` with zero attempts.
Cached canonical executions are shared across all attestations/candidates and
consume no second reservation or fetch. Budget exhaustion never becomes
`match`. Offline mode requires one attempt and never sleeps or fetches.

Live requests use a code-owned, exact-host compatibility map. The default
profile retains `User-Agent: nz-navigator-source-attestation/1.0`,
`Accept: text/html,application/xhtml+xml,application/pdf,application/json;q=0.9,*/*;q=0.1`,
and `Connection: close`. Only exact canonical hosts `canada.ca`,
`www.canada.ca`, and `ircc.canada.ca` use
`User-Agent: curl/8.7.1 NZ-Navigator-Source-Attestation/1.0` plus
`Accept-Encoding: identity`. Registry entries cannot add or override headers,
and the selected profile is not part of the canonical request key, so shared
requests still execute once. Media-type validation remains extractor-specific
after the response arrives. TLS certificate verification errors remain
`transient` non-matches and are reported explicitly, including when the same
attempt also exhausts its request budget.

Report schema version 2 adds `observationId`, `retryPolicy`, and
`requestAudit`. Each result includes `requestKey`, `attemptCount`,
`requestFinalStatus`, and `latencyBucket`. The public request key is only a
SHA-256 digest of canonical URL/method/body; request bodies are not reported.
`requestAudit.requests[]` contains:

```json
{
  "requestKey": "sha256:...",
  "requestUrl": "https://official.example/path",
  "method": "GET",
  "attemptCount": 2,
  "finalStatus": "ready",
  "latencyBucket": "250ms-999ms",
  "budgetSeconds": 30,
  "budgetExhausted": false,
  "attempts": [
    {"number": 1, "status": "transient", "latencyBucket": "lt250ms"},
    {"number": 2, "status": "ready", "latencyBucket": "lt250ms"}
  ]
}
```

Request final states are `ready|transient|blocked|changed|unsupported`.
Request-audit schema v2 adds the bounded `budgetSeconds` and boolean
`budgetExhausted`; the issue reducer continues to accept schema v1 reports.
Latency is content-free and bucketed as
`offline|lt250ms|250ms-999ms|1s-4.999s|5s-14.999s|15s-plus`.
Latency is visible in the current-run table but excluded from substantive
issue fingerprinting. The existing six-key source-attestation audit is
separate from retry telemetry.
The current-run table also shows the HTML-escaped request method and official
endpoint, and active/recovered trend rows join the current endpoint by request
hash when available. URLs are not copied into the hidden trend marker and do
not affect the issue fingerprint because the canonical request hash already
binds the transport.

The scheduled workflow supplies an explicit `observationId`. When live mode
is run without one, the verifier derives a stable SHA-256 observation ID from
sorted substantive results, request final states, and attempt status
sequences. It excludes `generatedAt` and latency, so an identical manual run
is a replay while a semantic or retry-history change becomes a new
observation. Offline reports retain the fixed `offline` observation ID.

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
  --timeout 15 \
  --max-attempts 3 \
  --retry-backoff-ms 500 \
  --request-budget-seconds 30 \
  --attestation-budget-seconds 60 \
  --observation-id "WORKFLOW_RUN_ID.WORKFLOW_ATTEMPT" \
  --output source-attestation-report.json
```

CI and the scheduled audit pass `--today` using the site operator's
`Asia/Seoul` calendar date. This keeps future-date and review-expiry boundaries
aligned with the dates shown in the public Korean/Japanese verification ledger
instead of changing at UTC midnight.

The pull-request workflow always runs fixture and reducer units, then runs the
production registry offline when present. The separate scheduled workflow has
`contents: read` and `issues: write`, one concurrency group, and no pull-request
trigger. It fetches each canonical request once, reduces the report to one
exact-title issue, and creates, updates, reopens, closes, or no-ops
idempotently. Duplicate exact-title issues fail closed. Changed, blocked,
transient, and unsupported results render in distinct issue sections.
The reducer accepts GitHub CLI/API issue states in either uppercase or
lowercase (`OPEN`/`CLOSED` or `open`/`closed`) and rejects every other state,
so a clean live report closes the actual GitHub issue instead of silently
no-oping on representation casing.

The issue body also contains one hidden, versioned marker:

```text
<!-- source-attestation-trend:v1:BASE64URL_CANONICAL_JSON -->
```

It stores only canonical request hashes, consecutive transient count,
first/last/recovery UTC timestamps, last status/observation ID, and at most
eight status events per request. It stores no response body, URL, token, or
other source content; it is limited to 128 requests, 48 KiB decoded, and
64 KiB encoded. Malformed, duplicate, unsupported-version, or oversized
markers fail closed. Replaying the same request/observation does not increment
the streak. One transient waits for the next schedule, two trigger endpoint
investigation, and three or more require manual official-source review.
Recovery is recorded explicitly. `changed`, `blocked`, and `unsupported`
retain their distinct immediate-review wording.

On every report that contains `requestAudit`, the reducer treats its request
keys as the current request universe. Trend entries absent from that universe
are retired immediately before the observation is reduced. This prevents a
removed candidate or source from remaining forever as an endpoint-less hash.
Reports without `requestAudit` retain legacy behavior and cannot erase or
increment transport history. Replaying an identical observation after
retirement is still a no-op.

Marker validation also enforces `firstSeen <= lastSeen`, chronological events,
last event status/observation/timestamp equality with the request state,
`recoveredAt == lastSeen` for recovered entries, and no `recoveredAt` on an
active transient streak.

The reducer returns `bodyFingerprint`, computed from sorted substantive
findings, audit data, normalized trend state, request keys/final states, and
attempt status sequences/counts while excluding volatile `generatedAt`,
result order, and latency. A result `contextFingerprint` is substantive only
for non-match statuses; a matching extracted value/unit/structure does not
create a new observation or issue update merely because unrelated page bytes
changed. Thus a one-attempt ready response versus a
transient-then-ready recovery updates the issue, but latency-bucket-only drift
does not. The same fingerprint is embedded in the issue body; an open issue
with the same marker is a `noop`. A v5 issue
without the trend marker and a v1 report without `requestAudit` are accepted
as legacy observations but never invent or increment a transient streak.

To migrate a cohort:

1. Capture the smallest faithful official HTML/PDF/JSON/CSV response or a
   human-reviewed structured extract when the safe parser cannot consume the
   official representation.
2. Record its raw SHA-256 and request final URL.
3. Add non-overlapping target pointers and scoped claim mappings. For a large
   object, first declare its exact `targetComponents` partition, then add the
   matching `componentId` to every target mapping.
4. Choose only a reviewed extractor enum and exact bounded parameters.
5. Declare `livePolicy`; use `fixture-only` for a representation the bounded
   parser cannot safely verify live.
6. Run offline verification and copy its six audit counts into the claims
   audit.
7. Review the first scheduled live report; never promote blocked, transient,
   or unsupported to match.

For candidate migration, keep the root request/extractor/fixture as candidate
zero, add only reviewed official alternatives, and use `available-parity`
when reachable representations must prove the same value. For split boundary
evidence, map each source's expected subtree with target `expectedPath`; never
inject a constant into one extractor merely to recreate a leaf proved by
another source.

For the CA 92-leaf migration, official T4127 CSV cohorts directly cover 65
leaves. Federal 14% may map both `/federal/brackets/0/1` and
`/federal/creditRate` to the same `/brackets/0/1` expected path. The BC split
CSV covers 13 non-first-rate leaves; the annual 5.60% prose cohort owns only
`/provinces/bc/brackets/0/1`. Table 8.9 owns federal BPA. T4032ON's fixed
derived cohort owns only `/ontario/taxReduction` and `/ontario/health`.
Ontario brackets/BPA/surtax remain CSV cohorts. No CSV S2=300 mapping may
directly claim the derived runtime tax reduction 600.

Known limits: the HTML parser intentionally ignores styling and client-side
rendering; the bounded PDF parser is not a general PDF engine and deliberately
rejects object/xref streams and complex font mappings; bot-protected sources
may remain blocked. A human-reviewed structured PDF extract proves fixture
integrity offline but remains explicitly `fixture-only`/`unsupported` until a
bounded representation is reviewed. Retries/failover address transport
availability only and never turn layout, value, unit, or safe-parser drift
into a match.
