# Employer registry schema and verification

`data/employers.json` is the machine-readable source for the NZ and AU
employer directory. Schema v1 records one business branch, reviewed gateway,
or reviewed producer location per row. A row proves directory presence only:
it never proves a current vacancy or that a particular role/location qualifies
for a visa extension.

The verifier is Python standard-library only and is network-free unless
`--check-links` is explicitly supplied.

## Root and audit

The root has exactly four keys:

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-07-19",
  "audit": {
    "employerCount": 8,
    "countryCounts": {"NZ": 3, "AU": 5},
    "statusCounts": {"active": 6, "uncertain": 1, "expired": 1},
    "contactableCount": 4,
    "expiredCount": 1,
    "nearDuplicateCandidateCount": 0,
    "linkUrlCount": 8
  },
  "employers": []
}
```

All audit keys and nested country/status keys are exact. The verifier derives
the object deterministically and rejects a stale or partially updated audit.
`linkUrlCount` counts every unique source/contact locator, including reviewed
`mailto:` contacts. Live checking fetches only the HTTPS subset; `mailto:`
contacts are never requested.

## Employer entry

Every entry has exactly these keys:

```json
{
  "id": "au-southern-orchards-bundaberg",
  "country": "AU",
  "name": "Southern Orchards",
  "location": {
    "label": "Bundaberg",
    "address": "10 Orchard Road, Bundaberg QLD 4670",
    "region": "Wide Bay",
    "state": "QLD",
    "postcode": "4670",
    "lat": -24.866,
    "lng": 152.349,
    "precision": "exact"
  },
  "workTypes": ["farm-packing"],
  "source": {
    "kind": "employer-official",
    "url": "https://www.southern-orchards.com.au/about",
    "checkedAt": "2026-07-14"
  },
  "contact": {
    "kind": "company",
    "url": "https://www.southern-orchards.com.au/careers"
  },
  "status": "active",
  "nextReviewAt": "2026-08-14",
  "vacancyStatus": "directory-only",
  "eligibility": {
    "scheme": "au-417-specified-work",
    "classification": "conditional",
    "requiresRoleCheck": true,
    "requiresLocationCheck": true
  }
}
```

`id` is unique lowercase kebab-case. Use a stable location suffix for multiple
branches of the same enterprise. A repeated normalized name is allowed when
the location and ID identify genuinely different branches.

`location` requires `label`, `region`, finite `lat`/`lng`, and `precision`.
`address`, `state`, and `postcode` are the only optional keys. Precision is
`exact`, `postcode`, `town`, or `region`; `exact` requires an address and
`postcode` requires a postcode. NZ rows reject `state` and accept only
four-digit postcodes. AU rows require an ACT/NSW/NT/QLD/SA/TAS/VIC/WA state and
a four-digit postcode inside the reviewed state/territory ranges. Coordinates
must be inside the code-owned NZ or AU bounding box.

`workTypes` contains 1–8 unique machine values from the reviewed
legacy-to-v1 normalization set:

- `horticulture`, `orchard-contracting`, `labour-contracting`, `nursery`
- `packhouse`, `packhouse-orchard`, `packhouse-processing`
- `viticulture-contracting`, `viticulture-winery`, `quality-lab`
- `farm-processing`, `farm-packing`, `food-processing`
- `grain-processing`, `winery-processing`
- `livestock-processing`, `meat-processing`
- `mining`, `construction`, `job-gateway`

Localized Korean work labels are presentation data and are not accepted as
machine enums.

## Evidence and contact

`source` is mandatory. Its kind is one of:

- `government-register`
- `government-job-gateway`
- `industry-association`
- `employer-official`
- `verified-local-producer`
- `unverified`

The URL is HTTPS only, without credentials or fragments. Government kinds
require the matching `.govt.nz` or `.gov.au` host. Industry evidence is
restricted to the reviewed association-host allowlist: `nzkgi.org.nz`,
`freshproduce.org.au`, `ntfarmers.org.au`, and the national association
`ausveg.com.au`. Exact hosts and their subdomains are accepted; suffix
lookalikes such as `ausveg.com.au.example` are not. A
`verified-local-producer` must be backed by a reviewed association or
government source. An `employer-official` URL may not point to government or
association evidence; company/email contacts, when present, must have the same
registrable employer domain. A recruitment contact may truthfully use a
different recruitment platform. `unverified` evidence forces `status` to
`uncertain`.

`contact.kind` is `recruitment`, `company`, `email`, or `none`.
Recruitment/company require HTTPS, email requires one exact `mailto:` address,
and none forbids `url`.

`checkedAt`, optional `effectiveTo`, `nextReviewAt`, and `generatedAt` are real
canonical ISO dates. Future evidence checks fail. Active/uncertain rows become
stale after `nextReviewAt`. An elapsed `effectiveTo` forces `expired`; an
expired row requires an elapsed `effectiveTo`. Historical expired rows remain
auditable without pretending that their evidence is current.

`vacancyStatus` is exactly `directory-only`. Unknown `vacancy` fields and
current-hiring phrases in names/locations fail closed.

Eligibility is deliberately non-affirmative:

- NZ conditional rows use `nz-whv-extension`, `conditional`, role check true,
  location check false.
- AU conditional rows use `au-417-specified-work`, `conditional`, role check
  true, location check true.
- Non-eligibility gateways use `none`, `not-applicable`, and role check true.
  Their explicit location-check boolean may be true or false according to the
  gateway scope; it cannot make a `not-applicable` row eligible.

No `eligible`, `vacancy=true`, or role-check bypass is representable.

## Duplicate review

An exact normalized name + location + contact duplicate is an error. The
near-duplicate review set is deliberately narrower than geographic proximity:
two rows are candidates only when they are within 200 metres and share the
same normalized name or the same non-empty canonical contact. This avoids
flagging every business placed at a shared town/region centroid.

Candidates do not silently merge branches. They are counted in `audit` and
printed with:

```sh
python3 scripts/verify_employers.py data/employers.json \
  --today 2026-07-19 --dump-duplicates
```

## Offline and live commands

PR/default verification is network-free:

```sh
python3 scripts/verify_employers.py data/employers.json \
  --today 2026-07-19
```

The checked-in representative registry is:

```sh
python3 scripts/verify_employers.py tests/fixtures/employers.json \
  --today 2026-07-19 --dump-duplicates
```

Live checking is explicit:

```sh
python3 scripts/verify_employers.py data/employers.json \
  --today 2026-07-19 --check-links --timeout 10 \
  --output employer-link-report.json
```

Each canonical HTTPS URL is fetched once with GET, even when shared by several
rows. Only the first 512 KiB of the response body is read for empty/challenge
detection, then discarded. A larger valid 2xx page remains `match`; the live
check never requires or stores the complete body. The report stores only URL,
row IDs/roles, status, HTTP/final URL metadata, and an actionable message:

- `match`: non-empty 2xx on the reviewed HTTPS registrable host.
- `changed`: empty 2xx, 404/410, or other non-transient 4xx.
- `blocked`: 401/403 or an exact human/password access challenge.
- `transient`: 429, 5xx, DNS, TLS, connection, or timeout.
- `unsupported`: cross-host or insecure redirect.

Only `match` is green. Blocked/transient/unsupported never become match and do
not claim that employer data changed.

## Single issue reducer

`render_employer_issue.py` is pure: unit tests never call GitHub. It reads the
live report and the `gh issue list --json number,title,state,body` array:

```sh
python3 scripts/render_employer_issue.py \
  --report employer-link-report.json \
  --issues employer-link-existing.json \
  --output employer-link-issue.json
```

The exact title is `Employer directory link drift`. Zero or one exact-title
issue is allowed. The reducer emits `create`, `update`, `reopen`, `close`, or
`noop`. Its hidden v1 marker fingerprint excludes volatile `generatedAt` and
result order. Duplicate URLs/issues, malformed audit counts, and missing or
duplicate markers fail closed. No response body, email content, credential,
token, or user data enters the report or issue.

PR CI runs only the fixture and unit tests with `contents: read`. The separate
scheduled/manual workflow has `contents: read` and `issues: write`, concurrency
protection, one exact issue, and a final failure when any URL is non-match.

## Current migration inventory

Read-only inventory at main `69c1602`:

- NZ: 187 rows (167 RSE, 20 NZKGI), 148 without contact, 17 HTTPS contacts,
  22 email contacts, 27 elapsed RSE expiries, and 20 association rows without
  an expiry. All 187 need explicit precision and per-row source metadata.
- AU: 113 rows, 3 without contact and 110 HTTPS contacts. Current
  state/postcode mismatches are zero. All 113 need explicit precision; 91
  source values are labels/shared constants rather than row-level evidence.
- Exact duplicate rows are zero. Repeated-name multi-branch inventory is one
  NZ group (2 rows) and 11 AU groups (26 rows). Raw 200-metre coordinate
  proximity alone yields 36 NZ and 74 AU pairs, confirming why name/contact
  evidence is required before a pair becomes a duplicate candidate.

Migration procedure:

1. Assign stable country/company/location IDs and preserve one row per branch.
2. Map the old type text to the fixed `workTypes` enums.
3. Set reviewed location precision rather than inferring it from decimal
   digits; town/region centroids must not be labelled exact.
4. Attach one truthful per-row source kind/URL/check date and contact kind.
5. Convert elapsed RSE dates to `expired`; schedule active/uncertain reviews.
6. Encode only conditional eligibility and `directory-only` vacancy state.
7. Run the fixture tests, verifier with `--dump-duplicates`, then publish the
   exact derived audit. Live link checking remains schedule/manual only.

The synchronized 300-row production target audit is:

```json
{
  "employerCount": 300,
  "countryCounts": {"NZ": 187, "AU": 113},
  "statusCounts": {"active": 269, "uncertain": 4, "expired": 27},
  "contactableCount": 148,
  "expiredCount": 27,
  "nearDuplicateCandidateCount": 0,
  "linkUrlCount": 125
}
```

The verifier intentionally does not determine whether a specific job's
duties, dates, employer relationship, or worksite satisfy immigration rules.
That remains a role/location evidence review.
