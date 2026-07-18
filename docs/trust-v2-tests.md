# Trust v2 regression tests

Trust v2 adds two offline checks to the factual-claim workflow. Both use only
the Python or Node.js standard library and do not make network requests.

## Numeric claim coverage

Run:

```sh
python3 scripts/verify_claim_coverage.py
```

The verifier scans `nz/index.html`, `ja/index.html`, `ca/index.html`, and
`au/index.html` in a deterministic order. It finds numeric facts in these
contexts:

- visa, application, and permit fees
- age limits and quotas
- minimum, median, hourly, and salary figures
- tax rates and tax tables
- proof-of-funds and settlement-funds requirements
- visa, permit, residence, and work durations
- processing times

The scanner covers visible semantic elements (`p`, `li`, table rows, labels,
summaries, and headings) plus stable structured-data boundaries in the main
inline script:

- `DB.wages`, `DB.fees`, and funds-related `DB.estimates`
- `DB.pathways` duration, requirement, and processing fields
- `NP_BRACKETS`, `CA_TAX`, and `AU_TAX`

A visible occurrence is covered directly when it or an ancestor has a
`data-claim-id`. Repeated copies of the same fact are also covered when the
same normalized value and category occur in a marked fact on that edition.
Claim-id names such as `-fee`, `-age`, `-duration`, `-wage`, and `-funds`
provide a category boundary when translated copy does not contain an
English keyword.

The number normalizer treats comma-separated numbers and `k`/`m` suffixes
consistently. It ignores calendar dates, long phone-like numbers, known visa
subclass identifiers, SVG and map coordinates, and content below scenario,
flight, calendar, map, or diagnosis containers. Local clause boundaries keep
unrelated IELTS scores, work hours, dates, and example inputs from being
attached to a nearby fee, wage, age, or funds keyword.

Every uncovered error includes the repository-relative selector, category,
line, normalized numbers, fingerprint, source text, and the two supported
fixes. Use the review view when preparing an exemption:

```sh
python3 scripts/verify_claim_coverage.py --dump-uncovered
```

### Exemption approval

Exemptions live in `data/claim-coverage-exemptions.json`. The default registry
is intentionally empty. Each approved entry must contain:

```json
{
  "selector": "nz/index.html::#example>p:nth-of-type(1)",
  "fingerprint": "sha256:0123456789abcdef0123",
  "reason": "Why this numeric text is intentionally outside the claim registry.",
  "owner": "Accountable team or person",
  "expiresAt": "2026-08-31"
}
```

Approval is exact: both selector and text fingerprint must match. The reason
must explain why adding a claim marker would be incorrect, not merely defer
work. The owner is responsible for review before the ISO expiry date.
Expired exemptions fail CI. Removed or changed candidates leave an orphan
exemption, which also fails CI; update a fingerprint only after reviewing the
changed text. Do not renew an exemption without rechecking the underlying
fact.

Fixture tests create their pages and exemption registries in temporary
directories, so they do not depend on repository claim data:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_verify_claim_coverage -v
```

## Diagnosis regression harness

Run:

```sh
node scripts/verify_diagnosis.mjs
```

`tests/fixtures/diagnosis-cases.json` contains four representative inputs for
each NZ, JA, CA, and AU edition. The NZ and JA cases form four parity pairs.
Every fixture provides all eight diagnosis inputs and an expected primary
route, optional alternate route, study variant, and minimum warning count.

The harness locates the inline script containing `const DB`, then uses a
string/comment-aware lexical scanner to extract these actual page boundaries:

- `DB`, `START_FUNDS`, `JOB_SAVE`, `WHV_SAVE`, `ENTRY_LABEL`, and
  `ENTRY_ADJUST`
- `recommend`, `runDiagnose`, `moneyPlanRows`, `entryAdjustedPathway`, and
  `resolveBVariant`
- the automatic study-variant keys from `renderDiagnoseResult`

Those definitions run in a Node `vm` context with a minimal DOM that supplies
only checked diagnosis inputs and the result element. The test does not
replace `DB.pathways` with fixture data.

For every case the verifier checks:

- the recommendation and optional alternate route
- input echo consistency and warning-based contradictory-input handling
- existence of the selected `DB.pathways` entry
- automatic study-variant resolution against the real `studyVariants` keys
- removal of an already-completed WHV/IEC/417 entry stage
- non-empty timeline fields and stages
- finite, non-reversed duration and stage-month values
- non-empty money rows, finite deltas, and non-reversed row and cumulative
  ranges
- NZ/JA parity for route ids, adjusted duration, stage months, money deltas,
  and SMC numeric shape

Every failure includes `edition`, fixture id, field, `actual`, and `expected`
so the affected edition and regression boundary are visible in CI.

## Limits

The coverage scanner is deliberately lexical. It does not execute arbitrary
JavaScript or infer values assembled from unrelated runtime expressions.
Values outside the documented HTML and structured-data boundaries require a
new explicit extraction rule and fixture.

The diagnosis harness is not a browser test. It does not validate CSS,
layout, click wiring, generated markup, storage, share controls, or network
behavior. Its stable boundary is the pure diagnosis/data functions embedded
in each edition. Renaming or materially restructuring one of those functions
will fail extraction with an actionable error and requires a deliberate
harness update.

Run the complete local trust suite with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/verify_claims.py data/claims.json
python3 scripts/verify_claim_coverage.py
node scripts/verify_calculators.mjs
node scripts/verify_diagnosis.mjs
```
