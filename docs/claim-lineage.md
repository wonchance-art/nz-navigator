# Claim lineage execution contract

`scripts/verify_claim_lineage.mjs` verifies critical claims that are derived from official inputs rather than stated verbatim by one source. It is an offline, fail-closed layer after the source-attestation, runtime-parity, and boundary-execution gates.

## Registry schema

The production registry should be `data/claim-lineage.json`:

```json
{
  "schemaVersion": 1,
  "derivedCriticalScope": ["nz-ko-netpay-72800"],
  "mappings": [
    {
      "claimId": "nz-ko-netpay-72800",
      "edition": "nz",
      "page": "nz/index.html",
      "inputClaimIds": [
        "nz-ko-income-tax-brackets-2026",
        "nz-ko-acc-rate-2026",
        "nz-ko-acc-cap-2026"
      ],
      "transform": "calculator-execution",
      "target": "nz-netpay-72800",
      "expected": {"type": "number", "unit": "NZD/year", "value": 57466},
      "dates": {"verifiedAt": "2026-07-19", "effectiveFrom": "2026-04-01"},
      "evidenceTier": "derived-executed"
    }
  ]
}
```

The root and every mapping are exact-key objects. Unknown fields, expression fields, selectors, scripts, regexes, duplicate IDs, missing mappings, unsupported enums, and non-finite values fail. `derivedCriticalScope` must equal all current claims whose `status` is `derived` and `severity` is `critical`.

Every ordinary mapping has exactly these fields:

- `claimId`, `edition`, and `page`: an exact code-reviewed claim/edition binding.
- `inputClaimIds`: the exact code-reviewed official or derived DAG inputs. Each derived input must execute successfully first.
- `transform` and `target`: fixed enums described below.
- `expected`: exact scalar `type`, `unit`, and `value`, all equal to the output claim.
- `dates`: exact `verifiedAt`, `effectiveFrom`, and `effectiveTo` when the claim has it.
- `evidenceTier`: exactly `derived-executed`; lineage is never presented as a direct official quotation.

The two negative-evidence targets also require:

```json
"negativeEvidence": {
  "attestationId": "nz-japan-whv-hero",
  "mode": "exact-cardinality",
  "expectedMatches": 0
}
```

The AU resident bracket serialization is deliberately based on reviewed boundary components, not invented component claims:

```json
{
  "claimId": "au-ko-tax-brackets-2026",
  "edition": "au",
  "page": "au/index.html",
  "inputClaimIds": [],
  "transform": "boundary-serialization",
  "target": "au-resident-brackets-serialization",
  "expected": {
    "type": "string",
    "unit": "AUD/rate",
    "value": "18200@0;45000@0.15;135000@0.30;190000@0.37;above@0.45"
  },
  "dates": {
    "verifiedAt": "2026-07-19",
    "effectiveFrom": "2026-07-01",
    "effectiveTo": "2027-06-30"
  },
  "evidenceTier": "derived-executed",
  "boundaryEvidence": {
    "targetId": "au-tax",
    "reviewedPath": "/resident/brackets",
    "attestationIds": [
      "au-resident-tax-free-band",
      "au-resident-tax-brackets"
    ]
  }
}
```

Both attestation IDs, every reviewed leaf, checked-in fixture SHA, effective/review date, and unit `AUD/rate` are mandatory. Parent/child overlap, missing or duplicate leaf coverage, a source value mismatch, and a source unit mismatch fail. The resulting derived claim then becomes the DAG input of the AU WHM and resident calculator claims.

## Fixed execution targets

No registry-provided program is evaluated. The supported transforms and targets are code-owned:

- `sum`: IRCC IEC `184.75 + 100 = 284.75` and PGWP `155 + 100 = 255`, with exact CAD units.
- `calculator-execution`: NZ/JA PAYE plus ACC, CA Ontario tax, and AU WHM/resident tax. The actual production functions are lexically extracted into a minimal Node VM. Independently reviewed boundary formulas calculate the expected result.
- `crs-fixed-profile`: the production CRS renderer runs the fixed `a35/e120/l7/x1` profile. The official inputs are age 77, bachelor 120, CLB 7 at 17 points **per ability**, and Canadian experience 40; the code-owned transform independently computes `77 + 120 + (17 × 4) + 40 = 305`. Treating the four raw inputs as the false sum 254 fails.
- `boundary-serialization`: serializes the two ATO-attested resident bracket cohorts into the exact five-pair public claim.
- `uncapped-availability`: requires the exact, exhaustive four-field Japan WHV hero cohort and zero availability/quota fields.
- `constant-absence-zero`: requires the exact Home Affairs combined 820/801 plus ceased-record cohort, zero standalone 801 records, and exact fee/unit parity.

Calculator execution first reruns the complete v4 boundary manifest (currently 143 probes). A single sample therefore cannot bypass a changed bracket, cap, LITO, levy, or runtime branch. The code also rejects the reviewed gross/profile/output literals inside extracted production functions, including alternate JavaScript numeric forms such as separators, exponent notation, and hex.

Official scalar inputs require exactly one current source-attestation claim mapping. Structured inputs whose public string is a fixed serialization may instead be proven by the code-reviewed v4 boundary subtree; that subtree still requires exact source-attestation leaf coverage and runtime execution parity.

## Dates, DAG, and coverage

Claims and evidence use strict ISO dates. Critical inputs older than 45 days, future verification, inverted effective windows, input evidence that starts after the output, and evidence outside `reviewAfterDays` fail. Cross-country/page inputs and NZ/JA output parity drift also fail.

The deterministic audit is:

```json
{
  "derivedCriticalCount": 11,
  "mappedCount": 11,
  "executedCount": 11,
  "inputClaimCount": 23,
  "remainingCriticalCount": 0
}
```

Counts are computed, not trusted. If `claims.audit.claimLineage` exists, its exact five-key object must match. `--require-critical-coverage` additionally verifies every official critical claim's unique source mapping and requires the union of direct official evidence plus successfully executed lineage to leave zero critical claims uncovered.

## Commands

Run the checked-in four-edition fixture tests without network access:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_verify_claim_lineage -v
```

Run a migrated production registry:

```sh
node scripts/verify_claim_lineage.mjs \
  --claims data/claims.json \
  --attestations data/source-attestations.json \
  --bindings data/runtime-bindings.json \
  --boundaries data/boundary-executions.json \
  --lineage data/claim-lineage.json \
  --today 2026-07-19 \
  --require-critical-coverage
```

The default root is the repository root. All registry/fixture paths must remain under it. Errors include `code`, claim, edition, target, field, actual, expected, and `Fix`; the process exits 1.

## Production migration

1. Change `au-ko-tax-brackets-2026` to `status: derived` while retaining its exact ATO-derived value/unit/date contract.
2. Add the 11 mappings from `tests/fixtures/claim-lineage.json` to `data/claim-lineage.json`.
3. Add source-attested official component claims `ca-ko-open-work-permit-holder-fee` (100 CAD), `ca-ko-crs-age35-no-spouse` (77 points), `ca-ko-crs-bachelor-no-spouse` (120 points), `ca-ko-crs-clb7-per-ability-no-spouse` (17 points/ability), and `ca-ko-crs-canadian-work1-no-spouse` (40 points). Keep `ca-ko-tax-on-60000` effective from the T4127 123rd-edition cohort (`2026-07-01`).
4. Preserve the two AU resident boundary attestations exactly; do not replace them with a synthetic combined official claim.
5. Correct any direct-source effective-window mismatch, run without coverage first, then run `--require-critical-coverage` and publish the exact audit only after it reports zero remaining.

## Limits

The verifier proves only the 11 reviewed transforms in its code-owned target table. Adding a new derived critical claim intentionally fails scope/mapping validation until a new fixed target and adversarial tests are reviewed; arbitrary business formulas are not accepted from JSON.
