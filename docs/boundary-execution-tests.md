# Boundary execution verification

`scripts/verify_boundary_execution.mjs` connects every boundary declaration in
`data/runtime-bindings.json` to either an executed calculator suite or an
executed semantic assertion. It uses only Node built-ins and works offline.

The reviewed production manifest is `data/boundary-executions.json`.
`tests/fixtures/boundary-executions.json` is the representative four-edition
fixture. The CLI accepts arbitrary repository-relative inputs:

```sh
node scripts/verify_boundary_execution.mjs \
  --claims data/claims.json \
  --bindings data/runtime-bindings.json \
  --manifest data/boundary-executions.json
```

All three paths default to the production locations. Paths may not escape the
selected `--root`.

## Manifest root

The root has exactly four fields:

```json
{
  "schemaVersion": 1,
  "requiredExecutions": [
    "nz-paye-acc-nz",
    "nz-paye-acc-ja",
    "ca-tax",
    "au-tax"
  ],
  "targets": [],
  "mappings": []
}
```

`requiredExecutions` makes policy suites such as Canadian tax mandatory even
when the current runtime boundary registry has no Canadian tax-rate claim.
Every id must resolve to one target. A target that is neither required nor
referenced by a mapping is an orphan and fails.

## Execution targets

Every target has exactly these fields:

| Field | Rule |
| --- | --- |
| `id` | Unique non-empty target id. |
| `kind` | `nz-paye-acc`, `ca-tax`, or `au-tax`. |
| `edition` | `nz`, `ja`, `ca`, or `au`, compatible with `kind`. |
| `page` | Canonical edition page. |
| `probeDelta` | Positive finite distance used for just-below and just-above inputs. |
| `tolerance` | Non-negative finite numeric comparison tolerance. |
| `rules` | Exact kind-specific reviewed rule set. |
| `reviewed` | Independent official constants used by the expected implementation. |

The exact rule sets are:

- NZ: `bracket-continuity`, `acc-cap-plateau`
- CA: `bracket-continuity`, `cpp-cap-plateau`,
  `cpp2-cap-plateau`, `ei-cap-plateau`
- AU: `bracket-continuity`, `lito-continuity`

Omitting a rule is a schema failure; the runner does not silently reduce test
coverage.

Bracket tables use `[cap, rate]` rows. The final unbounded cap is JSON `null`,
not a string or an executable `Infinity` expression. Caps must be strictly
increasing and rates must be finite and non-negative.

### Reviewed NZ constants

```json
{
  "brackets": [
    [15600, 0.105],
    [53500, 0.175],
    [78100, 0.3],
    [180000, 0.33],
    [null, 0.39]
  ],
  "acc": {"rate": 0.0175, "cap": 156641}
}
```

### Reviewed Canadian constants

The Canadian object contains:

- `federal`: `brackets`, `bpa`, `employmentAmount`, `creditRate`
- `provinces.on|bc|ab`: `brackets`, `bpa`
- `cpp`: `rate`, `baseRate`, `additionalRate`, `ympe`, `exempt`,
  `cpp2Rate`, `cpp2Min`, `cpp2Max`
- `ei`: `rate`, `maxInsurable`
- `ontario`: surtax thresholds/rates, `taxReduction`, and the reviewed health
  premium tier formulas

`cpp.rate` must equal `baseRate + additionalRate`; caps must be ordered.

### Reviewed Australian constants

The Australian object contains:

- `whm`: `cap`, `rate`
- `resident`: `brackets`, `medicareRate`, `superRate`
- `resident.lito`: `maxOffset`, `fullTo`, `taper1To`, `taper1Rate`,
  `cutOut`, `taper2Rate`

LITO thresholds must be ordered.

## Boundary mappings

Every runtime binding with `boundary` metadata must have exactly one mapping
for the same claim and edition. Extra mappings, duplicate mappings, and
missing mappings fail.

Executed calculator mapping:

```json
{
  "claimId": "nz-ko-acc-cap-2026",
  "edition": "nz",
  "mode": "execute",
  "targetId": "nz-paye-acc-nz",
  "assertion": "nz-acc-cap"
}
```

Executed assertion enums are:

- NZ: `nz-paye-brackets`, `nz-acc-rate`, `nz-acc-cap`
- AU: `au-whm-rate`, `au-resident-brackets`, `au-medicare-rate`,
  `au-super-rate`

Canadian tax is a required policy target rather than a current claim mapping.

Age range mapping:

```json
{
  "claimId": "ca-ko-iec-age",
  "edition": "ca",
  "mode": "semantic",
  "assertion": {
    "kind": "inclusive-range",
    "min": 18,
    "max": 35,
    "delta": 1
  }
}
```

Maximum duration mapping:

```json
{
  "claimId": "ca-ko-iec-duration",
  "edition": "ca",
  "mode": "semantic",
  "assertion": {
    "kind": "maximum",
    "value": 24,
    "delta": 1
  }
}
```

`semantic` is not a waiver. The runner parses the claim boundary and executes
real boolean probes. An inclusive range tests below-min, exact-min, exact-max,
and above-max. A maximum tests just-below, exact, and just-above. These probes
are included in the public probe total.

## Actual and expected execution

Actual results come from the real inline calculators:

- NZ/JA `NP_BRACKETS`, `NP_ACC`, `npTax`, and the ACC expression in
  `renderNetPay`
- CA `CA_TAX` and `npTax`
- AU `AU_TAX`, `npTaxResident`, and `npTax`

Extraction is limited to named declarations found within one inline script.
Constants must start as direct object/array literals. The runner masks strings
and comments before checking forbidden code tokens, so a source URL containing
words such as `document` cannot be mistaken for executable DOM access. The ACC
expression has a small identifier/operator allowlist.

Only the extracted declarations are executed in a fresh Node VM context with
string/wasm code generation disabled, no `process`, `require`, DOM, or network,
and a short timeout. The manifest never supplies code or an expression.

Expected values are calculated separately from the reviewed manifest:

- progressive PAYE and ACC cap behavior;
- Canadian federal/ON/BC/AB tax plus CPP, CPP2, EI, Ontario surtax, health
  premium, and tax reduction;
- Australian WHM cap transition, resident brackets, LITO, Medicare, and super.

Expected formulas never read the extracted runtime constants. Every official
threshold is tested at just-below, exact, and just-above using the declared
delta and tolerance. The reviewed production manifest currently executes 143
probes: NZ/JA 30, CA 69, AU 24, and age/duration assertions 20.

## Failures and audit

Failures exit 1 and use this format:

```text
ERROR code=<code> edition=<edition> claim=<id>
boundary=<target-or-rule> probe=<position:value>
actual=<value> expected=<value>
  Fix: <action>
```

Missing/orphan mappings, missing/orphan targets, invalid rules, extraction
failures, non-finite manifest values, and probe mismatches are actionable
failures.

When the selected manifest is `data/boundary-executions.json`, the runner also
requires:

```json
{
  "audit": {
    "runtimeBindings": {
      "boundaryProbeCount": 143
    }
  }
}
```

The success summary reports mapping, target, and probe counts:

```text
Boundary execution verification passed: 16 mapping(s), 4 execution target(s), 143 probe(s).
```

Run focused tests with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_verify_boundary_execution -v
```
