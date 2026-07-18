# Runtime binding registry

The runtime parity verifier connects reviewed claims in `data/claims.json` to
the constants that calculators, roadmaps, and diagnosis logic actually use.
It is offline, deterministic, and implemented with the Python standard
library.

The production migration target is `data/runtime-bindings.json`. Until that
file exists, CI verifies the representative four-edition registry at
`tests/fixtures/runtime-bindings.json`. The verifier always requires an
explicit `--bindings` argument, so adding the code does not silently impose
full-registry coverage.

## Root schema

```json
{
  "schemaVersion": 1,
  "claimScope": [
    "nz-ko-whv-fee",
    "nz-ja-whv-fee"
  ],
  "parityKeys": [
    "nz-whv-fee"
  ],
  "bindings": []
}
```

`schemaVersion` and `bindings` are required.

`claimScope` is optional. When omitted, it is the unique set of `claimId`
values in `bindings`. When present, it declares an incremental migration
cohort:

- every scope id must exist in `data/claims.json`;
- every scope claim must have exactly one binding for its edition;
- a missing binding is an orphan claim and fails verification.

`parityKeys` is optional. For every listed key, all claims carrying that
`parityKey` must be in the binding cohort. The verifier compares the
transformed runtime values and units, providing an NZ/JA runtime layer in
addition to claim-registry parity.

## Binding entry

```json
{
  "claimId": "nz-ko-acc-rate-2026",
  "edition": "nz",
  "page": "nz/index.html",
  "runtimePath": "NP_ACC.rate",
  "type": "number",
  "unit": "percent",
  "transform": {
    "op": "multiply",
    "factor": 100
  },
  "boundary": {
    "kind": "rate"
  }
}
```

Required entry fields:

| Field | Rule |
| --- | --- |
| `claimId` | Must resolve to one claim and belong to `claimScope`. |
| `edition` | One of `nz`, `ja`, `ca`, or `au`. |
| `page` | Must be the canonical page for the edition and occur in the claim's `pages`. |
| `runtimePath` | A path string, except that `sum` requires an array of at least two path strings. |
| `type` | Transformed value type: `number`, `string`, `array`, `object`, `boolean`, or `null`. |
| `unit` | Exact match for the claim's `unit`. |
| `transform` | An object containing one allowlisted `op`. |

`boundary` is optional. Its `kind` is `rate`, `insurance`, `age`, or
`duration`. Successful bindings with boundary metadata can generate
machine-readable edge cases with `--dump-boundaries`.

Two entries may not bind the same claim and edition. They also may not bind
the same edition, page, and runtime target. These rules prevent aliases from
making one runtime value appear independently reviewed twice.

## Runtime path grammar

Paths start at an inline `const` data literal:

```text
NP_BRACKETS
DB.fees.whv.v
CA_TAX.cpp.rate
NP_BRACKETS[0][1]
DB.pathways[id=A].stages[0].months
```

Supported segments are:

- `.property` for object properties;
- `[0]` for numeric array indexes;
- `[key=value]` for exactly one object in an array, such as a pathway id.

The stable selector form is preferred over a numeric index for arrays whose
order may change.

The `sum` transform is the only case where `runtimePath` is an array:

```json
{
  "claimId": "ca-ko-iec-fees",
  "edition": "ca",
  "page": "ca/index.html",
  "runtimePath": [
    "DB.fees.iecProgram.v",
    "DB.fees.openWorkPermit.v"
  ],
  "type": "number",
  "unit": "CAD",
  "transform": { "op": "sum" }
}
```

## Safe extraction

The verifier does not call `eval`, `exec`, a browser, or Node VM. It uses a
comment- and string-aware parser for a restricted JavaScript data-literal
subset:

- objects and arrays;
- quoted strings;
- finite decimal numbers;
- booleans and `null`;
- `NaN` and `Infinity` only so they can be rejected explicitly.

Backtick blocks inside a large `DB` object are retained as opaque strings;
`${...}` content is never evaluated. Functions, operators, references to
other identifiers, and computed expressions are rejected. A declaration
must contain one semicolon-terminated literal. This makes extraction fail
closed when a runtime value stops being declarative data.

All transformed output must be finite. The sole sentinel exception is the
final positive `Infinity` threshold accepted by `serializeBrackets`; it is
converted to the configured text label and never reaches comparison output
as a non-finite number.

## Transform allowlist

Transforms are declarative. No binding can provide executable code.

### `identity`

Returns the extracted value unchanged.

```json
{ "op": "identity" }
```

### `multiply`

Multiplies one numeric value by a finite factor. This maps a runtime decimal
rate to a percentage claim:

```json
{ "op": "multiply", "factor": 100 }
```

### `sum`

Adds the finite numeric values from a `runtimePath` array. It supports
composite claims such as IEC program fee plus open-work-permit fee:

```json
{ "op": "sum" }
```

### `joinRange`

Converts a two-number runtime array into a canonical string. The default
separator is `-`.

```json
{ "op": "joinRange", "separator": "-" }
```

### `extractRange`

Extracts the first numeric range from a literal runtime string and emits a
canonical range. It covers age and duration text such as `18–35세`.

```json
{ "op": "extractRange", "separator": "-" }
```

### `serializeBrackets`

Serializes `[threshold, rate]` rows into the claim registry's compact table
form:

```json
{
  "op": "serializeBrackets",
  "infinityLabel": "above",
  "preserveRateScale": true
}
```

For example, `[[15600, 0.105], [Infinity, 0.39]]` becomes
`15600@0.105;above@0.39`. `preserveRateScale` retains source spellings such
as `0.30` when the reviewed claim intentionally includes that precision.

## Verification failures

Every error exits with status 1 and includes:

```text
claim=<id> edition=<edition> runtimePath=<path>
actual=<value> expected=<value>
Fix: <action>
```

Failures cover:

- value, unit, type, and edition/page mismatch;
- missing or unsupported constants and path segments;
- duplicate claim or runtime bindings;
- orphan claims, bindings, scope entries, and parity members;
- transform shape or argument failure;
- `NaN`, unconverted `Infinity`, and other non-finite output;
- NZ/JA runtime parity mismatch.
- a public `claims.audit.runtimeBindings` summary that does not exactly match
  the production binding, claim, and generated boundary-set totals.

## Commands

Verify the checked representative bindings:

```sh
python3 scripts/verify_runtime_parity.py \
  --bindings tests/fixtures/runtime-bindings.json
```

Generate boundary cases after verification:

```sh
python3 scripts/verify_runtime_parity.py \
  --bindings tests/fixtures/runtime-bindings.json \
  --dump-boundaries
```

Run focused tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_verify_runtime_parity -v
```

## Production migration

1. Inventory claims whose reviewed value directly controls a runtime
   constant. Start with fees, wages, proof-of-funds values, tax and insurance
   rates, and pathway age/duration boundaries.
2. Create `data/runtime-bindings.json` with `schemaVersion: 1`. Add a small
   explicit `claimScope` so missing bindings fail within the migration cohort
   without requiring every claim on day one.
3. Migrate both members of an NZ/JA parity pair together and add its
   `parityKey`. Do not bind only one translation.
4. Prefer stable selectors such as `DB.pathways[id=A]`. Use numeric indexes
   only for fixed tuples such as tax-bracket rows.
5. Run the verifier and review every mismatch. Change protected claims or
   HTML only through the factual-source workflow; do not edit a binding to
   conceal an unexplained discrepancy.
6. Run `--dump-boundaries` and feed rate, insurance, age, and duration cases
   into later calculator boundary tests.
7. Commit the production binding registry. CI already detects
   `data/runtime-bindings.json` and runs it strictly when present.
8. Expand `claimScope` in reviewed batches until all runtime-backed claims
   are bound. Claims that are display-only remain outside this registry.
