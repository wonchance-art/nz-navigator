# Employer evidence lineage v1

`data/employer-evidence.json` binds every row in `data/employers.json` to one
reviewed source cohort and one immutable source record. It does not claim that
directory inclusion is a current vacancy or that a role is eligible for an NZ
Working Holiday Extension or Australian subclass 417 specified work.

## Evidence levels

- `machine-extracted`: the checked-in official response is parsed and matched
  to the employer row. INZ RSE bindings use the official `record_id`, full
  registered address, coordinates, and status expiry date. NZKGI bindings
  require reviewed business, operating-area, and contact tokens from the
  published PDF text representation.
- `hybrid`: the official AFPA member page proves the member entity, while the
  branch location remains a separately frozen reviewed snapshot.
- `reviewed-snapshot`: heterogeneous official company, government gateway, or
  official third-party pages were reviewed, but their branch facts are not
  promoted to safe machine extraction.
- `limited-candidate`: a useful candidate whose official status remains
  unverified. Such an employer must remain `uncertain`.

Every binding publishes its evidence scopes, the meaning of the location
(`registered-address`, `listed-operating-area`, `reviewed-worksite`, or
`reviewed-service-area`), and explicit limitations. All bindings retain the
`directory-not-current-vacancy` and visa-eligibility limitations.

## Deterministic gate

Run:

```sh
node --test tests/test_build_employer_evidence.mjs
node scripts/build_employer_evidence.mjs --check
```

The gate fails when an employer is unbound, an INZ record is reused or
orphaned, an official name/address/coordinate/expiry changes, an NZKGI source
token disappears, an AFPA member alias disappears, a reviewed AU source,
location, or contact drifts, a limited candidate is promoted, a fixture hash
changes, or the published audit is stale.

`--refresh-rse` and `--write` are maintainer-only update operations. They must
only be run after reviewing a newly fetched official INZ response and the
resulting diff.
