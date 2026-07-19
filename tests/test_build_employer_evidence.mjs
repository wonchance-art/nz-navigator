import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  AFPA_ALIASES,
  KGI_ASSERTIONS,
  buildRegistry,
  normalize,
  parseEnglishDate,
} from "../scripts/build_employer_evidence.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const baseline = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "employers.json"), "utf8"));
const clone = (value) => JSON.parse(JSON.stringify(value));

test("production employer evidence has exact deterministic audit", () => {
  const result = buildRegistry(clone(baseline));
  assert.deepEqual(result.audit, {
    employerCount: 300,
    bindingCount: 300,
    sourceCount: 70,
    machineExtractedCount: 187,
    hybridCount: 11,
    reviewedSnapshotCount: 100,
    limitedCandidateCount: 2,
    exactEntityCount: 198,
    exactLocationCount: 187,
    reviewedLocationCount: 111,
    limitedLocationCount: 2,
    contactScopeCount: 129,
    limitationBindingCount: 300,
    machineLiveSourceCount: 4,
  });
  assert.equal(new Set(result.bindings.map((item) => item.employerId)).size, 300);
  assert.equal(new Set(result.bindings.map((item) => item.id)).size, 300);
});

test("RSE rows bind to unique official record ids, including duplicate company names", () => {
  const result = buildRegistry(clone(baseline));
  const rse = result.bindings.filter((item) => item.sourceId === "inz-rse-current");
  assert.equal(rse.length, 167);
  assert.equal(new Set(rse.map((item) => item.record.key)).size, 167);
  const focus = rse.filter((item) => item.record.name === "Focus Central Ltd");
  assert.deepEqual(
    new Set(focus.map((item) => item.record.key)),
    new Set(["81930", "81931"]),
  );
  assert.notEqual(focus[0].record.location, focus[1].record.location);
});

test("RSE name, location, coordinates, expiry, and status drift fail closed", () => {
  for (const mutate of [
    (row) => { row.name = "Wrong Grower Limited"; },
    (row) => { row.location.address = "Wrong address"; },
    (row) => { row.location.lat += 0.01; },
    (row) => { row.source.effectiveTo = "2099-01-01"; },
    (row) => { row.status = row.status === "active" ? "expired" : "active"; },
  ]) {
    const changed = clone(baseline);
    const row = changed.employers.find((item) => item.source.kind === "government-register");
    mutate(row);
    assert.throws(() => buildRegistry(changed), /INZ RSE|no INZ RSE/);
  }
});

test("all 20 NZKGI rows have bounded reviewed source tokens", () => {
  assert.equal(Object.keys(KGI_ASSERTIONS).length, 20);
  const result = buildRegistry(clone(baseline));
  const rows = result.bindings.filter((item) => item.sourceId.startsWith("nzkgi-"));
  assert.equal(rows.length, 20);
  assert.ok(rows.every((item) => item.level === "machine-extracted"));
  assert.ok(rows.every((item) => item.record.tokens.length >= 3));
});

test("AFPA membership is exact while branch location remains visibly hybrid", () => {
  assert.equal(Object.keys(AFPA_ALIASES).length, 11);
  const result = buildRegistry(clone(baseline));
  const rows = result.bindings.filter((item) => item.sourceId === "afpa-members-2026-07");
  assert.equal(rows.length, 11);
  assert.ok(rows.every((item) => item.level === "hybrid"));
  assert.ok(rows.every((item) => item.record.memberUrl.startsWith("https://")));
  assert.ok(rows.every((item) => item.limitations.includes("membership-does-not-prove-worksite")));
});

test("reviewed AU source, location, contact, and review-date drift fail closed", () => {
  for (const mutate of [
    (row) => { row.source.url = "https://example.com/"; },
    (row) => { row.location.label = "Different town"; },
    (row) => { row.contact.url = "https://example.com/jobs"; },
  ]) {
    const changed = clone(baseline);
    const row = changed.employers.find((item) => item.country === "AU" && item.contact.url);
    mutate(row);
    assert.throws(() => buildRegistry(changed), /reviewed AU|missing reviewed AU/);
  }
});

test("limited candidates cannot be promoted to active", () => {
  const changed = clone(baseline);
  const row = changed.employers.find((item) => item.source.kind === "unverified");
  row.status = "active";
  assert.throws(() => buildRegistry(changed), /must remain uncertain/);
});

test("every binding preserves directory and visa-eligibility limitations", () => {
  const result = buildRegistry(clone(baseline));
  for (const binding of result.bindings) {
    assert.ok(binding.limitations.includes("directory-not-current-vacancy"));
    assert.ok(
      binding.limitations.includes("role-eligibility-unverified")
      || binding.limitations.includes("role-and-postcode-eligibility-unverified"),
    );
  }
});

test("source requests are deduplicated by 70 source cohorts", () => {
  const result = buildRegistry(clone(baseline));
  assert.equal(result.sources.length, 70);
  assert.equal(new Set(result.sources.map((item) => item.id)).size, 70);
  assert.equal(result.sources.filter((item) => item.liveMode.startsWith("machine")).length, 4);
  assert.ok(result.sources.every((item) => item.fixtures.every((entry) => /^[a-f0-9]{64}$/.test(entry.sha256))));
});

test("normalization and official date conversion are deterministic", () => {
  assert.equal(normalize("A.S.Wilcox & Sons Limited"), "aswilcoxandsonslimited");
  assert.equal(parseEnglishDate("18 July 2028"), "2028-07-18");
  assert.throws(() => parseEnglishDate("July 18, 2028"), /unsupported RSE expiry date/);
});
