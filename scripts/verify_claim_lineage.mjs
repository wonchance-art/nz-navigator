#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

import {
  executeReviewedCrsProfile,
  executeReviewedLineageSample,
  verifyBoundaryExecution,
} from './verify_boundary_execution.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const DEFAULT_ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
const SCHEMA_VERSION = 1;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_FIXTURE_BYTES = 12 * 1024 * 1024;
const OUTPUT_FIELDS = ['type', 'unit', 'value'];
const BASE_MAPPING_FIELDS = [
  'claimId',
  'edition',
  'page',
  'inputClaimIds',
  'transform',
  'target',
  'expected',
  'dates',
  'evidenceTier',
];
const EDITIONS = Object.freeze({
  nz: Object.freeze({ country: 'NZ', locale: 'ko', page: 'nz/index.html' }),
  ja: Object.freeze({ country: 'NZ', locale: 'ja', page: 'ja/index.html' }),
  ca: Object.freeze({ country: 'CA', locale: 'ko', page: 'ca/index.html' }),
  au: Object.freeze({ country: 'AU', locale: 'ko', page: 'au/index.html' }),
});

const TARGETS = Object.freeze({
  'nz-ja-whv-uncapped': Object.freeze({
    claimId: 'nz-ja-whv-cap',
    edition: 'ja',
    page: 'ja/index.html',
    transform: 'uncapped-availability',
    inputClaimIds: [
      'nz-ja-whv-age',
      'nz-ja-whv-duration',
      'nz-ja-whv-fee',
      'nz-ja-whv-processing',
    ],
    negativeAttestationId: 'nz-japan-whv-hero',
  }),
  'nz-netpay-72800': Object.freeze({
    claimId: 'nz-ko-netpay-72800',
    edition: 'nz',
    page: 'nz/index.html',
    transform: 'calculator-execution',
    inputClaimIds: [
      'nz-ko-income-tax-brackets-2026',
      'nz-ko-acc-rate-2026',
      'nz-ko-acc-cap-2026',
    ],
    boundaryTargetId: 'nz-paye-acc-nz',
    gross: 72800,
  }),
  'ja-netpay-72800': Object.freeze({
    claimId: 'nz-ja-netpay-72800',
    edition: 'ja',
    page: 'ja/index.html',
    transform: 'calculator-execution',
    inputClaimIds: [
      'nz-ja-income-tax-brackets-2026',
      'nz-ja-acc-rate-2026',
      'nz-ja-acc-cap-2026',
    ],
    boundaryTargetId: 'nz-paye-acc-ja',
    gross: 72800,
  }),
  'ca-iec-fees': Object.freeze({
    claimId: 'ca-ko-iec-fees',
    edition: 'ca',
    page: 'ca/index.html',
    transform: 'sum',
    inputClaimIds: [
      'ca-ko-iec-program-fee',
      'ca-ko-open-work-permit-holder-fee',
    ],
  }),
  'ca-pgwp-fee': Object.freeze({
    claimId: 'ca-ko-pgwp-fee',
    edition: 'ca',
    page: 'ca/index.html',
    transform: 'sum',
    inputClaimIds: [
      'ca-ko-work-permit-fee',
      'ca-ko-open-work-permit-holder-fee',
    ],
  }),
  'ca-crs-profile-305': Object.freeze({
    claimId: 'ca-ko-crs-sample-305',
    edition: 'ca',
    page: 'ca/index.html',
    transform: 'crs-fixed-profile',
    inputClaimIds: [
      'ca-ko-crs-age35-no-spouse',
      'ca-ko-crs-bachelor-no-spouse',
      'ca-ko-crs-clb7-per-ability-no-spouse',
      'ca-ko-crs-canadian-work1-no-spouse',
    ],
    profile: Object.freeze({
      age: 'a35',
      education: 'e120',
      language: 'l7',
      experience: 'x1',
    }),
    componentClaims: Object.freeze({
      age: Object.freeze({
        claimId: 'ca-ko-crs-age35-no-spouse',
        unit: 'points',
        multiplier: 1,
      }),
      education: Object.freeze({
        claimId: 'ca-ko-crs-bachelor-no-spouse',
        unit: 'points',
        multiplier: 1,
      }),
      language: Object.freeze({
        claimId: 'ca-ko-crs-clb7-per-ability-no-spouse',
        unit: 'points/ability',
        multiplier: 4,
      }),
      experience: Object.freeze({
        claimId: 'ca-ko-crs-canadian-work1-no-spouse',
        unit: 'points',
        multiplier: 1,
      }),
    }),
  }),
  'ca-on-netpay-60000': Object.freeze({
    claimId: 'ca-ko-tax-on-60000',
    edition: 'ca',
    page: 'ca/index.html',
    transform: 'calculator-execution',
    inputClaimIds: ['ca-ko-tax-constants-2026'],
    boundaryTargetId: 'ca-tax',
    gross: 60000,
    mode: 'on',
  }),
  'au-resident-brackets-serialization': Object.freeze({
    claimId: 'au-ko-tax-brackets-2026',
    edition: 'au',
    page: 'au/index.html',
    transform: 'boundary-serialization',
    inputClaimIds: [],
    boundaryTargetId: 'au-tax',
    boundaryReviewedPath: '/resident/brackets',
    boundaryUnit: 'AUD/rate',
    boundaryAttestationIds: Object.freeze([
      'au-resident-tax-free-band',
      'au-resident-tax-brackets',
    ]),
  }),
  'au-whm-netpay-52115': Object.freeze({
    claimId: 'au-ko-tax-whm-52115',
    edition: 'au',
    page: 'au/index.html',
    transform: 'calculator-execution',
    inputClaimIds: [
      'au-ko-whm-tax-rate',
      'au-ko-tax-brackets-2026',
    ],
    boundaryTargetId: 'au-tax',
    gross: 52115,
    mode: 'whm',
  }),
  'au-resident-netpay-60000': Object.freeze({
    claimId: 'au-ko-tax-resident-60000',
    edition: 'au',
    page: 'au/index.html',
    transform: 'calculator-execution',
    inputClaimIds: [
      'au-ko-tax-brackets-2026',
      'au-ko-tax-medicare-rate-2026',
      'au-ko-tax-lito-2026',
    ],
    boundaryTargetId: 'au-tax',
    gross: 60000,
    mode: 'resident',
  }),
  'au-partner-801-separate-zero': Object.freeze({
    claimId: 'au-ko-partner-801-separate-fee',
    edition: 'au',
    page: 'au/index.html',
    transform: 'constant-absence-zero',
    inputClaimIds: ['au-ko-partner-820-fee'],
    negativeAttestationId: 'au-partner-820-fee',
  }),
});

const TRANSFORMS = new Set([
  'sum',
  'calculator-execution',
  'crs-fixed-profile',
  'uncapped-availability',
  'constant-absence-zero',
  'boundary-serialization',
]);

function display(value) {
  if (value === undefined) return 'undefined';
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export class LineageReport {
  constructor() {
    this.issues = [];
    this.audit = {
      derivedCriticalCount: 0,
      mappedCount: 0,
      executedCount: 0,
      inputClaimCount: 0,
      remainingCriticalCount: 0,
    };
  }

  issue({
    code,
    claim = '<lineage>',
    edition = '<all>',
    target = '<schema>',
    field = '<root>',
    actual,
    expected,
    fix,
  }) {
    this.issues.push({
      code, claim, edition, target, field, actual, expected, fix,
    });
  }

  render(issue) {
    return (
      `ERROR code=${issue.code} claim=${issue.claim} ` +
      `edition=${issue.edition} target=${issue.target} field=${issue.field} ` +
      `actual=${display(issue.actual)} expected=${display(issue.expected)}\n` +
      `  Fix: ${issue.fix}`
    );
  }
}

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join('\0') === [...keys].sort().join('\0')
  );
}

function deepEqual(left, right) {
  if (typeof left === 'number' || typeof right === 'number') {
    return (
      typeof left === 'number' &&
      typeof right === 'number' &&
      Number.isFinite(left) &&
      Number.isFinite(right) &&
      Object.is(left, right)
    );
  }
  if (left === null || right === null || typeof left !== 'object' || typeof right !== 'object') {
    return left === right;
  }
  if (Array.isArray(left) !== Array.isArray(right)) return false;
  if (Array.isArray(left)) {
    return left.length === right.length && left.every(
      (item, index) => deepEqual(item, right[index]),
    );
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.join('\0') === rightKeys.join('\0') &&
    leftKeys.every(key => deepEqual(left[key], right[key]))
  );
}

function finiteTree(value, depth = 0) {
  if (depth > 32) return false;
  if (typeof value === 'number') return Number.isFinite(value);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return true;
  }
  if (Array.isArray(value)) {
    return value.length <= 2000 && value.every(item => finiteTree(item, depth + 1));
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value);
    return entries.length <= 2000 && entries.every(
      ([key, item]) => key.length <= 200 && finiteTree(item, depth + 1),
    );
  }
  return false;
}

function resolveInside(root, candidate) {
  const resolved = path.resolve(root, candidate);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`path escapes repository root: ${candidate}`);
  }
  return resolved;
}

function readJson(root, candidate, report, kind) {
  try {
    const filename = resolveInside(root, candidate);
    const stat = fs.statSync(filename);
    if (!stat.isFile() || stat.size > MAX_JSON_BYTES) {
      throw new Error(`must be a file no larger than ${MAX_JSON_BYTES} bytes`);
    }
    const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
    if (!finiteTree(value)) throw new Error('contains a non-finite or oversized value tree');
    return value;
  } catch (error) {
    report.issue({
      code: 'JSON_READ_FAILED',
      field: kind,
      actual: error.message,
      expected: `bounded finite ${kind} JSON`,
      fix: `Restore the reviewed ${kind} JSON under the repository root.`,
    });
    return null;
  }
}

function isoDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return null;
  }
  const parsed = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value
    ? null
    : parsed;
}

function daysBetween(left, right) {
  return Math.floor((right.valueOf() - left.valueOf()) / 86_400_000);
}

function valueType(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  return typeof value;
}

function decodePointerToken(token) {
  if (/~(?:[^01]|$)/.test(token)) throw new Error('invalid RFC6901 escape');
  return token.replace(/~1/g, '/').replace(/~0/g, '~');
}

function pointer(value, rawPath) {
  if (rawPath === undefined || rawPath === '/') return value;
  if (typeof rawPath !== 'string' || !rawPath.startsWith('/')) {
    throw new Error('JSON pointer must start with /');
  }
  let current = value;
  for (const rawToken of rawPath.slice(1).split('/')) {
    const token = decodePointerToken(rawToken);
    if (
      current === null ||
      typeof current !== 'object' ||
      !Object.hasOwn(current, token)
    ) {
      throw new Error(`JSON pointer segment not found: ${token}`);
    }
    current = current[token];
  }
  return current;
}

function escapePointerToken(token) {
  return String(token).replace(/~/g, '~0').replace(/\//g, '~1');
}

function leafPointers(value, prefix = '/') {
  if (value === null || typeof value !== 'object') return [prefix];
  const entries = Array.isArray(value)
    ? value.map((item, index) => [String(index), item])
    : Object.entries(value);
  if (!entries.length) return [prefix];
  return entries.flatMap(([key, item]) => leafPointers(
    item,
    prefix === '/'
      ? `/${escapePointerToken(key)}`
      : `${prefix}/${escapePointerToken(key)}`,
  ));
}

function joinPointer(parent, child) {
  if (parent === '/') return child;
  if (child === '/') return parent;
  return `${parent}${child}`;
}

function fixtureBytes(root, attestation, report, context) {
  try {
    const fixture = attestation.fixture;
    if (
      !fixture ||
      typeof fixture.path !== 'string' ||
      typeof fixture.sha256 !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/.test(fixture.sha256)
    ) {
      throw new Error('fixture path/sha256 contract is missing');
    }
    const filename = resolveInside(root, fixture.path);
    const stat = fs.statSync(filename);
    if (!stat.isFile() || stat.size > MAX_FIXTURE_BYTES) {
      throw new Error(`fixture exceeds ${MAX_FIXTURE_BYTES} bytes or is not a file`);
    }
    const bytes = fs.readFileSync(filename);
    const actual = `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
    if (actual !== fixture.sha256) {
      throw new Error(`fixture fingerprint ${actual} != ${fixture.sha256}`);
    }
    return bytes;
  } catch (error) {
    report.issue({
      code: 'EVIDENCE_FINGERPRINT_FAILED',
      ...context,
      field: 'fixture.sha256',
      actual: error.message,
      expected: 'checked-in fixture bytes matching the source attestation fingerprint',
      fix: 'Review the official evidence, then update its fixture and SHA together.',
    });
    return null;
  }
}

function selectedExpected(attestation, mapping) {
  const expectedPath = mapping.expectedPath || '/';
  const value = pointer(attestation.expected.value, expectedPath);
  const unitRoot = attestation.expected.unit;
  const unit = unitRoot && typeof unitRoot === 'object'
    ? pointer(unitRoot, expectedPath)
    : unitRoot;
  return { value, unit };
}

function attestationCoversOutput(attestation, outputClaim, today, report, context) {
  const verified = isoDate(attestation.verifiedAt);
  const outputVerified = isoDate(outputClaim.verifiedAt);
  const effectiveFrom = isoDate(attestation.effectiveFrom);
  const outputFrom = isoDate(outputClaim.effectiveFrom);
  const effectiveTo = attestation.effectiveTo === undefined
    ? null
    : isoDate(attestation.effectiveTo);
  const reviewAfterDays = attestation.reviewAfterDays;
  if (
    !verified || !outputVerified || !effectiveFrom || !outputFrom ||
    (attestation.effectiveTo !== undefined && !effectiveTo) ||
    !Number.isInteger(reviewAfterDays) || reviewAfterDays < 1 || reviewAfterDays > 365
  ) {
    report.issue({
      code: 'EVIDENCE_DATE_INVALID',
      ...context,
      field: 'dates',
      actual: {
        verifiedAt: attestation.verifiedAt,
        effectiveFrom: attestation.effectiveFrom,
        effectiveTo: attestation.effectiveTo,
        reviewAfterDays,
      },
      expected: 'valid reviewed evidence dates and reviewAfterDays 1..365',
      fix: 'Correct the source attestation date contract; do not bypass stale evidence.',
    });
    return false;
  }
  const problems = [];
  if (verified < outputVerified) problems.push('evidence predates derived verification');
  if (verified > today) problems.push('evidence is future-dated');
  if (daysBetween(verified, today) > reviewAfterDays) problems.push('evidence is stale');
  if (effectiveFrom > outputFrom) problems.push('input becomes effective after derived output');
  if (effectiveTo && effectiveTo < outputFrom) problems.push('input expired before derived output');
  if (problems.length) {
    report.issue({
      code: 'EVIDENCE_WINDOW_MISMATCH',
      ...context,
      field: 'dates',
      actual: problems,
      expected: 'fresh evidence whose effective window covers the derived claim',
      fix: 'Align the derived effective date with all official inputs or select the correct official cohort.',
    });
    return false;
  }
  return true;
}

function claimDatesValid(claim, today, report, context) {
  const verified = isoDate(claim.verifiedAt);
  const effectiveFrom = isoDate(claim.effectiveFrom);
  const effectiveTo = claim.effectiveTo === undefined
    ? null
    : isoDate(claim.effectiveTo);
  const problems = [];
  if (!verified) problems.push('verifiedAt');
  if (!effectiveFrom) problems.push('effectiveFrom');
  if (claim.effectiveTo !== undefined && !effectiveTo) problems.push('effectiveTo');
  if (verified && verified > today) problems.push('future verifiedAt');
  if (verified && daysBetween(verified, today) > (claim.severity === 'critical' ? 45 : 90)) {
    problems.push('stale verifiedAt');
  }
  if (effectiveFrom && effectiveTo && effectiveFrom > effectiveTo) {
    problems.push('effectiveFrom > effectiveTo');
  }
  if (problems.length) {
    report.issue({
      code: 'CLAIM_DATE_INVALID',
      ...context,
      field: 'dates',
      actual: { problems, verifiedAt: claim.verifiedAt, effectiveFrom: claim.effectiveFrom, effectiveTo: claim.effectiveTo },
      expected: 'fresh ISO dates with a non-inverted effective range',
      fix: 'Re-verify the claim and correct its effective date window.',
    });
    return false;
  }
  return true;
}

function buildEvidenceIndexes(attestations) {
  const byId = new Map();
  const byClaim = new Map();
  for (const attestation of attestations.attestations || []) {
    if (attestation && typeof attestation.id === 'string') {
      if (!byId.has(attestation.id)) byId.set(attestation.id, []);
      byId.get(attestation.id).push(attestation);
    }
    for (const mapping of attestation?.claims || []) {
      if (!mapping || typeof mapping.claimId !== 'string') continue;
      if (!byClaim.has(mapping.claimId)) byClaim.set(mapping.claimId, []);
      byClaim.get(mapping.claimId).push({ attestation, mapping });
    }
  }
  return { byId, byClaim };
}

function validateOfficialEvidence({
  root,
  claim,
  outputClaim,
  evidenceIndexes,
  today,
  report,
  edition,
  target,
}) {
  const context = {
    claim: outputClaim.id,
    edition,
    target,
  };
  const matches = evidenceIndexes.byClaim.get(claim.id) || [];
  if (matches.length !== 1) {
    report.issue({
      code: 'INPUT_EVIDENCE_CARDINALITY',
      ...context,
      field: `inputClaimIds.${claim.id}`,
      actual: matches.length,
      expected: 1,
      fix: 'Map each official input claim to exactly one strict source attestation.',
    });
    return false;
  }
  const { attestation, mapping } = matches[0];
  let valid = true;
  if (attestation.sourceUrl !== claim.sourceUrl) {
    report.issue({
      code: 'INPUT_SOURCE_MISMATCH',
      ...context,
      field: `inputClaimIds.${claim.id}.sourceUrl`,
      actual: attestation.sourceUrl,
      expected: claim.sourceUrl,
      fix: 'Bind the input claim to its exact official citation source.',
    });
    valid = false;
  }
  try {
    const selected = selectedExpected(attestation, mapping);
    if (!deepEqual(selected.value, claim.value) || !deepEqual(selected.unit, claim.unit)) {
      report.issue({
        code: 'INPUT_VALUE_MISMATCH',
        ...context,
        field: `inputClaimIds.${claim.id}.expected`,
        actual: selected,
        expected: { value: claim.value, unit: claim.unit },
        fix: 'Restore exact source-attestation value and unit parity for the official input.',
      });
      valid = false;
    }
  } catch (error) {
    report.issue({
      code: 'INPUT_EXPECTED_PATH_FAILED',
      ...context,
      field: `inputClaimIds.${claim.id}.expectedPath`,
      actual: error.message,
      expected: 'an existing scalar expected value/unit path',
      fix: 'Correct the source-attestation expectedPath for this input claim.',
    });
    valid = false;
  }
  if (!attestationCoversOutput(attestation, outputClaim, today, report, context)) {
    valid = false;
  }
  if (!fixtureBytes(root, attestation, report, context)) valid = false;
  return valid;
}

function validateBoundaryEvidence({
  root,
  boundaryTarget,
  outputClaim,
  attestations,
  today,
  report,
  edition,
  target,
  reviewedPath = '/',
  attestationIds = null,
  expectedUnit = null,
}) {
  const context = { claim: outputClaim.id, edition, target };
  let reviewedRoot;
  try {
    reviewedRoot = pointer(boundaryTarget.reviewed, reviewedPath);
  } catch (error) {
    report.issue({
      code: 'BOUNDARY_EVIDENCE_PATH_INVALID',
      ...context,
      field: `boundary.${boundaryTarget.id}${reviewedPath}`,
      actual: error.message,
      expected: 'an existing reviewed boundary subtree',
      fix: 'Restore the code-reviewed boundary target and subtree.',
    });
    return false;
  }
  const expectedLeaves = new Set(leafPointers(reviewedRoot).map(
    leaf => joinPointer(reviewedPath, leaf),
  ));
  const covered = new Map();
  const allowedIds = attestationIds === null ? null : new Set(attestationIds);
  let valid = true;
  if (allowedIds) {
    for (const attestationId of allowedIds) {
      const matches = (attestations.attestations || []).filter(
        attestation => attestation.id === attestationId,
      );
      if (matches.length !== 1) {
        report.issue({
          code: 'BOUNDARY_ATTESTATION_CARDINALITY',
          ...context,
          field: `boundaryAttestationIds.${attestationId}`,
          actual: matches.length,
          expected: 1,
          fix: 'Restore each code-reviewed boundary source attestation exactly once.',
        });
        valid = false;
      }
    }
  }
  for (const attestation of attestations.attestations || []) {
    if (allowedIds && !allowedIds.has(attestation.id)) continue;
    const mappings = (attestation.targets || []).filter(
      mapping => mapping.targetId === boundaryTarget.id,
    );
    if (allowedIds && mappings.length === 0) {
      report.issue({
        code: 'BOUNDARY_ATTESTATION_UNMAPPED',
        ...context,
        field: `boundaryAttestationIds.${attestation.id}`,
        actual: [],
        expected: `${boundaryTarget.id}${reviewedPath}`,
        fix: 'Map the reviewed official component to its exact boundary subtree.',
      });
      valid = false;
    }
    for (const mapping of mappings) {
      try {
        const mappedReviewedPath = mapping.reviewedPath || '/';
        if (
          reviewedPath !== '/' &&
          mappedReviewedPath !== reviewedPath &&
          !mappedReviewedPath.startsWith(`${reviewedPath}/`)
        ) {
          throw new Error(`mapping ${mappedReviewedPath} escapes reviewed subtree ${reviewedPath}`);
        }
        const expectedPath = mapping.expectedPath || '/';
        const reviewedValue = pointer(boundaryTarget.reviewed, mappedReviewedPath);
        const sourceValue = pointer(attestation.expected.value, expectedPath);
        if (!deepEqual(reviewedValue, sourceValue)) {
          throw new Error(`expected value does not equal reviewed ${mappedReviewedPath}`);
        }
        if (expectedUnit !== null) {
          const sourceUnit = attestation.expected.unit &&
            typeof attestation.expected.unit === 'object'
            ? pointer(attestation.expected.unit, expectedPath)
            : attestation.expected.unit;
          if (!deepEqual(sourceUnit, expectedUnit)) {
            throw new Error(`source unit ${display(sourceUnit)} != ${display(expectedUnit)}`);
          }
        }
        const relativeLeaves = leafPointers(reviewedValue);
        for (const relative of relativeLeaves) {
          const leaf = joinPointer(mappedReviewedPath, relative);
          if (!covered.has(leaf)) covered.set(leaf, []);
          covered.get(leaf).push(attestation.id);
        }
        if (!attestationCoversOutput(attestation, outputClaim, today, report, context)) {
          valid = false;
        }
        if (!fixtureBytes(root, attestation, report, context)) valid = false;
      } catch (error) {
        report.issue({
          code: 'BOUNDARY_EVIDENCE_MISMATCH',
          ...context,
          field: `boundary.${boundaryTarget.id}`,
          actual: `${attestation.id}: ${error.message}`,
          expected: 'source-attested reviewed target subtree parity',
          fix: 'Correct the source target mapping; do not execute a partially attested calculator.',
        });
        valid = false;
      }
    }
  }
  for (const leaf of expectedLeaves) {
    const matches = covered.get(leaf) || [];
    if (matches.length !== 1) {
      report.issue({
        code: 'BOUNDARY_EVIDENCE_CARDINALITY',
        ...context,
        field: `boundary.${boundaryTarget.id}${leaf}`,
        actual: matches,
        expected: 'exactly one source attestation',
        fix: 'Cover every reviewed calculator input leaf once without parent/child overlap.',
      });
      valid = false;
    }
  }
  for (const leaf of covered.keys()) {
    if (!expectedLeaves.has(leaf)) {
      report.issue({
        code: 'BOUNDARY_EVIDENCE_ORPHAN',
        ...context,
        field: `boundary.${boundaryTarget.id}${leaf}`,
        actual: covered.get(leaf),
        expected: 'a current reviewed boundary leaf',
        fix: 'Remove the orphan target mapping or restore the reviewed target leaf.',
      });
      valid = false;
    }
  }
  return valid;
}

function normalizeHtmlText(value) {
  return value
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function fixedTagTexts(html, tag) {
  const pattern = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'gi');
  return [...html.matchAll(pattern)].map(match => normalizeHtmlText(match[1]));
}

function executeUncappedEvidence(bytes, expectedMatches) {
  const html = bytes.toString('utf8');
  const headings = fixedTagTexts(html, 'h1');
  const labels = fixedTagTexts(html, 'h4');
  const reviewedLabels = [
    'Length of stay',
    'Cost',
    'Processing time',
    'Age range',
  ];
  if (
    headings.filter(value => value === 'Japan Working Holiday Visa').length !== 1 ||
    labels.length !== reviewedLabels.length ||
    !reviewedLabels.every((value, index) => labels[index] === value)
  ) {
    throw new Error('Japan WHV hero is not the exact exhaustive four-label cohort');
  }
  const unexpected = labels.filter(value => !reviewedLabels.includes(value));
  if (unexpected.length !== expectedMatches) {
    throw new Error(`unexpected availability fields=${unexpected.length}`);
  }
  return 'uncapped';
}

function parseAud(value) {
  if (typeof value !== 'string' || !/^AUD(?:0|[1-9][0-9]{0,2}(?:,[0-9]{3})*)\.[0-9]{2}$/.test(value)) {
    throw new Error(`invalid exact AUD amount ${display(value)}`);
  }
  const result = Number(value.slice(3).replace(/,/g, ''));
  if (!Number.isFinite(result)) throw new Error('non-finite AUD amount');
  return result;
}

function executePartnerZeroEvidence(bytes, inputValue, expectedMatches) {
  const document = JSON.parse(bytes.toString('utf8'));
  const rows = pointer(document, '/d/data');
  if (!Array.isArray(rows) || rows.length > 5000) {
    throw new Error('Home Affairs price records are missing or oversized');
  }
  const records = rows.filter(row => row?.visaSubclassCode === '801');
  const active = records.filter(
    row => row.visaSubclassText === 'Partner visa (subclass 820/801)',
  );
  const ceased = records.filter(
    row => row.visaSubclassText === 'Partner visa (subclass 820/801) - Ceased Prospective Marriage visa',
  );
  const standalone = records.filter(
    row => row.visaSubclassText === 'Partner visa (subclass 801)',
  );
  if (records.length !== 2 || active.length !== 1 || ceased.length !== 1) {
    throw new Error('801 records are not the exact combined + ceased cohort');
  }
  if (standalone.length !== expectedMatches) {
    throw new Error(`standalone 801 records=${standalone.length}`);
  }
  if (parseAud(active[0].basePrice) !== inputValue) {
    throw new Error('combined 820/801 amount does not equal its official input claim');
  }
  return 0;
}

function mappingSchema(mapping, report) {
  const issueStart = report.issues.length;
  const context = {
    claim: mapping?.claimId || '<mapping>',
    edition: mapping?.edition || '<unknown>',
    target: mapping?.target || '<unknown>',
  };
  const target = TARGETS[mapping?.target];
  const expectedFields = [
    ...BASE_MAPPING_FIELDS,
    ...(target?.negativeAttestationId ? ['negativeEvidence'] : []),
    ...(target?.boundaryAttestationIds ? ['boundaryEvidence'] : []),
  ];
  if (!exactKeys(mapping, expectedFields)) {
    report.issue({
      code: 'MAPPING_SCHEMA_INVALID',
      ...context,
      field: 'mapping',
      actual: mapping,
      expected: expectedFields,
      fix: 'Use only the strict lineage mapping fields; expressions and selectors are forbidden.',
    });
    return null;
  }
  if (!target || !TRANSFORMS.has(mapping.transform)) {
    report.issue({
      code: 'TARGET_UNSUPPORTED',
      ...context,
      field: 'target/transform',
      actual: { target: mapping.target, transform: mapping.transform },
      expected: Object.keys(TARGETS),
      fix: 'Use one code-reviewed lineage target and its fixed transform.',
    });
    return null;
  }
  if (
    mapping.claimId !== target.claimId ||
    mapping.edition !== target.edition ||
    mapping.page !== target.page ||
    mapping.transform !== target.transform
  ) {
    report.issue({
      code: 'TARGET_CONTRACT_MISMATCH',
      ...context,
      field: 'claimId/edition/page/transform',
      actual: {
        claimId: mapping.claimId,
        edition: mapping.edition,
        page: mapping.page,
        transform: mapping.transform,
      },
      expected: {
        claimId: target.claimId,
        edition: target.edition,
        page: target.page,
        transform: target.transform,
      },
      fix: 'Restore the code-reviewed edition/page/transform binding.',
    });
  }
  if (
    !Array.isArray(mapping.inputClaimIds) ||
    new Set(mapping.inputClaimIds).size !== mapping.inputClaimIds.length ||
    !deepEqual([...mapping.inputClaimIds].sort(), [...target.inputClaimIds].sort())
  ) {
    report.issue({
      code: 'INPUT_SET_MISMATCH',
      ...context,
      field: 'inputClaimIds',
      actual: mapping.inputClaimIds,
      expected: target.inputClaimIds,
      fix: 'Use every reviewed official input claim exactly once.',
    });
  }
  if (
    !exactKeys(mapping.expected, OUTPUT_FIELDS) ||
    !['number', 'string'].includes(mapping.expected.type) ||
    valueType(mapping.expected.value) !== mapping.expected.type ||
    typeof mapping.expected.unit !== 'string' ||
    !mapping.expected.unit ||
    (typeof mapping.expected.value === 'number' && !Number.isFinite(mapping.expected.value))
  ) {
    report.issue({
      code: 'EXPECTED_SCHEMA_INVALID',
      ...context,
      field: 'expected',
      actual: mapping.expected,
      expected: '{type:number|string, unit:nonempty string, value:matching finite scalar}',
      fix: 'Restore the exact finite output type, unit, and value.',
    });
  }
  if (mapping.evidenceTier !== 'derived-executed') {
    report.issue({
      code: 'EVIDENCE_TIER_INVALID',
      ...context,
      field: 'evidenceTier',
      actual: mapping.evidenceTier,
      expected: 'derived-executed',
      fix: 'Label executed derivations honestly; do not present them as direct official statements.',
    });
  }
  if (target.negativeAttestationId) {
    if (!exactKeys(mapping.negativeEvidence, ['attestationId', 'mode', 'expectedMatches']) ||
      mapping.negativeEvidence.attestationId !== target.negativeAttestationId ||
      mapping.negativeEvidence.mode !== 'exact-cardinality' ||
      mapping.negativeEvidence.expectedMatches !== 0) {
      report.issue({
        code: 'NEGATIVE_EVIDENCE_SCHEMA_INVALID',
        ...context,
        field: 'negativeEvidence',
        actual: mapping.negativeEvidence,
        expected: {
          attestationId: target.negativeAttestationId,
          mode: 'exact-cardinality',
          expectedMatches: 0,
        },
        fix: 'Use the reviewed exhaustive negative-evidence cardinality contract.',
      });
    }
  }
  if (target.boundaryAttestationIds) {
    const expected = {
      targetId: target.boundaryTargetId,
      reviewedPath: target.boundaryReviewedPath,
      attestationIds: [...target.boundaryAttestationIds],
    };
    if (!exactKeys(mapping.boundaryEvidence, Object.keys(expected)) ||
      !deepEqual(mapping.boundaryEvidence, expected)) {
      report.issue({
        code: 'BOUNDARY_INPUT_SCHEMA_INVALID',
        ...context,
        field: 'boundaryEvidence',
        actual: mapping.boundaryEvidence,
        expected,
        fix: 'Use the exact source-attested reviewed boundary components; do not invent synthetic input claims.',
      });
    }
  }
  return { mapping, target, valid: report.issues.length === issueStart };
}

function topologicalMappings(entries) {
  const byClaim = new Map(entries.map(entry => [entry.mapping.claimId, entry]));
  const ordered = [];
  const done = new Set();
  const active = new Set();
  const visit = entry => {
    const claimId = entry.mapping.claimId;
    if (done.has(claimId) || active.has(claimId)) return;
    active.add(claimId);
    for (const inputId of entry.mapping.inputClaimIds) {
      const dependency = byClaim.get(inputId);
      if (dependency) visit(dependency);
    }
    active.delete(claimId);
    done.add(claimId);
    ordered.push(entry);
  };
  entries.forEach(visit);
  return ordered;
}

function serializeBracketPairs(value, { requireFirstZero = false } = {}) {
  if (!Array.isArray(value) || value.length !== 5) {
    throw new Error('reviewed brackets must contain exactly five pairs');
  }
  let previousCap = -Infinity;
  return value.map((pair, index) => {
    if (!Array.isArray(pair) || pair.length !== 2) {
      throw new Error(`reviewed bracket ${index} is not [cap,rate]`);
    }
    const [cap, rate] = pair;
    if (!Number.isFinite(rate) || rate < 0 || rate > 1) {
      throw new Error(`reviewed bracket ${index} has an invalid finite rate`);
    }
    if (index === value.length - 1) {
      if (cap !== null) throw new Error('reviewed terminal cap must be null');
    } else if (!Number.isFinite(cap) || cap <= previousCap) {
      throw new Error(`reviewed bracket ${index} cap is not strictly increasing`);
    }
    if (requireFirstZero && index === 0 && rate !== 0) {
      throw new Error('resident tax-free band must have an exact zero rate');
    }
    if (cap !== null) previousCap = cap;
    const rawRate = String(rate);
    const rateText = rate === 0
      ? '0'
      : (rawRate.split('.')[1]?.length === 1 ? rate.toFixed(2) : rawRate);
    return `${cap === null ? 'above' : cap}@${rateText}`;
  }).join(';');
}

function boundaryBackedClaimMatches(claim, boundaryTarget) {
  if (!claim || !boundaryTarget) return false;
  if (
    ['nz-ko-income-tax-brackets-2026', 'nz-ja-income-tax-brackets-2026']
      .includes(claim.id)
  ) {
    return claim.unit === 'NZD/rate' &&
      claim.value === serializeBracketPairs(boundaryTarget.reviewed.brackets);
  }
  if (claim.id === 'au-ko-whm-tax-rate') {
    return claim.unit === 'percent' &&
      deepEqual(claim.value, boundaryTarget.reviewed.whm.rate * 100);
  }
  if (claim.id === 'au-ko-tax-lito-2026') {
    const lito = boundaryTarget.reviewed.resident.lito;
    const serialized = (
      `${lito.maxOffset};${lito.fullTo};` +
      `${lito.taper1To}@${lito.taper1Rate};` +
      `${lito.cutOut}@${lito.taper2Rate}`
    );
    return claim.unit === 'AUD/rate' && claim.value === serialized;
  }
  return false;
}

function detectCycles(mappings, report) {
  const byClaim = new Map();
  for (const mapping of mappings) {
    if (typeof mapping?.claimId === 'string') byClaim.set(mapping.claimId, mapping);
  }
  const state = new Map();
  const stack = [];
  const visit = claimId => {
    if (state.get(claimId) === 2) return;
    if (state.get(claimId) === 1) {
      const start = stack.indexOf(claimId);
      const cycle = [...stack.slice(start), claimId];
      report.issue({
        code: 'LINEAGE_CYCLE',
        claim: claimId,
        target: byClaim.get(claimId)?.target || '<unknown>',
        field: 'inputClaimIds',
        actual: cycle,
        expected: 'an acyclic official-input DAG',
        fix: 'Remove the derived dependency cycle and anchor the chain in official evidence.',
      });
      return;
    }
    state.set(claimId, 1);
    stack.push(claimId);
    for (const input of byClaim.get(claimId)?.inputClaimIds || []) {
      if (byClaim.has(input)) visit(input);
    }
    stack.pop();
    state.set(claimId, 2);
  };
  for (const claimId of byClaim.keys()) visit(claimId);
}

function validateClaimAndMapping(mapping, target, claim, today, report) {
  const context = { claim: mapping.claimId, edition: mapping.edition, target: mapping.target };
  let valid = true;
  const edition = EDITIONS[mapping.edition];
  if (!claim) {
    report.issue({
      code: 'UNKNOWN_CLAIM',
      ...context,
      field: 'claimId',
      actual: mapping.claimId,
      expected: 'a current derived critical claim',
      fix: 'Remove the orphan mapping or restore the exact claim ID.',
    });
    return false;
  }
  if (
    claim.status !== 'derived' ||
    claim.severity !== 'critical' ||
    claim.country !== edition.country ||
    claim.locale !== edition.locale ||
    !Array.isArray(claim.pages) ||
    claim.pages.length !== 1 ||
    claim.pages[0] !== mapping.page
  ) {
    report.issue({
      code: 'CLAIM_EDITION_MISMATCH',
      ...context,
      field: 'status/severity/country/locale/pages',
      actual: {
        status: claim.status,
        severity: claim.severity,
        country: claim.country,
        locale: claim.locale,
        pages: claim.pages,
      },
      expected: {
        status: 'derived', severity: 'critical', ...edition,
      },
      fix: 'Bind the derived critical claim to its exact edition and page.',
    });
    valid = false;
  }
  if (
    mapping.expected.type !== valueType(claim.value) ||
    mapping.expected.unit !== claim.unit ||
    !deepEqual(mapping.expected.value, claim.value)
  ) {
    report.issue({
      code: 'OUTPUT_CLAIM_MISMATCH',
      ...context,
      field: 'expected',
      actual: mapping.expected,
      expected: { type: valueType(claim.value), unit: claim.unit, value: claim.value },
      fix: 'Update the reviewed derivation or correct the claim; never mask claim drift.',
    });
    valid = false;
  }
  const claimDateFields = claim.effectiveTo === undefined
    ? ['verifiedAt', 'effectiveFrom']
    : ['verifiedAt', 'effectiveFrom', 'effectiveTo'];
  if (!exactKeys(mapping.dates, claimDateFields) || claimDateFields.some(
    field => mapping.dates[field] !== claim[field],
  )) {
    report.issue({
      code: 'OUTPUT_DATE_MISMATCH',
      ...context,
      field: 'dates',
      actual: mapping.dates,
      expected: Object.fromEntries(claimDateFields.map(field => [field, claim[field]])),
      fix: 'Keep lineage verified/effective dates exactly aligned with the output claim.',
    });
    valid = false;
  }
  if (!claimDatesValid(claim, today, report, context)) valid = false;
  return valid;
}

function validateParity(claims, report) {
  const left = claims.get('nz-ko-netpay-72800');
  const right = claims.get('nz-ja-netpay-72800');
  if (!left || !right) return;
  const actual = {
    value: [left.value, right.value],
    unit: [left.unit, right.unit],
    effectiveFrom: [left.effectiveFrom, right.effectiveFrom],
  };
  if (
    !deepEqual(left.value, right.value) ||
    left.unit !== right.unit ||
    left.effectiveFrom !== right.effectiveFrom
  ) {
    report.issue({
      code: 'NZ_JA_PARITY_MISMATCH',
      claim: 'nz-ko-netpay-72800:nz-ja-netpay-72800',
      edition: 'nz/ja',
      target: 'netpay-parity',
      field: 'value/unit/effectiveFrom',
      actual,
      expected: 'identical NZ/JA calculator claim parity',
      fix: 'Restore the same reviewed calculator inputs and output in both editions.',
    });
  }
}

function validateAudit(claimsData, actual, report) {
  const declared = claimsData.audit?.claimLineage;
  if (declared === undefined) return;
  const keys = Object.keys(actual);
  if (!exactKeys(declared, keys) || !deepEqual(declared, actual)) {
    report.issue({
      code: 'PUBLIC_AUDIT_MISMATCH',
      field: 'claims.audit.claimLineage',
      actual: declared,
      expected: actual,
      fix: 'Publish the exact deterministic lineage audit after the verifier is green.',
    });
  }
}

export function verifyClaimLineage({
  root,
  claimsPath,
  attestationsPath,
  bindingsPath,
  boundariesPath,
  lineagePath,
  today: todayText,
  requireCriticalCoverage = false,
}) {
  const report = new LineageReport();
  const today = isoDate(todayText);
  if (!today) {
    report.issue({
      code: 'TODAY_INVALID',
      field: 'today',
      actual: todayText,
      expected: 'an ISO calendar date',
      fix: 'Pass --today YYYY-MM-DD.',
    });
    return report;
  }
  const claimsData = readJson(root, claimsPath, report, 'claims');
  const attestations = readJson(root, attestationsPath, report, 'attestations');
  const boundaries = readJson(root, boundariesPath, report, 'boundaries');
  const lineage = readJson(root, lineagePath, report, 'lineage');
  if (!claimsData || !attestations || !boundaries || !lineage) return report;
  if (!Array.isArray(claimsData.claims) || !Array.isArray(attestations.attestations)) {
    report.issue({
      code: 'REGISTRY_ROOT_INVALID',
      field: 'claims/attestations',
      actual: { claims: claimsData.claims, attestations: attestations.attestations },
      expected: 'claims[] and attestations[]',
      fix: 'Use the production claims and source-attestation root schemas.',
    });
    return report;
  }
  if (!exactKeys(lineage, ['schemaVersion', 'derivedCriticalScope', 'mappings']) ||
    lineage.schemaVersion !== SCHEMA_VERSION ||
    !Array.isArray(lineage.derivedCriticalScope) ||
    !Array.isArray(lineage.mappings)) {
    report.issue({
      code: 'LINEAGE_ROOT_INVALID',
      field: 'lineage',
      actual: lineage,
      expected: '{schemaVersion:1, derivedCriticalScope:[], mappings:[]}',
      fix: 'Restore the strict v1 claim-lineage root.',
    });
    return report;
  }
  const claims = new Map();
  for (const claim of claimsData.claims) {
    if (typeof claim?.id !== 'string' || claims.has(claim.id)) {
      report.issue({
        code: 'CLAIM_ID_INVALID',
        claim: claim?.id || '<missing>',
        field: 'id',
        actual: claim?.id,
        expected: 'a unique nonempty claim ID',
        fix: 'Restore unique claim IDs before lineage validation.',
      });
      continue;
    }
    claims.set(claim.id, claim);
  }
  const derivedCritical = [...claims.values()]
    .filter(claim => claim.status === 'derived' && claim.severity === 'critical')
    .map(claim => claim.id)
    .sort();
  report.audit.derivedCriticalCount = derivedCritical.length;
  if (
    new Set(lineage.derivedCriticalScope).size !== lineage.derivedCriticalScope.length ||
    !deepEqual([...lineage.derivedCriticalScope].sort(), derivedCritical)
  ) {
    report.issue({
      code: 'DERIVED_SCOPE_MISMATCH',
      field: 'derivedCriticalScope',
      actual: lineage.derivedCriticalScope,
      expected: derivedCritical,
      fix: 'List every current derived critical claim exactly once; do not guess the count.',
    });
  }
  detectCycles(lineage.mappings, report);
  const validatedMappings = [];
  const seenClaims = new Set();
  const seenTargets = new Set();
  for (const mapping of lineage.mappings) {
    const validated = mappingSchema(mapping, report);
    if (!validated) continue;
    let duplicate = false;
    if (seenClaims.has(mapping.claimId)) {
      report.issue({
        code: 'DUPLICATE_MAPPING',
        claim: mapping.claimId,
        edition: mapping.edition,
        target: mapping.target,
        field: 'claimId',
        actual: 2,
        expected: 1,
        fix: 'Keep exactly one lineage mapping for each derived critical claim.',
      });
      duplicate = true;
    }
    if (seenTargets.has(mapping.target)) {
      report.issue({
        code: 'DUPLICATE_TARGET',
        claim: mapping.claimId,
        edition: mapping.edition,
        target: mapping.target,
        field: 'target',
        actual: 2,
        expected: 1,
        fix: 'Use every reviewed execution target exactly once.',
      });
      duplicate = true;
    }
    seenClaims.add(mapping.claimId);
    seenTargets.add(mapping.target);
    if (!duplicate) validatedMappings.push(validated);
  }
  for (const claimId of derivedCritical) {
    if (!seenClaims.has(claimId)) {
      report.issue({
        code: 'MISSING_MAPPING',
        claim: claimId,
        field: 'claimId',
        actual: 'unmapped',
        expected: 'exactly one lineage mapping',
        fix: 'Add the reviewed derived-executed mapping for this critical claim.',
      });
    }
  }
  report.audit.mappedCount = seenClaims.size;
  const uniqueInputs = new Set(
    lineage.mappings.flatMap(mapping => Array.isArray(mapping?.inputClaimIds)
      ? mapping.inputClaimIds
      : []),
  );
  report.audit.inputClaimCount = uniqueInputs.size;
  validateParity(claims, report);

  const evidenceIndexes = buildEvidenceIndexes(attestations);
  const boundaryTargets = new Map((boundaries.targets || []).map(
    target => [target.id, target],
  ));
  const boundaryReport = verifyBoundaryExecution({
    root,
    claimsPath,
    bindingsPath,
    manifestPath: boundariesPath,
  });
  const boundaryReady = boundaryReport.issues.length === 0;
  for (const issue of boundaryReport.issues) {
    report.issue({
      code: 'BOUNDARY_GATE_FAILED',
      claim: issue.claim,
      edition: issue.edition,
      target: issue.boundary,
      field: issue.probe,
      actual: issue.actual,
      expected: issue.expected,
      fix: issue.fix,
    });
  }

  const executedClaims = new Set();
  for (const { mapping, target, valid } of topologicalMappings(validatedMappings)) {
    if (!valid) continue;
    const issueStart = report.issues.length;
    const outputClaim = claims.get(mapping.claimId);
    validateClaimAndMapping(mapping, target, outputClaim, today, report);
    if (!outputClaim) continue;
    let boundaryTarget = target.boundaryTargetId
      ? boundaryTargets.get(target.boundaryTargetId)
      : null;
    const inputs = [];
    for (const inputId of mapping.inputClaimIds) {
      const input = claims.get(inputId);
      if (!input) {
        report.issue({
          code: 'UNKNOWN_INPUT_CLAIM',
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
          field: `inputClaimIds.${inputId}`,
          actual: 'missing',
          expected: 'an official claim or executed derived dependency',
          fix: 'Add the official component claim or correct the input ID.',
        });
        continue;
      }
      if (input.country !== outputClaim.country || !input.pages?.includes(mapping.page)) {
        report.issue({
          code: 'CROSS_EDITION_INPUT',
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
          field: `inputClaimIds.${inputId}`,
          actual: { country: input.country, pages: input.pages },
          expected: { country: outputClaim.country, page: mapping.page },
          fix: 'Use inputs from the same country edition as the derived output.',
        });
      }
      claimDatesValid(input, today, report, {
        claim: mapping.claimId,
        edition: mapping.edition,
        target: mapping.target,
      });
      const inputFrom = isoDate(input.effectiveFrom);
      const inputTo = input.effectiveTo === undefined ? null : isoDate(input.effectiveTo);
      const outputFrom = isoDate(outputClaim.effectiveFrom);
      if (inputFrom && outputFrom && (inputFrom > outputFrom || (inputTo && inputTo < outputFrom))) {
        report.issue({
          code: 'INPUT_EFFECTIVE_WINDOW_MISMATCH',
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
          field: `inputClaimIds.${inputId}.effectiveFrom/effectiveTo`,
          actual: { effectiveFrom: input.effectiveFrom, effectiveTo: input.effectiveTo },
          expected: `window covering ${outputClaim.effectiveFrom}`,
          fix: 'Align the derived effective date with the official input cohort.',
        });
      }
      if (input.status === 'official') {
        const directMatches = evidenceIndexes.byClaim.get(input.id) || [];
        if (
          directMatches.length === 0 &&
          boundaryBackedClaimMatches(input, boundaryTarget)
        ) {
          // Full leaf source coverage and runtime parity are checked below.
        } else {
          validateOfficialEvidence({
            root,
            claim: input,
            outputClaim,
            evidenceIndexes,
            today,
            report,
            edition: mapping.edition,
            target: mapping.target,
          });
        }
      } else if (input.status === 'derived') {
        if (!executedClaims.has(input.id)) {
          report.issue({
            code: 'DERIVED_INPUT_NOT_EXECUTED',
            claim: mapping.claimId,
            edition: mapping.edition,
            target: mapping.target,
            field: `inputClaimIds.${inputId}`,
            actual: 'not executed',
            expected: 'an earlier successful lineage dependency',
            fix: 'Order the acyclic DAG from official inputs to derived outputs.',
          });
        }
      } else {
        report.issue({
          code: 'INPUT_STATUS_INVALID',
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
          field: `inputClaimIds.${inputId}.status`,
          actual: input.status,
          expected: 'official or derived',
          fix: 'Use only official or already executed derived inputs.',
        });
      }
      inputs.push(input);
    }
    if (target.boundaryTargetId) {
      if (!boundaryTarget) {
        report.issue({
          code: 'BOUNDARY_TARGET_MISSING',
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
          field: 'boundaryTargetId',
          actual: target.boundaryTargetId,
          expected: 'a reviewed v4 boundary target',
          fix: 'Restore the required boundary target before executing lineage.',
        });
      } else {
        validateBoundaryEvidence({
          root,
          boundaryTarget,
          outputClaim,
          attestations,
          today,
          report,
          edition: mapping.edition,
          target: mapping.target,
          reviewedPath: target.boundaryReviewedPath || '/',
          attestationIds: target.boundaryAttestationIds || null,
          expectedUnit: target.boundaryUnit || null,
        });
      }
      if (!boundaryReady) {
        report.issue({
          code: 'BOUNDARY_EXECUTION_NOT_GREEN',
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
          field: 'boundary',
          actual: `${boundaryReport.issues.length} v4 issue(s)`,
          expected: 'green boundary execution before lineage sampling',
          fix: 'Fix the v4 runtime/boundary gate; a fixed sample cannot bypass it.',
        });
      }
    }
    if (report.issues.length !== issueStart) continue;
    try {
      let actual;
      if (mapping.transform === 'sum') {
        if (inputs.some(input => typeof input.value !== 'number' || !Number.isFinite(input.value))) {
          throw new Error('sum inputs must be finite numbers');
        }
        if (inputs.some(input => input.unit !== mapping.expected.unit)) {
          throw new Error('sum input units do not equal the output unit');
        }
        actual = inputs.reduce((total, input) => total + input.value, 0);
      } else if (mapping.transform === 'calculator-execution') {
        const sample = executeReviewedLineageSample({
          root,
          target: boundaryTarget,
          gross: target.gross,
          mode: target.mode || null,
        });
        if (!deepEqual(sample.actual, sample.expected)) {
          throw new Error(`runtime ${sample.actual} != independent boundary formula ${sample.expected}`);
        }
        actual = sample.actual;
      } else if (mapping.transform === 'crs-fixed-profile') {
        const sample = executeReviewedCrsProfile({
          root,
          page: mapping.page,
          profile: target.profile,
        });
        const inputMap = new Map(inputs.map(input => [input.id, input]));
        let independent = 0;
        for (const [component, contract] of Object.entries(target.componentClaims)) {
          const input = inputMap.get(contract.claimId);
          if (!input || input.unit !== contract.unit) {
            throw new Error(
              `CRS ${component} input unit ${input?.unit} != ${contract.unit}`,
            );
          }
          if (typeof input.value !== 'number' || !Number.isFinite(input.value)) {
            throw new Error(`CRS ${component} input must be a finite number`);
          }
          const expectedComponent = input.value * contract.multiplier;
          if (!deepEqual(sample.components[component], expectedComponent)) {
            throw new Error(
              `CRS ${component} runtime ${sample.components[component]} != ` +
              `official input ${input.value} × ${contract.multiplier} = ${expectedComponent}`,
            );
          }
          independent += expectedComponent;
        }
        if (sample.actual !== independent) {
          throw new Error(
            `CRS runtime ${sample.actual} != official transformed component sum ${independent}`,
          );
        }
        actual = sample.actual;
      } else if (mapping.transform === 'boundary-serialization') {
        actual = serializeBracketPairs(
          pointer(boundaryTarget.reviewed, target.boundaryReviewedPath),
          { requireFirstZero: true },
        );
      } else {
        const idMatches = evidenceIndexes.byId.get(mapping.negativeEvidence.attestationId) || [];
        if (idMatches.length !== 1) {
          throw new Error(`negative evidence attestation cardinality ${idMatches.length}`);
        }
        const attestation = idMatches[0];
        if (!attestationCoversOutput(attestation, outputClaim, today, report, {
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
        })) {
          throw new Error('negative evidence date window is invalid');
        }
        const bytes = fixtureBytes(root, attestation, report, {
          claim: mapping.claimId,
          edition: mapping.edition,
          target: mapping.target,
        });
        if (!bytes) throw new Error('negative evidence fixture is invalid');
        if (
          mapping.transform === 'constant-absence-zero' &&
          inputs[0]?.unit !== mapping.expected.unit
        ) {
          throw new Error('negative fee cohort input/output units do not match');
        }
        actual = mapping.transform === 'uncapped-availability'
          ? executeUncappedEvidence(bytes, mapping.negativeEvidence.expectedMatches)
          : executePartnerZeroEvidence(
            bytes,
            inputs[0].value,
            mapping.negativeEvidence.expectedMatches,
          );
      }
      if (!deepEqual(actual, mapping.expected.value)) {
        throw new Error(`executed value ${display(actual)} != expected ${display(mapping.expected.value)}`);
      }
      report.audit.executedCount += 1;
      executedClaims.add(mapping.claimId);
    } catch (error) {
      report.issue({
        code: 'LINEAGE_EXECUTION_FAILED',
        claim: mapping.claimId,
        edition: mapping.edition,
        target: mapping.target,
        field: 'execution',
        actual: error.message,
        expected: mapping.expected,
        fix: 'Review the official inputs and production execution; never hardcode the sample output.',
      });
    }
  }

  const directCandidates = new Set();
  const validDirect = new Set();
  for (const claim of claims.values()) {
    if (claim.status !== 'official' || claim.severity !== 'critical') continue;
    const matches = evidenceIndexes.byClaim.get(claim.id) || [];
    if (matches.length === 1) directCandidates.add(claim.id);
    if (requireCriticalCoverage) {
      const before = report.issues.length;
      validateOfficialEvidence({
        root,
        claim,
        outputClaim: claim,
        evidenceIndexes,
        today,
        report,
        edition: claim.pages?.[0] || '<unknown>',
        target: 'critical-coverage',
      });
      if (report.issues.length === before) validDirect.add(claim.id);
    }
  }
  const direct = requireCriticalCoverage ? validDirect : directCandidates;
  const remaining = [...claims.values()].filter(
    claim => claim.severity === 'critical' &&
      !direct.has(claim.id) &&
      !executedClaims.has(claim.id),
  );
  report.audit.remainingCriticalCount = remaining.length;
  if (requireCriticalCoverage && remaining.length) {
    report.issue({
      code: 'CRITICAL_COVERAGE_REMAINING',
      field: 'critical-coverage',
      actual: remaining.map(claim => claim.id),
      expected: [],
      fix: 'Source-attest every official critical claim and lineage-map every derived critical claim.',
    });
  }
  validateAudit(claimsData, report.audit, report);
  return report;
}

function cliOptions() {
  const { values } = parseArgs({
    options: {
      root: { type: 'string', default: DEFAULT_ROOT },
      claims: { type: 'string', default: 'data/claims.json' },
      attestations: { type: 'string', default: 'data/source-attestations.json' },
      bindings: { type: 'string', default: 'data/runtime-bindings.json' },
      boundaries: { type: 'string', default: 'data/boundary-executions.json' },
      lineage: { type: 'string' },
      today: { type: 'string', default: new Date().toISOString().slice(0, 10) },
      'require-critical-coverage': { type: 'boolean', default: false },
    },
    strict: true,
  });
  if (!values.lineage) throw new Error('--lineage is required');
  return {
    root: path.resolve(values.root),
    claimsPath: values.claims,
    attestationsPath: values.attestations,
    bindingsPath: values.bindings,
    boundariesPath: values.boundaries,
    lineagePath: values.lineage,
    today: values.today,
    requireCriticalCoverage: values['require-critical-coverage'],
  };
}

function main() {
  try {
    const report = verifyClaimLineage(cliOptions());
    if (report.issues.length) {
      console.error(
        `Claim lineage verification failed with ${report.issues.length} error(s):`,
      );
      report.issues.forEach(issue => console.error(report.render(issue)));
      console.error(`Audit: ${JSON.stringify(report.audit)}`);
      return 1;
    }
    console.log(
      `Claim lineage verification passed: ` +
      `${report.audit.mappedCount}/${report.audit.derivedCriticalCount} mapping(s), ` +
      `${report.audit.executedCount} executed, ` +
      `${report.audit.inputClaimCount} official/DAG input claim(s), ` +
      `${report.audit.remainingCriticalCount} critical remaining, ` +
      `audit=${JSON.stringify(report.audit)}.`,
    );
    return 0;
  } catch (error) {
    const report = new LineageReport();
    report.issue({
      code: 'CLI_FAILED',
      field: 'arguments',
      actual: error.message,
      expected: 'documented bounded claim-lineage CLI options',
      fix: 'Pass --lineage and only the documented registry paths/options.',
    });
    console.error(report.render(report.issues[0]));
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT_PATH) {
  process.exitCode = main();
}

export const CLAIM_LINEAGE_CONTRACT = Object.freeze({
  schemaVersion: SCHEMA_VERSION,
  targets: TARGETS,
  transforms: Object.freeze([...TRANSFORMS]),
  editions: EDITIONS,
});
