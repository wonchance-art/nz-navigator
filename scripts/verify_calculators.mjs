#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const registry = JSON.parse(fs.readFileSync(path.join(root, 'data/claims.json'), 'utf8'));
const values = new Map(registry.claims.map(claim => [claim.id, claim.value]));
const failures = [];

function html(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function slice(source, startToken, endToken) {
  const start = source.indexOf(startToken);
  const end = source.indexOf(endToken, start);
  if (start < 0 || end < 0) {
    throw new Error(`script block not found: ${startToken} … ${endToken}`);
  }
  return source.slice(start, end);
}

function evaluate(source, expression) {
  const context = {};
  vm.createContext(context);
  vm.runInContext(`${source}\n__result = (${expression});`, context);
  return context.__result;
}

function expect(id, actual) {
  const expected = values.get(id);
  if (expected === undefined) {
    failures.push(`${id}: registry value is missing`);
    return;
  }
  if (actual !== expected) {
    failures.push(`${id}: expected ${expected}, got ${actual}`);
    return;
  }
  console.log(`PASS ${id}: ${actual}`);
}

function verifyNz(relativePath, id) {
  const source = html(relativePath);
  const block = slice(source, 'const NP_BRACKETS =', 'function renderNetPay');
  const net = evaluate(
    block,
    'Math.round(72800 - npTax(72800) - Math.min(72800, NP_ACC.cap) * NP_ACC.rate)'
  );
  expect(id, net);
}

function verifyCanada() {
  const source = html('ca/index.html');
  const crsBlock = slice(source, 'const CRS_AGE_SCORES =', 'function renderCrsCalc');
  const crs = evaluate(
    crsBlock,
    'CRS_AGE_SCORES.a35 + CRS_EDUCATION_SCORES.e120 + CRS_LANGUAGE_SCORES.l7 + CRS_EXPERIENCE_SCORES.x1'
  );
  expect('ca-ko-crs-sample-305', crs);

  const taxBlock = slice(source, 'const CA_TAX =', 'function renderNetPay');
  const net = evaluate(taxBlock, 'Math.round(60000 - npTax(60000, "on").totalTax)');
  expect('ca-ko-tax-on-60000', net);
}

function verifyAustralia() {
  const source = html('au/index.html');
  const block = slice(source, 'const AU_TAX =', 'function renderNetPay');
  const whm = evaluate(block, 'npTax(52115, "whm").net');
  const resident = evaluate(block, 'npTax(60000, "resident").net');
  expect('au-ko-tax-whm-52115', whm);
  expect('au-ko-tax-resident-60000', resident);
}

try {
  verifyNz('nz/index.html', 'nz-ko-netpay-72800');
  verifyNz('ja/index.html', 'nz-ja-netpay-72800');
  verifyCanada();
  verifyAustralia();
} catch (error) {
  failures.push(error.stack || error.message);
}

if (failures.length) {
  console.error('\nCalculator regression verification failed:');
  failures.forEach(failure => console.error(`- ${failure}`));
  process.exit(1);
}

console.log(`\nAll 6 calculator regression samples passed.`);
