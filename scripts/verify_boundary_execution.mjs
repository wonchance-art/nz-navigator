#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

const SCHEMA_VERSION = 1;
const ROOT_FIELDS = new Set([
  'schemaVersion', 'requiredExecutions', 'targets', 'mappings',
]);
const TARGET_FIELDS = new Set([
  'id', 'kind', 'edition', 'page', 'probeDelta', 'tolerance', 'rules', 'reviewed',
]);
const EXECUTE_MAPPING_FIELDS = new Set([
  'claimId', 'edition', 'mode', 'targetId', 'assertion',
]);
const SEMANTIC_MAPPING_FIELDS = new Set([
  'claimId', 'edition', 'mode', 'assertion',
]);
const EDITION_PAGES = {
  nz: 'nz/index.html',
  ja: 'ja/index.html',
  ca: 'ca/index.html',
  au: 'au/index.html',
};
const TARGET_RULES = {
  'nz-paye-acc': ['bracket-continuity', 'acc-cap-plateau'],
  'ca-tax': [
    'bracket-continuity',
    'cpp-cap-plateau',
    'cpp2-cap-plateau',
    'ei-cap-plateau',
  ],
  'au-tax': ['bracket-continuity', 'lito-continuity'],
};
const TARGET_EDITIONS = {
  'nz-paye-acc': new Set(['nz', 'ja']),
  'ca-tax': new Set(['ca']),
  'au-tax': new Set(['au']),
};
const EXECUTE_ASSERTIONS = {
  'nz-paye-acc': new Set([
    'nz-paye-brackets', 'nz-acc-rate', 'nz-acc-cap',
  ]),
  'ca-tax': new Set(),
  'au-tax': new Set([
    'au-whm-rate',
    'au-resident-brackets',
    'au-medicare-rate',
    'au-super-rate',
  ]),
};
const FORBIDDEN_RUNTIME_TOKENS = /\b(?:eval|Function|process|require|import|fetch|XMLHttpRequest|WebSocket|document|window|globalThis)\b/;

function display(value) {
  if (value === undefined) return 'undefined';
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

class BoundaryReport {
  constructor() {
    this.issues = [];
    this.probes = 0;
    this.mappings = 0;
    this.targets = 0;
  }

  issue({
    code,
    edition = '<all>',
    claim = '<manifest>',
    boundary = '<schema>',
    probe = '<none>',
    actual,
    expected,
    fix,
  }) {
    this.issues.push({
      code, edition, claim, boundary, probe, actual, expected, fix,
    });
  }

  render(issue) {
    return (
      `ERROR code=${issue.code} edition=${issue.edition} ` +
      `claim=${issue.claim} boundary=${issue.boundary} ` +
      `probe=${issue.probe} actual=${display(issue.actual)} ` +
      `expected=${display(issue.expected)}\n  Fix: ${issue.fix}`
    );
  }
}

function readJson(root, relativePath, report, kind) {
  try {
    return JSON.parse(fs.readFileSync(resolveInside(root, relativePath), 'utf8'));
  } catch (error) {
    report.issue({
      code: `INVALID_${kind.toUpperCase()}`,
      boundary: relativePath,
      actual: error.message,
      expected: 'valid UTF-8 JSON',
      fix: `Repair the ${kind} file.`,
    });
    return null;
  }
}

function resolveInside(root, relativePath) {
  const resolved = path.resolve(root, relativePath);
  const prefix = `${path.resolve(root)}${path.sep}`;
  if (resolved !== path.resolve(root) && !resolved.startsWith(prefix)) {
    throw new Error(`path escapes repository root: ${relativePath}`);
  }
  return resolved;
}

function exactFields(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === fields.size && keys.every(key => fields.has(key));
}

function finiteNumber(value, { positive = false, nonnegative = false } = {}) {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    (!positive || value > 0) &&
    (!nonnegative || value >= 0)
  );
}

function validateBrackets(value) {
  if (!Array.isArray(value) || value.length < 2) return false;
  let previous = -Infinity;
  return value.every((row, index) => {
    if (!Array.isArray(row) || row.length !== 2) return false;
    const [cap, rate] = row;
    if (!finiteNumber(rate, { nonnegative: true })) return false;
    if (index === value.length - 1) return cap === null;
    if (!finiteNumber(cap, { positive: true }) || cap <= previous) return false;
    previous = cap;
    return true;
  });
}

function schemaIssue(report, boundary, actual, expected, fix) {
  report.issue({
    code: 'INVALID_MANIFEST',
    boundary,
    actual,
    expected,
    fix,
  });
}

function validateReviewed(target, report) {
  const reviewed = target.reviewed;
  const fail = (actual, expected, fix) => {
    schemaIssue(report, target.id, actual, expected, fix);
    return false;
  };
  if (!reviewed || typeof reviewed !== 'object' || Array.isArray(reviewed)) {
    return fail(reviewed, 'kind-specific reviewed object', 'Add reviewed official constants.');
  }
  if (target.kind === 'nz-paye-acc') {
    if (
      !validateBrackets(reviewed.brackets) ||
      !reviewed.acc ||
      !finiteNumber(reviewed.acc.rate, { positive: true }) ||
      !finiteNumber(reviewed.acc.cap, { positive: true })
    ) {
      return fail(
        reviewed,
        '{brackets:[[cap|null,rate]], acc:{rate,cap}}',
        'Repair the reviewed NZ brackets and ACC values.',
      );
    }
    return true;
  }
  if (target.kind === 'ca-tax') {
    const provinceKeys = ['on', 'bc', 'ab'];
    const validFederal = (
      reviewed.federal &&
      validateBrackets(reviewed.federal.brackets) &&
      finiteNumber(reviewed.federal.bpa, { nonnegative: true }) &&
      finiteNumber(reviewed.federal.employmentAmount, { nonnegative: true }) &&
      finiteNumber(reviewed.federal.creditRate, { nonnegative: true })
    );
    const validProvinces = (
      reviewed.provinces &&
      provinceKeys.every(code => (
        reviewed.provinces[code] &&
        validateBrackets(reviewed.provinces[code].brackets) &&
        finiteNumber(reviewed.provinces[code].bpa, { nonnegative: true })
      ))
    );
    const cpp = reviewed.cpp || {};
    const ei = reviewed.ei || {};
    const on = reviewed.ontario || {};
    const health = on.health || {};
    const validHealth = (
      finiteNumber(health.zeroTo, { nonnegative: true }) &&
      Array.isArray(health.tiers) &&
      health.tiers.length > 0 &&
      health.tiers.every(tier => (
        tier &&
        ['to', 'base', 'offset', 'rate', 'cap'].every(
          key => finiteNumber(tier[key], { nonnegative: true }),
        )
      )) &&
      health.above &&
      ['base', 'offset', 'rate', 'cap'].every(
        key => finiteNumber(health.above[key], { nonnegative: true }),
      )
    );
    const validCpp = [
      'rate', 'baseRate', 'additionalRate', 'ympe', 'exempt',
      'cpp2Rate', 'cpp2Min', 'cpp2Max',
    ].every(key => finiteNumber(cpp[key], { nonnegative: true }));
    const validEi = (
      finiteNumber(ei.rate, { nonnegative: true }) &&
      finiteNumber(ei.maxInsurable, { positive: true })
    );
    const validOntario = (
      ['surtaxLower', 'surtaxUpper', 'surtaxLowerRate',
        'surtaxUpperRate', 'taxReduction'].every(
        key => finiteNumber(on[key], { nonnegative: true }),
      ) && validHealth
    );
    if (!validFederal || !validProvinces || !validCpp || !validEi || !validOntario) {
      return fail(
        reviewed,
        'reviewed federal/provinces/cpp/ei/ontario constants',
        'Complete every documented CA reviewed constant with finite numbers.',
      );
    }
    if (
      Math.abs(cpp.rate - cpp.baseRate - cpp.additionalRate) > 1e-12 ||
      !(cpp.exempt < cpp.ympe && cpp.cpp2Min <= cpp.cpp2Max)
    ) {
      return fail(
        cpp,
        'rate=baseRate+additionalRate and ordered CPP limits',
        'Correct the reviewed CPP rate decomposition and caps.',
      );
    }
    return true;
  }
  if (target.kind === 'au-tax') {
    const whm = reviewed.whm || {};
    const resident = reviewed.resident || {};
    const lito = resident.lito || {};
    if (
      !finiteNumber(whm.cap, { positive: true }) ||
      !finiteNumber(whm.rate, { nonnegative: true }) ||
      !validateBrackets(resident.brackets) ||
      !finiteNumber(resident.medicareRate, { nonnegative: true }) ||
      !finiteNumber(resident.superRate, { nonnegative: true }) ||
      !['maxOffset', 'fullTo', 'taper1To', 'taper1Rate', 'cutOut', 'taper2Rate']
        .every(key => finiteNumber(lito[key], { nonnegative: true })) ||
      !(lito.fullTo < lito.taper1To && lito.taper1To < lito.cutOut)
    ) {
      return fail(
        reviewed,
        'reviewed WHM, resident brackets, Medicare, super, and LITO constants',
        'Repair the reviewed AU constants and ordered LITO thresholds.',
      );
    }
    return true;
  }
  return fail(target.kind, Object.keys(TARGET_RULES), 'Use a supported target kind.');
}

function validateManifest(manifest, report) {
  if (!exactFields(manifest, ROOT_FIELDS) || manifest.schemaVersion !== SCHEMA_VERSION) {
    schemaIssue(
      report,
      '<root>',
      manifest,
      {
        schemaVersion: SCHEMA_VERSION,
        requiredExecutions: [],
        targets: [],
        mappings: [],
      },
      'Use the exact documented manifest root fields.',
    );
    return null;
  }
  if (
    !Array.isArray(manifest.requiredExecutions) ||
    !Array.isArray(manifest.targets) ||
    !Array.isArray(manifest.mappings)
  ) {
    schemaIssue(report, '<root>', manifest, 'three arrays', 'Repair the manifest arrays.');
    return null;
  }
  const targets = new Map();
  for (const target of manifest.targets) {
    if (!exactFields(target, TARGET_FIELDS)) {
      schemaIssue(
        report,
        target?.id || '<target>',
        target,
        [...TARGET_FIELDS],
        'Use the exact common target fields.',
      );
      continue;
    }
    const canonicalPage = EDITION_PAGES[target.edition];
    const requiredRules = TARGET_RULES[target.kind];
    if (
      typeof target.id !== 'string' ||
      !target.id ||
      !requiredRules ||
      !TARGET_EDITIONS[target.kind]?.has(target.edition) ||
      canonicalPage !== target.page ||
      !finiteNumber(target.probeDelta, { positive: true }) ||
      !finiteNumber(target.tolerance, { nonnegative: true }) ||
      !Array.isArray(target.rules) ||
      new Set(target.rules).size !== target.rules.length ||
      [...target.rules].sort().join('|') !== [...requiredRules].sort().join('|')
    ) {
      schemaIssue(
        report,
        target.id || '<target>',
        target,
        'canonical edition/page, finite probe settings, and exact kind rules',
        'Correct the target identity, page, probeDelta, tolerance, or rules.',
      );
      continue;
    }
    if (targets.has(target.id)) {
      schemaIssue(
        report,
        target.id,
        target.id,
        'unique target id',
        'Remove the duplicate target.',
      );
      continue;
    }
    if (validateReviewed(target, report)) targets.set(target.id, target);
  }
  const required = new Set();
  for (const id of manifest.requiredExecutions) {
    if (typeof id !== 'string' || !id || required.has(id)) {
      schemaIssue(
        report,
        '<requiredExecutions>',
        id,
        'unique target id',
        'Remove invalid or duplicate required execution ids.',
      );
      continue;
    }
    required.add(id);
    if (!targets.has(id)) {
      report.issue({
        code: 'MISSING_REQUIRED_TARGET',
        boundary: id,
        actual: 'target not found',
        expected: 'declared target',
        fix: 'Add the reviewed target or remove the required execution id.',
      });
    }
  }
  return { targets, required };
}

function scriptBlocks(html) {
  return [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/gi)]
    .filter(match => !/\bsrc\s*=/.test(match[1]))
    .map(match => match[2]);
}

function balancedEnd(source, start, open, close) {
  let depth = 0;
  let state = 'code';
  let quote = '';
  for (let index = start; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1] || '';
    if (state === 'line') {
      if (char === '\n') state = 'code';
      continue;
    }
    if (state === 'block') {
      if (char === '*' && next === '/') {
        state = 'code';
        index += 1;
      }
      continue;
    }
    if (state === 'string') {
      if (char === '\\') {
        index += 1;
      } else if (char === quote) {
        state = 'code';
      }
      continue;
    }
    if (char === '/' && next === '/') {
      state = 'line';
      index += 1;
    } else if (char === '/' && next === '*') {
      state = 'block';
      index += 1;
    } else if (char === "'" || char === '"' || char === '`') {
      state = 'string';
      quote = char;
    } else if (char === open) {
      depth += 1;
    } else if (char === close) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  throw new Error(`unterminated ${open}${close} block`);
}

function maskStringsAndComments(source) {
  const chars = [...source];
  let state = 'code';
  let quote = '';
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1] || '';
    if (state === 'line') {
      if (char === '\n') {
        state = 'code';
      } else {
        chars[index] = ' ';
      }
      continue;
    }
    if (state === 'block') {
      chars[index] = ' ';
      if (char === '*' && next === '/') {
        chars[index + 1] = ' ';
        index += 1;
        state = 'code';
      }
      continue;
    }
    if (state === 'string') {
      if (char !== '\n') chars[index] = ' ';
      if (char === '\\') {
        if (index + 1 < source.length) {
          chars[index + 1] = ' ';
          index += 1;
        }
      } else if (char === quote) {
        state = 'code';
      }
      continue;
    }
    if (char === '/' && next === '/') {
      chars[index] = ' ';
      chars[index + 1] = ' ';
      index += 1;
      state = 'line';
    } else if (char === '/' && next === '*') {
      chars[index] = ' ';
      chars[index + 1] = ' ';
      index += 1;
      state = 'block';
    } else if (char === "'" || char === '"' || char === '`') {
      chars[index] = ' ';
      state = 'string';
      quote = char;
    }
  }
  return chars.join('');
}

function findBlock(html, token) {
  const matches = scriptBlocks(html).filter(block => block.includes(token));
  if (matches.length !== 1) {
    throw new Error(`${token} must occur in exactly one inline script`);
  }
  return matches[0];
}

function validateDataLiteral(initializer, name) {
  const masked = maskStringsAndComments(initializer);
  for (let index = 0; index < masked.length; index += 1) {
    if (masked[index] !== '+' && masked[index] !== '-') continue;
    let previous = index - 1;
    while (previous >= 0 && /\s/.test(masked[previous])) previous -= 1;
    let next = index + 1;
    while (next < masked.length && /\s/.test(masked[next])) next += 1;
    const valueSign = (
      (
        previous < 0 ||
        [':', ',', '[', '{'].includes(masked[previous])
      ) &&
      (/\d/.test(masked[next] || '') ||
        (masked[next] === '.' && /\d/.test(masked[next + 1] || '')))
    );
    const exponentSign = (
      (masked[previous] === 'e' || masked[previous] === 'E') &&
      previous > 0 &&
      /\d/.test(masked[previous - 1]) &&
      /\d/.test(masked[next] || '')
    );
    if (!valueSign && !exponentSign) {
      throw new Error(
        `const ${name} contains a computed binary ${masked[index]} expression`,
      );
    }
  }
  if (/[^A-Za-z0-9_$\s{}[\],:.\-+]/.test(masked)) {
    throw new Error(`const ${name} contains a computed expression`);
  }
  const withoutNumbers = masked.replace(
    /(?<![A-Za-z0-9_$])(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?(?![A-Za-z0-9_$])/g,
    token => ' '.repeat(token.length),
  );
  for (const match of withoutNumbers.matchAll(/[A-Za-z_$][A-Za-z0-9_$]*/g)) {
    const identifier = match[0];
    if (['Infinity', 'true', 'false', 'null'].includes(identifier)) {
      continue;
    }
    let next = match.index + identifier.length;
    while (/\s/.test(withoutNumbers[next] || '')) next += 1;
    if (withoutNumbers[next] !== ':') {
      throw new Error(
        `const ${name} identifier ${identifier} is not a literal object key`,
      );
    }
  }
}

function extractConst(block, name) {
  const match = new RegExp(`\\bconst\\s+${name}\\s*=`).exec(block);
  if (!match) throw new Error(`const ${name} not found`);
  let start = match.index + match[0].length;
  while (/\s/.test(block[start] || '')) start += 1;
  const open = block[start];
  if (open !== '{' && open !== '[') {
    throw new Error(`const ${name} must be a direct object/array literal`);
  }
  const end = balancedEnd(block, start, open, open === '{' ? '}' : ']');
  let semicolon = end;
  while (/\s/.test(block[semicolon] || '')) semicolon += 1;
  if (block[semicolon] !== ';') {
    throw new Error(`const ${name} must end after one literal`);
  }
  validateDataLiteral(block.slice(start, end), name);
  const source = block.slice(match.index, semicolon + 1);
  if (FORBIDDEN_RUNTIME_TOKENS.test(maskStringsAndComments(source))) {
    throw new Error(`const ${name} contains a forbidden runtime token`);
  }
  return source;
}

function extractFunction(block, name, { enforceTokenAllowlist = true } = {}) {
  const match = new RegExp(`\\bfunction\\s+${name}\\s*\\(`).exec(block);
  if (!match) throw new Error(`function ${name} not found`);
  const bodyStart = block.indexOf('{', match.index + match[0].length);
  if (bodyStart < 0) throw new Error(`function ${name} has no body`);
  const end = balancedEnd(block, bodyStart, '{', '}');
  const source = block.slice(match.index, end);
  if (
    enforceTokenAllowlist &&
    FORBIDDEN_RUNTIME_TOKENS.test(maskStringsAndComments(source))
  ) {
    throw new Error(`function ${name} contains a forbidden runtime token`);
  }
  return source;
}

function extractNzAccExpression(block) {
  const renderer = extractFunction(
    block,
    'renderNetPay',
    { enforceTokenAllowlist: false },
  );
  const match = /\bconst\s+acc\s*=\s*([^;]+);/.exec(renderer);
  if (!match) throw new Error('renderNetPay ACC expression not found');
  const expression = match[1];
  if (!/^[\s\d+*/().,-]+$/.test(
    expression.replace(/\b(?:Math|min|gross|NP_ACC|cap|rate)\b/g, ''),
  )) {
    throw new Error('renderNetPay ACC expression exceeds the lexical allowlist');
  }
  const identifiers = expression.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || [];
  const allowed = new Set(['Math', 'min', 'gross', 'NP_ACC', 'cap', 'rate']);
  if (identifiers.some(identifier => !allowed.has(identifier))) {
    throw new Error('renderNetPay ACC expression contains an unknown identifier');
  }
  return expression;
}

function loadRuntime(root, target) {
  const html = fs.readFileSync(resolveInside(root, target.page), 'utf8');
  if (target.kind === 'nz-paye-acc') {
    const block = findBlock(html, 'const NP_BRACKETS =');
    const accExpression = extractNzAccExpression(block);
    const source = [
      extractConst(block, 'NP_BRACKETS'),
      extractConst(block, 'NP_ACC'),
      extractFunction(block, 'npTax'),
      'globalThis.__api = {',
      ' tax: gross => npTax(gross),',
      ` acc: gross => (${accExpression})`,
      '};',
    ].join('\n');
    return runIsolated(source);
  }
  if (target.kind === 'ca-tax') {
    const block = findBlock(html, 'const CA_TAX =');
    const source = [
      extractConst(block, 'CA_TAX'),
      extractFunction(block, 'npTax'),
      'globalThis.__api = { tax: (gross, province) => npTax(gross, province) };',
    ].join('\n');
    return runIsolated(source);
  }
  const block = findBlock(html, 'const AU_TAX =');
  const source = [
    extractConst(block, 'AU_TAX'),
    extractFunction(block, 'npTaxResident'),
    extractFunction(block, 'npTax'),
    'globalThis.__api = { tax: (gross, mode) => npTax(gross, mode) };',
  ].join('\n');
  return runIsolated(source);
}

function runIsolated(source) {
  const context = vm.createContext(Object.create(null), {
    codeGeneration: { strings: false, wasm: false },
  });
  vm.runInContext(source, context, { timeout: 200 });
  return context.__api;
}

function progressiveTax(gross, brackets) {
  let total = 0;
  let previous = 0;
  for (const [rawCap, rate] of brackets) {
    const cap = rawCap === null ? Infinity : rawCap;
    if (gross > previous) total += (Math.min(gross, cap) - previous) * rate;
    previous = cap;
  }
  return total;
}

function expectedCanada(gross, province, reviewed) {
  const pensionable = Math.max(
    0,
    Math.min(gross, reviewed.cpp.ympe) - reviewed.cpp.exempt,
  );
  const cppBase = pensionable * reviewed.cpp.baseRate;
  const cppAdditional = pensionable * reviewed.cpp.additionalRate;
  const cpp2Base = gross > reviewed.cpp.cpp2Min
    ? Math.max(0, Math.min(gross, reviewed.cpp.cpp2Max) - reviewed.cpp.cpp2Min)
    : 0;
  const cpp2 = cpp2Base * reviewed.cpp.cpp2Rate;
  const cppTax = cppBase + cppAdditional + cpp2;
  const eiTax = Math.min(gross, reviewed.ei.maxInsurable) * reviewed.ei.rate;
  const taxable = Math.max(0, gross - cppAdditional - cpp2);
  let fedTax = progressiveTax(taxable, reviewed.federal.brackets);
  const fedCredits = (
    reviewed.federal.bpa +
    cppBase +
    eiTax +
    Math.min(gross, reviewed.federal.employmentAmount)
  ) * reviewed.federal.creditRate;
  fedTax = Math.max(0, fedTax - fedCredits);
  const provinceData = reviewed.provinces[province];
  let provTax = progressiveTax(taxable, provinceData.brackets);
  provTax = Math.max(
    0,
    provTax - (
      provinceData.bpa + cppBase + eiTax
    ) * provinceData.brackets[0][1],
  );
  if (province === 'on') {
    const on = reviewed.ontario;
    const surtax = provTax <= on.surtaxLower
      ? 0
      : provTax <= on.surtaxUpper
        ? (provTax - on.surtaxLower) * on.surtaxLowerRate
        : (
          (provTax - on.surtaxLower) * on.surtaxLowerRate +
          (provTax - on.surtaxUpper) * on.surtaxUpperRate
        );
    let healthPremium = 0;
    if (taxable > on.health.zeroTo) {
      const tier = on.health.tiers.find(item => taxable <= item.to);
      const formula = tier || on.health.above;
      healthPremium = Math.min(
        formula.cap,
        formula.base + (taxable - formula.offset) * formula.rate,
      );
    }
    const taxReduction = Math.min(
      provTax,
      Math.max(0, on.taxReduction - provTax),
    );
    provTax = Math.max(0, provTax + surtax + healthPremium - taxReduction);
  }
  return {
    fedTax,
    provTax,
    cppTax,
    eiTax,
    totalTax: fedTax + provTax + cppTax + eiTax,
  };
}

function expectedAustralia(gross, mode, reviewed) {
  let tax = 0;
  let medicare = 0;
  if (mode === 'whm') {
    tax = Math.min(gross, reviewed.whm.cap) * reviewed.whm.rate;
    if (gross > reviewed.whm.cap) {
      let previous = reviewed.whm.cap;
      for (const [rawCap, rate] of reviewed.resident.brackets) {
        const cap = rawCap === null ? Infinity : rawCap;
        if (cap <= reviewed.whm.cap) {
          previous = Math.max(previous, cap);
          continue;
        }
        if (gross > previous) tax += (Math.min(gross, cap) - previous) * rate;
        previous = cap;
      }
    }
  } else {
    tax = progressiveTax(gross, reviewed.resident.brackets);
    const lito = reviewed.resident.lito;
    let offset = 0;
    if (gross <= lito.fullTo) offset = lito.maxOffset;
    else if (gross <= lito.taper1To) {
      offset = lito.maxOffset - (gross - lito.fullTo) * lito.taper1Rate;
    } else if (gross <= lito.cutOut) {
      const afterFirst = (
        lito.maxOffset -
        (lito.taper1To - lito.fullTo) * lito.taper1Rate
      );
      offset = afterFirst - (gross - lito.taper1To) * lito.taper2Rate;
    }
    tax = Math.max(0, tax - offset);
    medicare = gross * reviewed.resident.medicareRate;
  }
  const superValue = gross * reviewed.resident.superRate;
  const net = gross - tax - medicare;
  return {
    tax: Math.round(tax),
    medicare: Math.round(medicare),
    net: Math.round(net),
    super: Math.round(superValue),
    effectiveRate: ((tax + medicare) / gross * 100).toFixed(1),
  };
}

function compareNumbers(actual, expected, tolerance) {
  if (typeof actual === 'number' && typeof expected === 'number') {
    return Number.isFinite(actual) && Math.abs(actual - expected) <= tolerance;
  }
  if (
    actual &&
    expected &&
    typeof actual === 'object' &&
    typeof expected === 'object'
  ) {
    return Object.keys(expected).every(
      key => compareNumbers(actual[key], expected[key], tolerance),
    );
  }
  return actual === expected;
}

function recordProbe(report, target, claim, boundary, label, actual, expected) {
  report.probes += 1;
  if (!compareNumbers(actual, expected, target.tolerance)) {
    report.issue({
      code: 'BOUNDARY_PROBE_MISMATCH',
      edition: target.edition,
      claim,
      boundary,
      probe: label,
      actual,
      expected,
      fix: 'Review the runtime function and reviewed manifest constants; do not adjust tolerance to hide a factual mismatch.',
    });
  }
}

function around(threshold, delta) {
  return [
    ['just-below', threshold - delta],
    ['exact', threshold],
    ['just-above', threshold + delta],
  ];
}

function mappingClaim(mappings, targetId, assertion, fallback) {
  return mappings.find(
    item => item.mode === 'execute' &&
      item.targetId === targetId &&
      item.assertion === assertion,
  )?.claimId || fallback;
}

function executeNz(target, runtime, mappings, report) {
  const bracketsClaim = mappingClaim(
    mappings, target.id, 'nz-paye-brackets', `<policy:${target.id}>`,
  );
  for (const [threshold] of target.reviewed.brackets.slice(0, -1)) {
    for (const [position, gross] of around(threshold, target.probeDelta)) {
      recordProbe(
        report,
        target,
        bracketsClaim,
        'nz-paye-brackets',
        `${position}@${threshold}:${gross}`,
        runtime.tax(gross),
        progressiveTax(gross, target.reviewed.brackets),
      );
    }
  }
  const capClaim = mappingClaim(
    mappings, target.id, 'nz-acc-cap', `<policy:${target.id}>`,
  );
  const { cap, rate } = target.reviewed.acc;
  for (const [position, gross] of around(cap, target.probeDelta)) {
    recordProbe(
      report,
      target,
      capClaim,
      'nz-acc-cap-plateau',
      `${position}@${cap}:${gross}`,
      runtime.acc(gross),
      Math.min(gross, cap) * rate,
    );
  }
}

function executeCanada(target, runtime, report) {
  const reviewed = target.reviewed;
  const probes = [];
  for (const [threshold] of reviewed.federal.brackets.slice(0, -1)) {
    probes.push(['federal-bracket', threshold, 'on']);
  }
  for (const province of ['on', 'bc', 'ab']) {
    for (const [threshold] of reviewed.provinces[province].brackets.slice(0, -1)) {
      probes.push([`${province}-bracket`, threshold, province]);
    }
  }
  const capBoundaries = [
    ['cpp-exemption', reviewed.cpp.exempt],
    ['ei-cap', reviewed.ei.maxInsurable],
    ['cpp-cap-cpp2-start', reviewed.cpp.ympe],
    ['cpp2-cap', reviewed.cpp.cpp2Max],
  ];
  for (const [name, threshold] of capBoundaries) {
    probes.push([name, threshold, 'on']);
  }
  for (const [boundary, threshold, province] of probes) {
    for (const [position, gross] of around(threshold, target.probeDelta)) {
      recordProbe(
        report,
        target,
        '<policy:ca-tax>',
        boundary,
        `${position}@${threshold}:${gross}`,
        runtime.tax(gross, province),
        expectedCanada(gross, province, reviewed),
      );
    }
  }
}

function executeAustralia(target, runtime, mappings, report) {
  const reviewed = target.reviewed;
  const whmClaim = mappingClaim(
    mappings, target.id, 'au-whm-rate', `<policy:${target.id}>`,
  );
  for (const [position, gross] of around(reviewed.whm.cap, target.probeDelta)) {
    recordProbe(
      report,
      target,
      whmClaim,
      'au-whm-cap',
      `${position}@${reviewed.whm.cap}:${gross}`,
      runtime.tax(gross, 'whm'),
      expectedAustralia(gross, 'whm', reviewed),
    );
  }
  const residentClaim = mappingClaim(
    mappings, target.id, 'au-resident-brackets', `<policy:${target.id}>`,
  );
  for (const [threshold] of reviewed.resident.brackets.slice(0, -1)) {
    for (const [position, gross] of around(threshold, target.probeDelta)) {
      recordProbe(
        report,
        target,
        residentClaim,
        'au-resident-bracket',
        `${position}@${threshold}:${gross}`,
        runtime.tax(gross, 'resident'),
        expectedAustralia(gross, 'resident', reviewed),
      );
    }
  }
  const lito = reviewed.resident.lito;
  for (const threshold of [lito.fullTo, lito.taper1To, lito.cutOut]) {
    for (const [position, gross] of around(threshold, target.probeDelta)) {
      recordProbe(
        report,
        target,
        residentClaim,
        'au-lito-continuity',
        `${position}@${threshold}:${gross}`,
        runtime.tax(gross, 'resident'),
        expectedAustralia(gross, 'resident', reviewed),
      );
    }
  }
}

function parseClaimRange(value) {
  if (typeof value !== 'string') return null;
  const match = value.match(/^([+-]?\d+(?:\.\d+)?)\s*-\s*([+-]?\d+(?:\.\d+)?)$/);
  return match ? [Number(match[1]), Number(match[2])] : null;
}

function parseClaimBrackets(value) {
  if (typeof value !== 'string') return null;
  const rows = value.split(';').map(row => {
    const parts = row.split('@');
    if (parts.length !== 2) return null;
    const cap = parts[0] === 'above' ? null : Number(parts[0]);
    const rate = Number(parts[1]);
    if (
      (cap !== null && !Number.isFinite(cap)) ||
      !Number.isFinite(rate)
    ) return null;
    return [cap, rate];
  });
  return rows.some(row => row === null) ? null : rows;
}

function expectedClaimValue(assertion, reviewed) {
  if (assertion === 'nz-paye-brackets') return reviewed.brackets;
  if (assertion === 'nz-acc-rate') return reviewed.acc.rate * 100;
  if (assertion === 'nz-acc-cap') return reviewed.acc.cap;
  if (assertion === 'au-whm-rate') return reviewed.whm.rate * 100;
  if (assertion === 'au-resident-brackets') {
    return reviewed.resident.brackets;
  }
  if (assertion === 'au-medicare-rate') {
    return reviewed.resident.medicareRate;
  }
  if (assertion === 'au-super-rate') {
    return reviewed.resident.superRate;
  }
  return undefined;
}

function claimMatchesAssertion(claim, assertion, reviewed) {
  const expected = expectedClaimValue(assertion, reviewed);
  if (expected === undefined) return true;
  if (assertion.endsWith('brackets')) {
    const actual = parseClaimBrackets(claim?.value);
    return actual !== null && compareNumbers(actual, expected, 1e-12);
  }
  return compareNumbers(claim?.value, expected, 1e-12);
}

function executeSemantic(mapping, claim, report) {
  const assertion = mapping.assertion;
  if (
    !assertion ||
    typeof assertion !== 'object' ||
    Array.isArray(assertion) ||
    !finiteNumber(assertion.delta, { positive: true })
  ) {
    report.issue({
      code: 'INVALID_SEMANTIC_ASSERTION',
      edition: mapping.edition,
      claim: mapping.claimId,
      boundary: 'semantic',
      actual: assertion,
      expected: 'inclusive-range or maximum assertion with positive delta',
      fix: 'Use the documented semantic assertion shape.',
    });
    return;
  }
  if (assertion.kind === 'inclusive-range') {
    if (
      !exactFields(assertion, new Set(['kind', 'min', 'max', 'delta'])) ||
      !finiteNumber(assertion.min, { nonnegative: true }) ||
      !finiteNumber(assertion.max, { positive: true }) ||
      assertion.min >= assertion.max
    ) {
      report.issue({
        code: 'INVALID_SEMANTIC_ASSERTION',
        edition: mapping.edition,
        claim: mapping.claimId,
        boundary: 'inclusive-range',
        actual: assertion,
        expected: '{kind,min,max,delta} with min < max',
        fix: 'Repair the reviewed inclusive range assertion.',
      });
      return;
    }
    const claimRange = parseClaimRange(claim?.value);
    if (!claimRange) {
      report.issue({
        code: 'SEMANTIC_SOURCE_MISMATCH',
        edition: mapping.edition,
        claim: mapping.claimId,
        boundary: 'inclusive-range',
        actual: claim?.value,
        expected: `${assertion.min}-${assertion.max}`,
        fix: 'Align the claim range and reviewed semantic assertion.',
      });
      return;
    }
    const probes = [
      ['just-below-min', assertion.min - assertion.delta, false],
      ['exact-min', assertion.min, true],
      ['exact-max', assertion.max, true],
      ['just-above-max', assertion.max + assertion.delta, false],
    ];
    for (const [label, value, expected] of probes) {
      const actual = value >= claimRange[0] && value <= claimRange[1];
      recordProbe(
        report,
        {
          edition: mapping.edition,
          tolerance: 0,
        },
        mapping.claimId,
        'inclusive-range',
        `${label}:${value}`,
        actual,
        expected,
      );
    }
    return;
  }
  if (
    assertion.kind !== 'maximum' ||
    !exactFields(assertion, new Set(['kind', 'value', 'delta'])) ||
    !finiteNumber(assertion.value, { positive: true })
  ) {
    report.issue({
      code: 'INVALID_SEMANTIC_ASSERTION',
      edition: mapping.edition,
      claim: mapping.claimId,
      boundary: 'semantic',
      actual: assertion,
      expected: '{kind:"maximum",value,delta}',
      fix: 'Repair the reviewed maximum assertion.',
    });
    return;
  }
  if (!finiteNumber(claim?.value, { positive: true })) {
    report.issue({
      code: 'SEMANTIC_SOURCE_MISMATCH',
      edition: mapping.edition,
      claim: mapping.claimId,
      boundary: 'maximum',
      actual: claim?.value,
      expected: assertion.value,
      fix: 'Align the numeric claim and reviewed maximum assertion.',
    });
    return;
  }
  for (const [label, value, expected] of [
    ['just-below', assertion.value - assertion.delta, true],
    ['exact', assertion.value, true],
    ['just-above', assertion.value + assertion.delta, false],
  ]) {
    const actual = value <= claim.value;
    recordProbe(
      report,
      { edition: mapping.edition, tolerance: 0 },
      mapping.claimId,
      'maximum',
      `${label}:${value}`,
      actual,
      expected,
    );
  }
}

function validateMappings(manifest, validated, bindings, claims, report) {
  const boundaryBindings = new Map();
  for (const binding of bindings.bindings || []) {
    if (binding && binding.boundary) {
      boundaryBindings.set(
        `${binding.claimId}\0${binding.edition}`,
        binding,
      );
    }
  }
  const seen = new Set();
  const referencedTargets = new Set();
  const validMappings = [];
  for (const mapping of manifest.mappings) {
    const mode = mapping?.mode;
    const expectedFields = mode === 'execute'
      ? EXECUTE_MAPPING_FIELDS
      : mode === 'semantic'
        ? SEMANTIC_MAPPING_FIELDS
        : null;
    if (!expectedFields || !exactFields(mapping, expectedFields)) {
      report.issue({
        code: 'INVALID_MAPPING',
        edition: mapping?.edition || '<unknown>',
        claim: mapping?.claimId || '<mapping>',
        boundary: mode || '<mode>',
        actual: mapping,
        expected: 'exact execute or semantic mapping fields',
        fix: 'Use a documented mapping mode and exact fields.',
      });
      continue;
    }
    const key = `${mapping.claimId}\0${mapping.edition}`;
    if (seen.has(key)) {
      report.issue({
        code: 'DUPLICATE_MAPPING',
        edition: mapping.edition,
        claim: mapping.claimId,
        boundary: mode,
        actual: 'duplicate',
        expected: 'one mapping per boundary binding',
        fix: 'Remove the duplicate mapping.',
      });
      continue;
    }
    seen.add(key);
    const binding = boundaryBindings.get(key);
    if (!binding) {
      report.issue({
        code: 'ORPHAN_MAPPING',
        edition: mapping.edition,
        claim: mapping.claimId,
        boundary: mode,
        actual: 'no matching boundary declaration',
        expected: 'claim+edition in runtime bindings with boundary metadata',
        fix: 'Remove the mapping or add the reviewed runtime boundary declaration.',
      });
      continue;
    }
    if (mode === 'execute') {
      const target = validated.targets.get(mapping.targetId);
      if (
        !target ||
        target.edition !== mapping.edition ||
        !EXECUTE_ASSERTIONS[target.kind]?.has(mapping.assertion)
      ) {
        report.issue({
          code: 'INVALID_EXECUTE_MAPPING',
          edition: mapping.edition,
          claim: mapping.claimId,
          boundary: mapping.targetId,
          actual: mapping.assertion,
          expected: target
            ? [...EXECUTE_ASSERTIONS[target.kind]]
            : 'existing target for the same edition',
          fix: 'Correct targetId, edition, and the kind-specific assertion.',
        });
        continue;
      }
      const claim = claims.get(mapping.claimId);
      if (!claim || !claimMatchesAssertion(
        claim,
        mapping.assertion,
        target.reviewed,
      )) {
        report.issue({
          code: 'MAPPING_CLAIM_MISMATCH',
          edition: mapping.edition,
          claim: mapping.claimId,
          boundary: mapping.assertion,
          actual: claim?.value,
          expected: expectedClaimValue(
            mapping.assertion,
            target.reviewed,
          ),
          fix: 'Map this assertion to the matching reviewed claim; do not use a mapping to bypass claim parity.',
        });
        continue;
      }
      referencedTargets.add(mapping.targetId);
    }
    validMappings.push(mapping);
  }
  for (const [key, binding] of boundaryBindings) {
    if (!seen.has(key)) {
      report.issue({
        code: 'MISSING_MAPPING',
        edition: binding.edition,
        claim: binding.claimId,
        boundary: binding.boundary?.kind || '<boundary>',
        actual: 'unmapped',
        expected: 'execute or semantic mapping',
        fix: 'Add exactly one reviewed mapping for this boundary declaration.',
      });
    }
  }
  for (const [id, target] of validated.targets) {
    if (!validated.required.has(id) && !referencedTargets.has(id)) {
      report.issue({
        code: 'ORPHAN_TARGET',
        edition: target.edition,
        claim: '<manifest>',
        boundary: id,
        actual: 'not required or mapped',
        expected: 'requiredExecutions entry or execute mapping',
        fix: 'Remove the target or make its policy/mapping explicit.',
      });
    }
  }
  report.mappings = validMappings.length;
  return { validMappings, boundaryBindings };
}

export function verifyBoundaryExecution({
  root,
  claimsPath,
  bindingsPath,
  manifestPath,
}) {
  const report = new BoundaryReport();
  const claimsData = readJson(root, claimsPath, report, 'claims');
  const bindingsData = readJson(root, bindingsPath, report, 'bindings');
  const manifest = readJson(root, manifestPath, report, 'manifest');
  if (!claimsData || !bindingsData || !manifest) return report;
  if (
    !Array.isArray(claimsData.claims) ||
    !Array.isArray(bindingsData.bindings)
  ) {
    schemaIssue(
      report,
      '<registries>',
      { claims: claimsData.claims, bindings: bindingsData.bindings },
      'claims[] and bindings[]',
      'Use the production registry root schemas.',
    );
    return report;
  }
  const validated = validateManifest(manifest, report);
  if (!validated) return report;
  const claims = new Map(claimsData.claims.map(claim => [claim.id, claim]));
  const { validMappings } = validateMappings(
    manifest,
    validated,
    bindingsData,
    claims,
    report,
  );
  for (const mapping of validMappings) {
    if (mapping.mode === 'semantic') {
      executeSemantic(mapping, claims.get(mapping.claimId), report);
    }
  }
  for (const [id, target] of validated.targets) {
    if (!validated.required.has(id) && !validMappings.some(
      mapping => mapping.mode === 'execute' && mapping.targetId === id,
    )) continue;
    try {
      const runtime = loadRuntime(root, target);
      if (target.kind === 'nz-paye-acc') {
        executeNz(target, runtime, validMappings, report);
      } else if (target.kind === 'ca-tax') {
        executeCanada(target, runtime, report);
      } else {
        executeAustralia(target, runtime, validMappings, report);
      }
      report.targets += 1;
    } catch (error) {
      report.issue({
        code: 'RUNTIME_EXTRACTION_FAILED',
        edition: target.edition,
        claim: `<policy:${id}>`,
        boundary: id,
        actual: error.message,
        expected: 'allowlisted lexical declarations and isolated calculator functions',
        fix: 'Restore the supported calculator declaration boundary; do not add executable manifest content.',
      });
    }
  }
  const productionManifest = path.resolve(root, 'data/boundary-executions.json');
  if (path.resolve(root, manifestPath) === productionManifest) {
    const actualAudit = claimsData.audit?.runtimeBindings?.boundaryProbeCount;
    if (actualAudit !== report.probes) {
      report.issue({
        code: 'PUBLIC_AUDIT_MISMATCH',
        boundary: manifestPath,
        probe: '<summary>',
        actual: actualAudit,
        expected: report.probes,
        fix: 'Set claims.audit.runtimeBindings.boundaryProbeCount to the verified probe total.',
      });
    }
  }
  return report;
}

function cliOptions() {
  const repositoryRoot = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
  );
  const { values } = parseArgs({
    options: {
      root: { type: 'string', default: repositoryRoot },
      claims: { type: 'string', default: 'data/claims.json' },
      bindings: { type: 'string', default: 'data/runtime-bindings.json' },
      manifest: {
        type: 'string',
        default: 'data/boundary-executions.json',
      },
    },
  });
  return {
    root: path.resolve(values.root),
    claimsPath: values.claims,
    bindingsPath: values.bindings,
    manifestPath: values.manifest,
  };
}

function main() {
  const report = verifyBoundaryExecution(cliOptions());
  if (report.issues.length) {
    console.error(
      `Boundary execution verification failed with ${report.issues.length} error(s):`,
    );
    report.issues.forEach(issue => console.error(report.render(issue)));
    return 1;
  }
  console.log(
    `Boundary execution verification passed: ${report.mappings} mapping(s), ` +
    `${report.targets} execution target(s), ${report.probes} probe(s).`,
  );
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
