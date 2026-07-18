#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "..");
const DEFAULT_FIXTURES = path.join(
  REPO_ROOT,
  "tests",
  "fixtures",
  "diagnosis-cases.json",
);
const REQUIRED_INPUT_FIELDS = [
  "entry",
  "age",
  "job",
  "experience",
  "english",
  "funding",
  "education",
  "family",
];

function display(value) {
  if (typeof value === "undefined") return "<undefined>";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function failure(edition, fixtureId, field, actual, expected, detail = "") {
  const suffix = detail ? ` — ${detail}` : "";
  return (
    `ERROR edition=${edition} fixture=${fixtureId} field=${field} ` +
    `actual=${display(actual)} expected=${display(expected)}${suffix}`
  );
}

function extractInlineScript(html, edition) {
  const blocks = [
    ...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/gi),
  ].filter((match) => !/\bsrc\s*=/.test(match[1]));
  const block = blocks.find((match) => match[2].includes("const DB ="));
  if (!block) {
    throw new Error(
      failure(
        edition,
        "<extract>",
        "inlineScript",
        blocks.length,
        "a script containing const DB",
      ),
    );
  }
  return block[2];
}

function scanBlock(source, openIndex, openChar, closeChar, label) {
  let depth = 0;
  let state = "code";
  let quote = "";

  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];

    if (state === "line-comment") {
      if (char === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (char === "*" && next === "/") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (state === "string") {
      if (char === "\\") {
        index += 1;
      } else if (char === quote) {
        state = "code";
      }
      continue;
    }

    if (char === "/" && next === "/") {
      state = "line-comment";
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      state = "block-comment";
      index += 1;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      state = "string";
      quote = char;
      continue;
    }
    if (char === openChar) depth += 1;
    if (char === closeChar) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  throw new Error(`unterminated ${label}`);
}

function extractFunction(source, name, edition) {
  const pattern = new RegExp(`\\bfunction\\s+${name}\\s*\\(`);
  const match = pattern.exec(source);
  if (!match) {
    throw new Error(
      failure(
        edition,
        "<extract>",
        `function.${name}`,
        "missing",
        "present",
      ),
    );
  }
  const openIndex = source.indexOf("{", match.index + match[0].length);
  const end = scanBlock(source, openIndex, "{", "}", `function ${name}`);
  return source.slice(match.index, end);
}

function extractConst(source, name, edition) {
  const pattern = new RegExp(`\\bconst\\s+${name}\\s*=`);
  const match = pattern.exec(source);
  if (!match) {
    throw new Error(
      failure(
        edition,
        "<extract>",
        `const.${name}`,
        "missing",
        "present",
      ),
    );
  }

  let state = "code";
  let quote = "";
  const depths = { "{": 0, "[": 0, "(": 0 };
  const closing = { "}": "{", "]": "[", ")": "(" };
  for (
    let index = match.index + match[0].length;
    index < source.length;
    index += 1
  ) {
    const char = source[index];
    const next = source[index + 1];
    if (state === "line-comment") {
      if (char === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (char === "*" && next === "/") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (state === "string") {
      if (char === "\\") {
        index += 1;
      } else if (char === quote) {
        state = "code";
      }
      continue;
    }
    if (char === "/" && next === "/") {
      state = "line-comment";
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      state = "block-comment";
      index += 1;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      state = "string";
      quote = char;
      continue;
    }
    if (Object.hasOwn(depths, char)) depths[char] += 1;
    if (Object.hasOwn(closing, char)) depths[closing[char]] -= 1;
    if (
      char === ";" &&
      depths["{"] === 0 &&
      depths["["] === 0 &&
      depths["("] === 0
    ) {
      return source.slice(match.index, index + 1);
    }
  }
  throw new Error(
    failure(
      edition,
      "<extract>",
      `const.${name}`,
      "unterminated",
      "semicolon-terminated declaration",
    ),
  );
}

function buildEditionHarness(edition, pagePath) {
  const html = fs.readFileSync(pagePath, "utf8");
  const source = extractInlineScript(html, edition);
  const renderSource = extractFunction(source, "renderDiagnoseResult", edition);
  const autoVariantMatch =
    /const\s+bAuto\s*=\s*[\s\S]*?\?\s*'([^']+)'\s*:\s*'([^']+)'/.exec(
      renderSource,
    );
  if (!autoVariantMatch) {
    throw new Error(
      failure(
        edition,
        "<extract>",
        "renderDiagnoseResult.bAuto",
        "unparseable",
        "educated/uneducated study-variant keys",
      ),
    );
  }
  const parts = [
    extractConst(source, "DB", edition),
    extractConst(source, "START_FUNDS", edition),
    extractConst(source, "JOB_SAVE", edition),
    extractConst(source, "WHV_SAVE", edition),
    extractConst(source, "ENTRY_LABEL", edition),
    extractConst(source, "ENTRY_ADJUST", edition),
    "const JOURNEYS = {};",
    "let lastDiagnoseResult = null;",
    "let roadmapAdjust = null;",
    extractFunction(source, "recommend", edition),
    extractFunction(source, "runDiagnose", edition),
    extractFunction(source, "moneyPlanRows", edition),
    extractFunction(source, "entryAdjustedPathway", edition),
    extractFunction(source, "resolveBVariant", edition),
    `globalThis.__api = {
      DB,
      START_FUNDS,
      runDiagnose,
      recommend,
      moneyPlanRows,
      entryAdjustedPathway,
      resolveBVariant
    };`,
  ];

  const diagnoseElement = { innerHTML: "" };
  const context = vm.createContext({
    __input: null,
    __rendered: null,
    __consoleErrors: [],
    console: {
      error: (...args) => context.__consoleErrors.push(args.map(String).join(" ")),
      log: () => {},
      warn: () => {},
    },
    document: {
      querySelector(selector) {
        const match = /input\[name="([^"]+)"\]:checked/.exec(selector);
        if (!match) return null;
        return { value: context.__input?.[match[1]] };
      },
      getElementById(id) {
        return id === "diagnoseResult" ? diagnoseElement : null;
      },
    },
    renderDiagnoseResult(result) {
      context.__rendered = result;
    },
    saveState() {},
    injectDiagnoseShareBar() {},
  });

  const script = new vm.Script(parts.join("\n"), {
    filename: `${edition}:diagnosis-extract.js`,
  });
  script.runInContext(context, { timeout: 1000 });
  return {
    context,
    api: context.__api,
    diagnoseElement,
    autoVariants: {
      educated: autoVariantMatch[1],
      uneducated: autoVariantMatch[2],
    },
  };
}

function numericRange(value) {
  if (typeof value !== "string") return null;
  const match = /(-?\d+(?:\.\d+)?)\s*[–~〜～-]\s*(-?\d+(?:\.\d+)?)/.exec(
    value.replaceAll(",", ""),
  );
  if (!match) return null;
  return [Number(match[1]), Number(match[2])];
}

function finiteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function hasInvalidNumericText(value) {
  return (
    typeof value === "string" &&
    /\b(?:NaN|undefined|Infinity)\b/i.test(value)
  );
}

function pickStudyVariant(pathway, input, autoVariants) {
  if (!pathway?.studyVariants) return null;
  return ["bach", "master", "phd"].includes(input.education)
    ? autoVariants.educated
    : autoVariants.uneducated;
}

function runFixture(harness, fixture) {
  const { context, api, diagnoseElement, autoVariants } = harness;
  context.__input = structuredClone(fixture.input);
  context.__rendered = null;
  context.__consoleErrors.length = 0;
  diagnoseElement.innerHTML = "";
  api.runDiagnose();

  if (!context.__rendered) {
    throw new Error(
      failure(
        fixture.edition,
        fixture.id,
        "runDiagnose.rendered",
        {
          rendered: context.__rendered,
          errorHtml: diagnoseElement.innerHTML,
          consoleErrors: context.__consoleErrors,
        },
        "a rendered diagnosis result",
      ),
    );
  }

  const result = structuredClone(context.__rendered);
  const rawPathway = api.DB.pathways.find((item) => item.id === result.primary);
  let pathway = rawPathway;
  const requestedVariant = pickStudyVariant(
    rawPathway,
    fixture.input,
    autoVariants,
  );
  let resolvedVariant = null;
  if (requestedVariant) {
    pathway = api.resolveBVariant(rawPathway, requestedVariant);
    resolvedVariant =
      Object.entries(rawPathway.studyVariants).find(
        ([, value]) => value.stages === pathway.stages,
      )?.[0] ?? null;
  }
  const preEntryPathway = structuredClone(pathway);
  if (pathway) {
    pathway = api.entryAdjustedPathway(pathway, fixture.input.entry || "whv");
  }
  const moneyRows = structuredClone(
    api.moneyPlanRows(result.primary, fixture.input),
  );
  return {
    result,
    rawPathway,
    preEntryPathway,
    pathway: structuredClone(pathway),
    requestedVariant,
    resolvedVariant,
    moneyRows,
  };
}

function validateFixtureShape(fixture) {
  const errors = [];
  for (const field of ["id", "edition", "page", "input", "expected"]) {
    if (!Object.hasOwn(fixture, field)) {
      errors.push(
        failure(
          fixture.edition ?? "<unknown>",
          fixture.id ?? "<unknown>",
          `fixture.${field}`,
          "<missing>",
          "present",
        ),
      );
    }
  }
  if (fixture.input && typeof fixture.input === "object") {
    for (const field of REQUIRED_INPUT_FIELDS) {
      if (typeof fixture.input[field] !== "string" || !fixture.input[field]) {
        errors.push(
          failure(
            fixture.edition ?? "<unknown>",
            fixture.id ?? "<unknown>",
            `input.${field}`,
            fixture.input[field],
            "a non-empty string",
          ),
        );
      }
    }
  }
  return errors;
}

function validateOutcome(fixture, outcome) {
  const errors = [];
  const { edition, id, expected, input } = fixture;
  const { result, rawPathway, preEntryPathway, pathway, moneyRows } = outcome;

  if (result.primary !== expected.primary) {
    errors.push(
      failure(
        edition,
        id,
        "result.primary",
        result.primary,
        expected.primary,
      ),
    );
  }
  if (expected.alt !== undefined && result.alt !== expected.alt) {
    errors.push(
      failure(edition, id, "result.alt", result.alt, expected.alt),
    );
  }
  if (
    expected.studyVariant !== undefined &&
    outcome.resolvedVariant !== expected.studyVariant
  ) {
    errors.push(
      failure(
        edition,
        id,
        "timeline.studyVariant",
        {
          requested: outcome.requestedVariant,
          resolved: outcome.resolvedVariant,
        },
        {
          requested: expected.studyVariant,
          resolved: expected.studyVariant,
        },
        "the automatic selector and DB.studyVariants keys must agree",
      ),
    );
  }
  for (const field of REQUIRED_INPUT_FIELDS) {
    if (result.input?.[field] !== input[field]) {
      errors.push(
        failure(
          edition,
          id,
          `result.input.${field}`,
          result.input?.[field],
          input[field],
        ),
      );
    }
  }
  if ((result.warnings?.length ?? 0) < (expected.minWarnings ?? 0)) {
    errors.push(
      failure(
        edition,
        id,
        "result.warnings.length",
        result.warnings?.length,
        `>= ${expected.minWarnings}`,
      ),
    );
  }
  if (!rawPathway) {
    errors.push(
      failure(
        edition,
        id,
        "DB.pathways[result.primary]",
        result.primary,
        "an existing pathway id",
      ),
    );
    return errors;
  }
  if (!pathway) {
    errors.push(
      failure(edition, id, "timeline.pathway", pathway, "a pathway object"),
    );
    return errors;
  }
  for (const field of ["id", "name", "duration", "cost", "summary"]) {
    if (
      typeof pathway[field] !== "string" ||
      pathway[field].trim().length === 0
    ) {
      errors.push(
        failure(
          edition,
          id,
          `timeline.${field}`,
          pathway[field],
          "a non-empty string",
        ),
      );
    }
    if (hasInvalidNumericText(pathway[field])) {
      errors.push(
        failure(
          edition,
          id,
          `timeline.${field}`,
          pathway[field],
          "text without NaN, undefined, or Infinity",
        ),
      );
    }
  }
  if (!Array.isArray(pathway.stages) || pathway.stages.length === 0) {
    errors.push(
      failure(
        edition,
        id,
        "timeline.stages",
        pathway.stages,
        "a non-empty array",
      ),
    );
  } else {
    pathway.stages.forEach((stage, index) => {
      if (!finiteNumber(stage.months) || stage.months <= 0) {
        errors.push(
          failure(
            edition,
            id,
            `timeline.stages[${index}].months`,
            stage.months,
            "a finite number > 0",
          ),
        );
      }
      if (typeof stage.name !== "string" || !stage.name.trim()) {
        errors.push(
          failure(
            edition,
            id,
            `timeline.stages[${index}].name`,
            stage.name,
            "a non-empty string",
          ),
        );
      }
    });
  }

  const duration = numericRange(pathway.duration);
  if (!duration || !duration.every(Number.isFinite)) {
    errors.push(
      failure(
        edition,
        id,
        "timeline.durationRange",
        pathway.duration,
        "a finite numeric min–max range",
      ),
    );
  } else if (duration[0] > duration[1]) {
    errors.push(
      failure(
        edition,
        id,
        "timeline.duration",
        duration,
        "[min, max] with min <= max",
      ),
    );
  }

  const rawDuration = numericRange(preEntryPathway?.duration);
  if (
    !["whv", "none"].includes(input.entry) &&
    Array.isArray(preEntryPathway?.stages) &&
    preEntryPathway.stages.length > 0
  ) {
    const first = preEntryPathway.stages[0].name;
    const startsWithTemporaryEntry =
      /(?:WHV|IEC|417\s*워홀|ワーキングホリデー)/i.test(first);
    if (
      startsWithTemporaryEntry &&
      pathway.stages.length !== preEntryPathway.stages.length - 1
    ) {
      errors.push(
        failure(
          edition,
          id,
          "timeline.entryAdjustment",
          {
            entry: input.entry,
            rawFirstStage: first,
            rawLength: preEntryPathway.stages.length,
            adjustedLength: pathway.stages.length,
          },
          "the initial WHV/IEC/417 stage removed",
        ),
      );
    }
    if (
      rawDuration &&
      duration &&
      (duration[0] > rawDuration[0] || duration[1] > rawDuration[1])
    ) {
      errors.push(
        failure(
          edition,
          id,
          "timeline.entryDuration",
          { entry: input.entry, adjusted: duration },
          { raw: rawDuration, rule: "adjusted bounds must not increase" },
        ),
      );
    }
  }

  if (!Array.isArray(moneyRows) || moneyRows.length === 0) {
    errors.push(
      failure(
        edition,
        id,
        "money.rows",
        moneyRows,
        "a non-empty array",
      ),
    );
  } else {
    if (Array.isArray(expected.moneyPeriods)) {
      const actualPeriods = moneyRows.map((row) => row.period);
      if (
        JSON.stringify(actualPeriods) !==
        JSON.stringify(expected.moneyPeriods)
      ) {
        errors.push(
          failure(
            edition,
            id,
            "money.periods",
            actualPeriods,
            expected.moneyPeriods,
            "keep route phases aligned with the reviewed study, work, and processing periods",
          ),
        );
      }
    }
    const moneyText = moneyRows
      .flatMap((row) =>
        ["period", "visa", "act", "cash"].map((field) =>
          String(row[field] ?? ""),
        ),
      )
      .join("\n");
    for (const requiredText of expected.moneyIncludes ?? []) {
      if (!moneyText.includes(requiredText)) {
        errors.push(
          failure(
            edition,
            id,
            "money.requiredText",
            moneyText,
            `text containing ${JSON.stringify(requiredText)}`,
            "use the reviewed country-specific fee, work-limit, and duration values",
          ),
        );
      }
    }
    for (const forbiddenText of expected.moneyExcludes ?? []) {
      if (moneyText.includes(forbiddenText)) {
        errors.push(
          failure(
            edition,
            id,
            "money.forbiddenText",
            forbiddenText,
            "absent from all money-plan rows",
            "remove legacy values from the country-specific money plan",
          ),
        );
      }
    }
    const startFunds = outcome.startFunds?.[fixture.input.funding];
    if (!finiteNumber(startFunds)) {
      errors.push(
        failure(
          edition,
          id,
          `money.startFunds.${fixture.input.funding}`,
          startFunds,
          "a finite number",
        ),
      );
    }
    let cumulativeMin = finiteNumber(startFunds) ? startFunds : 0;
    let cumulativeMax = cumulativeMin;
    moneyRows.forEach((row, index) => {
      for (const field of ["period", "visa", "act", "cash"]) {
        if (typeof row[field] !== "string" || !row[field].trim()) {
          errors.push(
            failure(
              edition,
              id,
              `money.rows[${index}].${field}`,
              row[field],
              "a non-empty string",
            ),
          );
        }
        if (hasInvalidNumericText(row[field])) {
          errors.push(
            failure(
              edition,
              id,
              `money.rows[${index}].${field}`,
              row[field],
              "text without NaN, undefined, or Infinity",
            ),
          );
        }
      }
      for (const field of ["dMin", "dMax"]) {
        if (!finiteNumber(row[field])) {
          errors.push(
            failure(
              edition,
              id,
              `money.rows[${index}].${field}`,
              row[field],
              "a finite number",
            ),
          );
        }
      }
      if (
        finiteNumber(row.dMin) &&
        finiteNumber(row.dMax) &&
        row.dMin > row.dMax
      ) {
        errors.push(
          failure(
            edition,
            id,
            `money.rows[${index}].range`,
            [row.dMin, row.dMax],
            "[min, max] with min <= max",
          ),
        );
      }
      cumulativeMin += row.dMin;
      cumulativeMax += row.dMax;
      if (
        !finiteNumber(cumulativeMin) ||
        !finiteNumber(cumulativeMax) ||
        cumulativeMin > cumulativeMax
      ) {
        errors.push(
          failure(
            edition,
            id,
            `money.rows[${index}].cumulativeRange`,
            [cumulativeMin, cumulativeMax],
            "finite [min, max] with min <= max",
          ),
        );
      }
    });
  }
  return errors;
}

function paritySnapshot(outcome) {
  const duration = numericRange(outcome.pathway?.duration);
  return {
    primary: outcome.result.primary,
    alt: outcome.result.alt,
    timelineId: outcome.pathway?.id,
    duration,
    stageMonths: outcome.pathway?.stages?.map((stage) => stage.months),
    moneyRanges: outcome.moneyRows.map((row) => [row.dMin, row.dMax]),
    smc: outcome.result.smc
      ? {
          eduPts: outcome.result.smc.eduPts,
          needYears: outcome.result.smc.needYears,
          exempt: Boolean(outcome.result.smc.exemptReason),
        }
      : null,
  };
}

function validateParity(fixtures, outcomes) {
  const errors = [];
  const groups = new Map();
  for (const fixture of fixtures) {
    if (!fixture.parityKey || !outcomes.has(fixture.id)) continue;
    const group = groups.get(fixture.parityKey) ?? [];
    group.push(fixture);
    groups.set(fixture.parityKey, group);
  }

  for (const [parityKey, group] of groups) {
    const editions = group.map((fixture) => fixture.edition).sort();
    if (
      group.length !== 2 ||
      editions[0] !== "ja" ||
      editions[1] !== "nz"
    ) {
      errors.push(
        failure(
          "nz/ja",
          parityKey,
          "parity.members",
          editions,
          ["ja", "nz"],
        ),
      );
      continue;
    }
    const nzFixture = group.find((fixture) => fixture.edition === "nz");
    const jaFixture = group.find((fixture) => fixture.edition === "ja");
    const baseline = paritySnapshot(outcomes.get(nzFixture.id));
    const actual = paritySnapshot(outcomes.get(jaFixture.id));
    if (JSON.stringify(actual) !== JSON.stringify(baseline)) {
      errors.push(
        failure(
          "nz/ja",
          parityKey,
          "parity.snapshot",
          actual,
          baseline,
        ),
      );
    }
  }
  return errors;
}

function main() {
  const fixturePath = path.resolve(process.argv[2] ?? DEFAULT_FIXTURES);
  let payload;
  try {
    payload = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  } catch (error) {
    console.error(
      failure(
        "<all>",
        "<fixtures>",
        "fixtureFile",
        error.message,
        `valid JSON at ${fixturePath}`,
      ),
    );
    return 1;
  }

  if (payload.schemaVersion !== 1 || !Array.isArray(payload.cases)) {
    console.error(
      failure(
        "<all>",
        "<fixtures>",
        "fixtureSchema",
        {
          schemaVersion: payload.schemaVersion,
          cases: Array.isArray(payload.cases),
        },
        { schemaVersion: 1, cases: true },
      ),
    );
    return 1;
  }

  const errors = [];
  const counts = new Map();
  const harnesses = new Map();
  const outcomes = new Map();
  const ids = new Set();

  for (const fixture of payload.cases) {
    errors.push(...validateFixtureShape(fixture));
    if (ids.has(fixture.id)) {
      errors.push(
        failure(
          fixture.edition,
          fixture.id,
          "fixture.id",
          fixture.id,
          "a unique id",
        ),
      );
    }
    ids.add(fixture.id);
    counts.set(fixture.edition, (counts.get(fixture.edition) ?? 0) + 1);
  }
  for (const edition of ["nz", "ja", "ca", "au"]) {
    if ((counts.get(edition) ?? 0) < 3) {
      errors.push(
        failure(
          edition,
          "<fixtures>",
          "fixture.count",
          counts.get(edition) ?? 0,
          ">= 3",
        ),
      );
    }
  }

  if (errors.length === 0) {
    for (const fixture of payload.cases) {
      try {
        let harness = harnesses.get(fixture.edition);
        if (!harness) {
          harness = buildEditionHarness(
            fixture.edition,
            path.resolve(REPO_ROOT, fixture.page),
          );
          harnesses.set(fixture.edition, harness);
        }
        const outcome = runFixture(harness, fixture);
        outcome.startFunds = harness.api.START_FUNDS;
        outcomes.set(fixture.id, outcome);
        errors.push(...validateOutcome(fixture, outcome));
      } catch (error) {
        errors.push(
          error.message.startsWith("ERROR ")
            ? error.message
            : failure(
                fixture.edition,
                fixture.id,
                "execution",
                error.message,
                "successful VM diagnosis execution",
              ),
        );
      }
    }
    errors.push(...validateParity(payload.cases, outcomes));
  }

  if (errors.length > 0) {
    console.error(`Diagnosis verification failed with ${errors.length} error(s):`);
    for (const error of errors) console.error(error);
    return 1;
  }

  console.log(
    `Diagnosis verification passed: ${payload.cases.length} fixture(s), ` +
      `${harnesses.size} edition(s), ` +
      `${new Set(payload.cases.map((fixture) => fixture.parityKey).filter(Boolean)).size} parity group(s).`,
  );
  return 0;
}

process.exitCode = main();
