import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  assertNoConsoleErrors,
  CleanupStack,
  E2EFailure,
  findBrowser,
  parseMapAsset,
  REVIEWED_CONTRACT,
  startStaticServer,
  validateBaseUrl,
  validateCalculatorSnapshot,
  validateDiagnosisSnapshot,
  validateFixtureRegistry,
  validateMapAssets,
  validateMapSnapshot,
  validateTabSnapshot,
  validateVerificationSnapshot,
  waitForDevTools,
} from "../scripts/verify_browser_e2e.mjs";

const FIXTURE_PATH = new URL("./fixtures/browser-e2e-cases.json", import.meta.url);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function validTabSnapshot(edition = "nz", clicked = "home") {
  const labels = REVIEWED_CONTRACT.editions[edition].tabs;
  return {
    clicked,
    title: REVIEWED_CONTRACT.editions[edition].title,
    labels,
    tabCount: 6,
    panelCount: 6,
    activeTabs: 1,
    activeTabIds: [clicked],
    activePanels: 1,
    hash: `#${clicked}`,
    panels: ["home", "diagnose", "jobs", "settle", "scenarios", "snapshot"]
      .map((id) => ({
        id,
        count: 1,
        active: id === clicked,
        hidden: id !== clicked,
        ariaHidden: id === clicked ? null : "true",
        display: id === clicked ? "block" : "none",
        textLength: id === clicked ? 20 : 10,
      })),
    innerWidth: 375,
    scrollWidth: 375,
  };
}

function validMapSnapshot(country = "NZ") {
  const au = country === "AU";
  return {
    assetCount: au ? 113 : 187,
    uniqueIds: au ? 113 : 187,
    countryCount: au ? 113 : 187,
    directoryOnlyCount: au ? 113 : 187,
    innerWidth: 375,
    scrollWidth: 375,
    sourceFilterCount: 1,
    statusFilterCount: 1,
    precisionFilterCount: 1,
    sourceOptionCount: 3,
    statusOptionCount: 4,
    precisionOptionCount: 4,
    listCount: 1,
    listRole: "list",
    listItemCount: au ? 12 : 20,
    warning: "실시간 공고가 아닌 사업체 디렉터리",
    filteredSource: au ? "government-job-gateway" : "industry-association",
    filteredListItems: au ? 12 : 20,
    monthButtonCount: au ? 13 : 0,
    monthPressedCount: au ? 1 : 0,
    pressedMonth: au ? "1" : "",
    exampleButtonCount: au ? 6 : 0,
    examplePostcode: au ? "4670" : "",
    exampleState: au ? "QLD" : "",
    exampleResultCount: au ? 1 : 0,
    gatewayNoneCount: au ? 12 : 0,
    gatewayBadgeCount: au ? 12 : 0,
  };
}

function fakeChild() {
  const child = new EventEmitter();
  child.stderr = new PassThrough();
  return child;
}

function request(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    }).on("error", reject);
  });
}

test("fixture registry accepts only every reviewed enum exactly once", () => {
  const registry = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  assert.equal(validateFixtureRegistry(registry), registry);

  for (const mutation of [
    (value) => value.suites.tabs.pop(),
    (value) => { value.suites.tabs[0] = value.suites.tabs[1]; },
    (value) => value.suites.diagnosis.push("arbitrary-selector"),
    (value) => { value.extra = true; },
  ]) {
    const bad = clone(registry);
    mutation(bad);
    assert.throws(() => validateFixtureRegistry(bad), E2EFailure);
  }
});

test("base URL and browser paths are code-owned allowlists", () => {
  assert.equal(
    validateBaseUrl("https://wonchance-art.github.io/nz-navigator/"),
    "https://wonchance-art.github.io/nz-navigator/",
  );
  assert.throws(
    () => validateBaseUrl("https://example.invalid/nz-navigator/"),
    /step=base-url/,
  );
  assert.equal(
    findBrowser(null, (candidate) => candidate === "/usr/bin/chromium"),
    "/usr/bin/chromium",
  );
  assert.throws(() => findBrowser(null, () => false), /browser-discovery/);
  assert.throws(
    () => findBrowser("/tmp/unreviewed-browser", () => true),
    /browser-path/,
  );
});

test("tab contract accepts the reviewed visible/hidden state", () => {
  assert.doesNotThrow(() =>
    validateTabSnapshot("nz", "tabs-nz", validTabSnapshot())
  );
});

test("duplicate or missing tabs and panels fail closed", () => {
  for (const patch of [
    { tabCount: 7 },
    { tabCount: 5 },
    { panelCount: 7 },
    { panelCount: 5 },
    { activeTabs: 2 },
    { activePanels: 0 },
    { activeTabIds: ["jobs"] },
  ]) {
    assert.throws(
      () => validateTabSnapshot(
        "nz",
        "tabs-nz",
        { ...validTabSnapshot(), ...patch },
      ),
      E2EFailure,
    );
  }
});

test("wrong hidden, aria-hidden, display, and hash fail closed", () => {
  for (const mutate of [
    (snapshot) => { snapshot.panels[1].hidden = false; },
    (snapshot) => { snapshot.panels[1].ariaHidden = null; },
    (snapshot) => { snapshot.panels[1].display = "block"; },
    (snapshot) => { snapshot.hash = "#jobs"; },
  ]) {
    const snapshot = validTabSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateTabSnapshot("nz", "tabs-nz", snapshot),
      E2EFailure,
    );
  }
});

test("mobile horizontal overflow fails closed", () => {
  const snapshot = validTabSnapshot();
  snapshot.scrollWidth = 376;
  assert.throws(
    () => validateTabSnapshot("nz", "tabs-nz", snapshot),
    /viewport-overflow/,
  );
});

test("map asset literals and registry parity fail closed", () => {
  const rows = Array.from({ length: 187 }, (_, index) => ({
    id: `nz-reviewed-${index}`,
    country: "NZ",
    vacancyStatus: "directory-only",
  }));
  const registry = {
    generatedAt: "2026-07-19",
    employers: rows,
  };
  const meta = {
    schemaVersion: 1,
    generatedAt: "2026-07-19",
    count: 187,
  };
  assert.doesNotThrow(() =>
    validateMapAssets("nz-employers-map", registry, rows, meta)
  );
  const source =
    "/* generated */\n" +
    `window.NZ_EMPLOYERS=Object.freeze(${JSON.stringify(rows)});\n` +
    `window.NZ_EMPLOYER_REGISTRY_META=Object.freeze(${JSON.stringify(meta)});`;
  assert.deepEqual(parseMapAsset("nz-employers-map", source), { rows, meta });

  const duplicate = clone(rows);
  duplicate[1].id = duplicate[0].id;
  assert.throws(
    () => validateMapAssets("nz-employers-map", registry, duplicate, meta),
    /asset-count/,
  );
  assert.throws(
    () => parseMapAsset("nz-employers-map", `${source}\nalert(1);`),
    /asset-literal/,
  );
  assert.throws(
    () => parseMapAsset(
      "nz-employers-map",
      source.replace('"directory-only"', "(() => 'directory-only')()"),
    ),
    /asset-json/,
  );
});

test("map DOM contract covers filters, overflow, buttons, and gateway safety", () => {
  assert.doesNotThrow(() =>
    validateMapSnapshot("nz-employers-map", validMapSnapshot("NZ"))
  );
  assert.doesNotThrow(() =>
    validateMapSnapshot("au-employers-map", validMapSnapshot("AU"))
  );

  for (const mutate of [
    (snapshot) => { snapshot.scrollWidth = 376; },
    (snapshot) => { snapshot.sourceFilterCount = 0; },
    (snapshot) => { snapshot.listRole = ""; },
    (snapshot) => { snapshot.warning = "current vacancies"; },
  ]) {
    const snapshot = validMapSnapshot("NZ");
    mutate(snapshot);
    assert.throws(
      () => validateMapSnapshot("nz-employers-map", snapshot),
      E2EFailure,
    );
  }
  for (const mutate of [
    (snapshot) => { snapshot.monthButtonCount = 12; },
    (snapshot) => { snapshot.monthPressedCount = 2; },
    (snapshot) => { snapshot.exampleButtonCount = 0; },
    (snapshot) => { snapshot.gatewayNoneCount = 11; },
    (snapshot) => { snapshot.gatewayBadgeCount = 0; },
  ]) {
    const snapshot = validMapSnapshot("AU");
    mutate(snapshot);
    assert.throws(
      () => validateMapSnapshot("au-employers-map", snapshot),
      /au-interactions/,
    );
  }
});

test("stale or duplicate diagnosis selectors fail closed", () => {
  const base = {
    resultCardCount: 1,
    titleCount: 1,
    title: REVIEWED_CONTRACT.diagnosisCases["nz-student"].title,
    timelineCount: 1,
    timeline: [
      "학업(학사 3년)",
      "졸업비자→고용주 워크비자 근무",
      "6점제 영주권 처리",
    ],
    moneyTableCount: 1,
    moneyRows: 3,
    text: "학생비자 진입 실행·머니 플랜",
    primary: "B",
    alt: null,
  };
  assert.doesNotThrow(() => validateDiagnosisSnapshot("nz-student", base));
  assert.throws(
    () => validateDiagnosisSnapshot(
      "nz-student",
      { ...base, resultCardCount: 0 },
    ),
    /result-cardinality/,
  );
  assert.throws(
    () => validateDiagnosisSnapshot(
      "nz-student",
      { ...base, titleCount: 2 },
    ),
    /result-cardinality/,
  );
});

test("wrong calculator output and non-finite UI text fail closed", () => {
  assert.doesNotThrow(() =>
    validateCalculatorSnapshot("nz-netpay", {
      outputCount: 1,
      text: "실수령: 연 57,466",
    })
  );
  assert.throws(
    () => validateCalculatorSnapshot("nz-netpay", {
      outputCount: 1,
      text: "실수령: 연 57,465",
    }),
    /calculator-output/,
  );
  assert.throws(
    () => validateCalculatorSnapshot("nz-netpay", {
      outputCount: 1,
      text: "실수령: 연 57,466 NaN",
    }),
    /finite-output/,
  );
});

test("verification source and lineage audit or v10 history drift fails closed", () => {
  const expected = REVIEWED_CONTRACT.verificationCases["trust-v10"];
  const snapshot = {
    audit: clone(expected.audit),
    gateCount: 2,
    gateText: Object.values(expected.audit).join(" "),
    historyMatches: 1,
  };
  assert.doesNotThrow(() =>
    validateVerificationSnapshot("trust-v10", snapshot)
  );
  const drift = clone(snapshot);
  drift.audit.sourceAttestations = "51";
  assert.throws(
    () => validateVerificationSnapshot("trust-v10", drift),
    /step=audit/,
  );
  assert.throws(
    () => validateVerificationSnapshot(
      "trust-v10",
      { ...snapshot, historyMatches: 0 },
    ),
    /v10-history/,
  );
});

test("console errors and exceptions are never suppressed", () => {
  assert.doesNotThrow(() => assertNoConsoleErrors([], "nz", "tabs-nz"));
  assert.throws(
    () => assertNoConsoleErrors(
      [{ type: "error", text: "boom" }],
      "nz",
      "tabs-nz",
    ),
    /step=console/,
  );
});

test("DevTools wait detects readiness, browser crash, and timeout", async () => {
  const ready = fakeChild();
  const readyPromise = waitForDevTools(ready, 100);
  ready.stderr.write("DevTools listening on ws://127.0.0.1:123/devtools/browser/id\n");
  assert.equal(
    await readyPromise,
    "ws://127.0.0.1:123/devtools/browser/id",
  );

  const crashed = fakeChild();
  const crashPromise = waitForDevTools(crashed, 100);
  crashed.emit("exit", 9, null);
  await assert.rejects(crashPromise, /Chrome exited before CDP was ready/);

  const timedOut = fakeChild();
  await assert.rejects(
    waitForDevTools(timedOut, 5),
    /Chrome DevTools endpoint timeout/,
  );
});

test("cleanup runs every task in reverse order after a cleanup failure", async () => {
  const order = [];
  const cleanup = new CleanupStack();
  cleanup.use(async () => { order.push("server"); });
  cleanup.use(async () => {
    order.push("profile");
    throw new Error("profile cleanup failed");
  });
  cleanup.use(async () => { order.push("browser"); });
  await assert.rejects(cleanup.cleanup(), /profile cleanup failed/);
  assert.deepEqual(order, ["browser", "profile", "server"]);
  assert.deepEqual(cleanup.tasks, []);
});

test("static server is loopback-only, no-store, and path-contained", async () => {
  const root = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), "browser-e2e-server-test-"),
  );
  await fs.promises.writeFile(path.join(root, "index.html"), "reviewed", "utf8");
  const server = await startStaticServer(root);
  try {
    assert.equal(new URL(server.baseUrl).hostname, "127.0.0.1");
    const page = await request(server.baseUrl);
    assert.equal(page.status, 200);
    assert.equal(page.headers["cache-control"], "no-store");
    assert.equal(page.body, "reviewed");
    const missing = await request(new URL("missing.html", server.baseUrl));
    assert.equal(missing.status, 404);
  } finally {
    await server.close();
    await fs.promises.rm(root, { recursive: true, force: true });
  }
});
