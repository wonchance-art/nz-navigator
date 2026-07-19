#!/usr/bin/env node

import childProcess from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const DEFAULT_ROOT = path.resolve(path.dirname(SCRIPT_PATH), "..");
const FIXTURE_PATH = "tests/fixtures/browser-e2e-cases.json";
const LIVE_BASE_URL = "https://wonchance-art.github.io/nz-navigator/";
const VIEWPORT = Object.freeze({ width: 375, height: 812 });
const TAB_IDS = Object.freeze([
  "home",
  "diagnose",
  "jobs",
  "settle",
  "scenarios",
  "snapshot",
]);
const INPUT_FIELDS = Object.freeze([
  "entry",
  "age",
  "job",
  "experience",
  "english",
  "funding",
  "education",
  "family",
]);
const BROWSER_PATHS = Object.freeze([
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
]);
const DEFAULT_TIMEOUT_MS = 10_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 30_000;

const EDITIONS = Object.freeze({
  nz: Object.freeze({
    page: "nz/",
    title: "NZ NAVI",
    tabs: ["홈", "로드맵", "직군", "정착", "시나리오", "정책 현황"],
  }),
  ja: Object.freeze({
    page: "ja/",
    title: "NZ NAVI",
    tabs: ["ホーム", "ロードマップ", "職種", "定住", "シナリオ", "政策動向"],
  }),
  ca: Object.freeze({
    page: "ca/",
    title: "CA NAVI",
    tabs: ["홈", "로드맵", "직군", "정착", "시나리오", "정책 현황"],
  }),
  au: Object.freeze({
    page: "au/",
    title: "AU NAVI",
    tabs: ["홈", "로드맵", "직군", "정착", "시나리오", "정책 현황"],
  }),
});

const NZ_STUDENT_INPUT = Object.freeze({
  entry: "student",
  age: "under30",
  job: "undecided",
  experience: "none",
  english: "none",
  funding: "high",
  education: "none",
  family: "solo",
});
const NZ_NONE_INPUT = Object.freeze({
  ...NZ_STUDENT_INPUT,
  entry: "none",
});

const DIAGNOSIS_CASES = Object.freeze({
  "nz-student": Object.freeze({
    edition: "nz",
    input: NZ_STUDENT_INPUT,
    primary: "B",
    alt: null,
    title: "당신의 추천 경로: B. 유학 경유 (워홀→학업→졸업비자→고용주 워크비자→6점제 영주권)",
    timelineIncludes: ["학업(학사 3년)", "졸업비자→고용주 워크비자 근무", "6점제 영주권 처리"],
    timelineExcludes: ["워홀"],
    resultIncludes: ["학생비자 진입", "실행·머니 플랜"],
  }),
  "ja-student": Object.freeze({
    edition: "ja",
    input: NZ_STUDENT_INPUT,
    primary: "B",
    alt: null,
    title: "あなたの推奨経路: B. 留学経由（ワーホリ→学業→卒業後就労ビザ→雇用主就労ビザ→6点制永住権）",
    timelineIncludes: ["学業（学士 3年）", "卒業後就労ビザ→雇用主就労ビザ勤務", "6点制永住権処理"],
    timelineExcludes: ["ワーホリ"],
    resultIncludes: ["学生ビザ進入", "実行・マネープラン"],
  }),
  "nz-none": Object.freeze({
    edition: "nz",
    input: NZ_NONE_INPUT,
    primary: "B",
    alt: null,
    title: "당신의 추천 경로: B. 유학 경유 (워홀→학업→졸업비자→고용주 워크비자→6점제 영주권)",
    timelineIncludes: ["워홀", "학업(학사 3년)", "졸업비자→고용주 워크비자 근무"],
    timelineExcludes: [],
    resultIncludes: ["진입 비자 추천", "유학(학생비자)", "실행·머니 플랜"],
  }),
  "ja-none": Object.freeze({
    edition: "ja",
    input: NZ_NONE_INPUT,
    primary: "B",
    alt: null,
    title: "あなたの推奨経路: B. 留学経由（ワーホリ→学業→卒業後就労ビザ→雇用主就労ビザ→6点制永住権）",
    timelineIncludes: ["ワーホリ", "学業（学士 3年）", "卒業後就労ビザ→雇用主就労ビザ勤務"],
    timelineExcludes: [],
    resultIncludes: ["進入ビザ推奨", "留学(学生ビザ)", "実行・マネープラン"],
  }),
  "ca-cec": Object.freeze({
    edition: "ca",
    input: Object.freeze({
      entry: "whv",
      age: "under30",
      job: "dev",
      experience: "over2",
      english: "ielts65",
      funding: "mid",
      education: "bach",
      family: "solo",
    }),
    primary: "A",
    alt: null,
    title: "당신의 추천 경로: A. 워홀 직행 (IEC 워홀 → 1년 경력 → 캐나다 경험류)",
    timelineIncludes: ["IEC 워홀 Working Holiday", "직장 경력", "캐나다 경험류 신청"],
    timelineExcludes: [],
    resultIncludes: ["캐나다 경험류", "실행·머니 플랜"],
  }),
  "ca-work": Object.freeze({
    edition: "ca",
    input: Object.freeze({
      entry: "work",
      age: "over30",
      job: "trade",
      experience: "over2",
      english: "ielts65",
      funding: "mid",
      education: "bach",
      family: "partner",
    }),
    primary: "C-PNP",
    alt: null,
    title: "당신의 추천 경로: C. 주 지명 프로그램 경로 (주정부 지명 +600점)",
    timelineIncludes: ["주 지명 프로그램 지원", "주 지명 프로그램 지명", "Express Entry 신청"],
    timelineExcludes: ["IEC 워홀 Working Holiday"],
    resultIncludes: ["Work Permit(워크비자) 진입", "실행·머니 플랜"],
  }),
  "au-sid": Object.freeze({
    edition: "au",
    input: Object.freeze({
      entry: "work",
      age: "over35",
      job: "trade",
      experience: "over2",
      english: "ielts7",
      funding: "mid",
      education: "bach",
      family: "partner",
    }),
    primary: "D",
    alt: "C-189",
    title: "당신의 추천 경로: D. 고용주 스폰서 (482 → 186)",
    timelineIncludes: ["고용주 스폰서십·482 지명·비자 승인", "482로 적격 스폰서 근무", "186 승인"],
    timelineExcludes: ["417 첫 해"],
    resultIncludes: ["워크비자(482 기술 비자 · 482) 보유 진입", "실행·머니 플랜"],
  }),
});

const CALCULATOR_CASES = Object.freeze({
  "nz-netpay": Object.freeze({
    edition: "nz",
    kind: "netpay",
    section: "jobs",
    input: Object.freeze({ salary: "72800" }),
    expected: "실수령: 연 57,466",
  }),
  "ca-netpay-on": Object.freeze({
    edition: "ca",
    kind: "netpay",
    section: "jobs",
    input: Object.freeze({ salary: "60000", mode: "on" }),
    expected: "실수령: 연 47,340",
  }),
  "ca-crs": Object.freeze({
    edition: "ca",
    kind: "crs",
    section: "diagnose",
    input: Object.freeze({
      age: "a35",
      education: "e120",
      language: "l7",
      experience: "x1",
    }),
    expected: "core 305점",
  }),
  "au-netpay-whm": Object.freeze({
    edition: "au",
    kind: "netpay",
    section: "jobs",
    input: Object.freeze({ salary: "52115", mode: "whm" }),
    expected: "실수령: 연 43,231",
  }),
  "au-netpay-resident": Object.freeze({
    edition: "au",
    kind: "netpay",
    section: "jobs",
    input: Object.freeze({ salary: "60000", mode: "resident" }),
    expected: "실수령: 연 50,380",
  }),
});

const VERIFICATION_CASES = Object.freeze({
  "trust-v10": Object.freeze({
    audit: Object.freeze({
      sourceAttestations: "101",
      attestedClaims: "118",
      attestedLeaves: "136",
      liveCapable: "101",
      liveExtractable: "98",
      fixtureOnly: "3",
      lineageDerived: "11",
      lineageMapped: "11",
      lineageExecuted: "11",
      lineageInputs: "23",
      criticalRemaining: "0",
    }),
    historyIncludes: "2026-07-19 · 신뢰 기반 v10:",
  }),
});

export class E2EFailure extends Error {
  constructor(edition, fixture, step, actual, expected, fix) {
    const show = (value) => {
      try {
        return JSON.stringify(value);
      } catch {
        return String(value);
      }
    };
    super(
      `ERROR edition=${edition} fixture=${fixture} step=${step} ` +
      `actual=${show(actual)} expected=${show(expected)} Fix: ${fix}`,
    );
    this.name = "E2EFailure";
    this.edition = edition;
    this.fixture = fixture;
    this.step = step;
  }
}

function fail(edition, fixture, step, actual, expected, fix) {
  throw new E2EFailure(edition, fixture, step, actual, expected, fix);
}

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === [...keys].sort().join("\0")
  );
}

function exactEnumArray(value, allowed) {
  return (
    Array.isArray(value) &&
    value.length === allowed.length &&
    new Set(value).size === value.length &&
    value.every((item) => typeof item === "string" && allowed.includes(item)) &&
    allowed.every((item) => value.includes(item))
  );
}

export function validateFixtureRegistry(registry) {
  if (
    !exactKeys(registry, ["schemaVersion", "suites"]) ||
    registry.schemaVersion !== 1 ||
    !exactKeys(registry.suites, [
      "tabs",
      "diagnosis",
      "calculators",
      "verification",
    ])
  ) {
    fail(
      "<registry>",
      "<schema>",
      "fixture-root",
      registry,
      "schemaVersion 1 and exact suites object",
      "Restore the reviewed browser fixture root; arbitrary fields are forbidden.",
    );
  }
  const contracts = [
    ["tabs", Object.keys(EDITIONS)],
    ["diagnosis", Object.keys(DIAGNOSIS_CASES)],
    ["calculators", Object.keys(CALCULATOR_CASES)],
    ["verification", Object.keys(VERIFICATION_CASES)],
  ];
  for (const [name, allowed] of contracts) {
    if (!exactEnumArray(registry.suites[name], allowed)) {
      fail(
        "<registry>",
        "<schema>",
        `suite-${name}`,
        registry.suites[name],
        allowed,
        "Use every code-reviewed fixture enum exactly once.",
      );
    }
  }
  return registry;
}

export function validateBaseUrl(value) {
  if (value !== LIVE_BASE_URL) {
    fail(
      "<browser>",
      "<cli>",
      "base-url",
      value,
      LIVE_BASE_URL,
      "Use the exact reviewed Pages origin or omit --base-url for local checkout.",
    );
  }
  return value;
}

export function findBrowser(explicitPath = null, exists = fs.existsSync) {
  if (explicitPath !== null) {
    if (!BROWSER_PATHS.includes(explicitPath) || !exists(explicitPath)) {
      fail(
        "<browser>",
        "<launch>",
        "browser-path",
        explicitPath,
        BROWSER_PATHS,
        "Install Chrome/Chromium at a code-owned path or choose an existing allowlisted binary.",
      );
    }
    return explicitPath;
  }
  const detected = BROWSER_PATHS.find((candidate) => exists(candidate));
  if (!detected) {
    fail(
      "<browser>",
      "<launch>",
      "browser-discovery",
      "not found",
      BROWSER_PATHS,
      "Install an allowlisted Chrome/Chromium binary; browser absence fails closed.",
    );
  }
  return detected;
}

export function validateTabSnapshot(edition, fixture, snapshot) {
  const spec = EDITIONS[edition];
  if (!spec) fail(edition, fixture, "edition", edition, Object.keys(EDITIONS), "Use a reviewed edition enum.");
  if (snapshot.title !== spec.title) {
    fail(edition, fixture, "title", snapshot.title, spec.title, "Restore the reviewed document title.");
  }
  if (JSON.stringify(snapshot.labels) !== JSON.stringify(spec.tabs)) {
    fail(edition, fixture, "tab-labels", snapshot.labels, spec.tabs, "Restore exactly six reviewed tab labels and order.");
  }
  if (snapshot.tabCount !== 6 || snapshot.panelCount !== 6) {
    fail(edition, fixture, "tab-cardinality", { tabs: snapshot.tabCount, panels: snapshot.panelCount }, { tabs: 6, panels: 6 }, "Remove duplicate tabs/panels or restore the missing reviewed element.");
  }
  if (
    snapshot.activeTabs !== 1 ||
    snapshot.activePanels !== 1 ||
    snapshot.activeTabIds?.length !== 1 ||
    snapshot.activeTabIds[0] !== snapshot.clicked
  ) {
    fail(
      edition,
      fixture,
      "active-cardinality",
      {
        tabs: snapshot.activeTabs,
        tabIds: snapshot.activeTabIds,
        panels: snapshot.activePanels,
      },
      { tabs: 1, tabIds: [snapshot.clicked], panels: 1 },
      "Ensure the clicked tab and its panel are the only active controls.",
    );
  }
  if (snapshot.hash !== `#${snapshot.clicked}`) {
    fail(edition, fixture, "hash", snapshot.hash, `#${snapshot.clicked}`, "Keep click routing and URL hash synchronized.");
  }
  for (const panel of snapshot.panels) {
    const active = panel.id === snapshot.clicked;
    const valid = active
      ? panel.active && !panel.hidden && panel.ariaHidden === null && panel.display !== "none" && panel.textLength > 0
      : !panel.active && panel.hidden && panel.ariaHidden === "true" && panel.display === "none";
    if (!valid) {
      fail(
        edition,
        fixture,
        `panel-${panel.id}`,
        panel,
        active ? "visible, nonempty active panel" : "hidden + aria-hidden=true + display:none",
        "Restore showSection hidden/ARIA/display behavior for all six panels.",
      );
    }
  }
  if (snapshot.innerWidth !== VIEWPORT.width || snapshot.scrollWidth > VIEWPORT.width) {
    fail(
      edition,
      fixture,
      "viewport-overflow",
      { innerWidth: snapshot.innerWidth, scrollWidth: snapshot.scrollWidth },
      { innerWidth: VIEWPORT.width, maxScrollWidth: VIEWPORT.width },
      "Constrain the active tab content to the 375px viewport.",
    );
  }
}

export function validateDiagnosisSnapshot(caseId, snapshot) {
  const spec = DIAGNOSIS_CASES[caseId];
  if (!spec) fail("<diagnosis>", caseId, "case-enum", caseId, Object.keys(DIAGNOSIS_CASES), "Use a reviewed diagnosis enum.");
  if (snapshot.resultCardCount !== 1 || snapshot.titleCount !== 1) {
    fail(spec.edition, caseId, "result-cardinality", snapshot, { resultCardCount: 1, titleCount: 1 }, "Restore one rendered diagnosis result card and title.");
  }
  if (snapshot.primary !== spec.primary || snapshot.alt !== spec.alt) {
    fail(spec.edition, caseId, "recommendation", { primary: snapshot.primary, alt: snapshot.alt }, { primary: spec.primary, alt: spec.alt }, "Review the diagnosis input wiring or recommendation regression.");
  }
  if (snapshot.title !== spec.title) {
    fail(spec.edition, caseId, "result-title", snapshot.title, spec.title, "Restore the reviewed rendered recommendation title.");
  }
  if (
    snapshot.timelineCount !== 1 ||
    snapshot.timeline.length < 2 ||
    snapshot.moneyTableCount !== 1 ||
    snapshot.moneyRows < 2
  ) {
    fail(spec.edition, caseId, "structured-output", snapshot, "one nonempty timeline and one multi-row money plan", "Restore rendered timeline and money-plan structures.");
  }
  for (const text of spec.timelineIncludes) {
    if (!snapshot.timeline.some((item) => item.includes(text))) {
      fail(spec.edition, caseId, "timeline-include", snapshot.timeline, text, "Restore the reviewed pathway stages.");
    }
  }
  for (const text of spec.timelineExcludes) {
    if (snapshot.timeline.some((item) => item.includes(text))) {
      fail(spec.edition, caseId, "timeline-exclude", snapshot.timeline, `no ${text}`, "Keep entry-adjusted stages out of the rendered timeline.");
    }
  }
  for (const text of spec.resultIncludes) {
    if (!snapshot.text.includes(text)) {
      fail(spec.edition, caseId, "result-text", snapshot.text, text, "Restore the reviewed diagnosis explanation or money plan.");
    }
  }
  if (/NaN|undefined/.test(snapshot.text)) {
    fail(spec.edition, caseId, "finite-output", snapshot.text, "no NaN/undefined", "Fix the runtime calculation before rendering.");
  }
}

export function validateCalculatorSnapshot(caseId, snapshot) {
  const spec = CALCULATOR_CASES[caseId];
  if (!spec) fail("<calculator>", caseId, "case-enum", caseId, Object.keys(CALCULATOR_CASES), "Use a reviewed calculator enum.");
  if (snapshot.outputCount !== 1 || typeof snapshot.text !== "string" || !snapshot.text.includes(spec.expected)) {
    fail(spec.edition, caseId, "calculator-output", snapshot, { outputCount: 1, includes: spec.expected }, "Restore the calculator event wiring or reviewed result.");
  }
  if (/NaN|undefined/.test(snapshot.text)) {
    fail(spec.edition, caseId, "finite-output", snapshot.text, "no NaN/undefined", "Fix the calculator before rendering.");
  }
}

export function validateVerificationSnapshot(caseId, snapshot) {
  const spec = VERIFICATION_CASES[caseId];
  if (!spec) fail("verification", caseId, "case-enum", caseId, Object.keys(VERIFICATION_CASES), "Use a reviewed verification enum.");
  if (JSON.stringify(snapshot.audit) !== JSON.stringify(spec.audit)) {
    fail("verification", caseId, "audit", snapshot.audit, spec.audit, "Restore the public v10 source and lineage audit counters from claims.json.");
  }
  if (snapshot.gateCount !== 2 || !Object.values(spec.audit).every((value) => snapshot.gateText.includes(value))) {
    fail("verification", caseId, "trust-gates", snapshot, "source and lineage gates containing all eleven audit values", "Restore the rendered source-attestation and claim-lineage gates.");
  }
  if (snapshot.historyMatches !== 1) {
    fail("verification", caseId, "v10-history", snapshot.historyMatches, 1, "Restore exactly one v10 trust history entry.");
  }
}

export function assertNoConsoleErrors(errors, edition, fixture) {
  if (errors.length) {
    fail(
      edition,
      fixture,
      "console",
      errors,
      [],
      "Resolve the page console error/exception; E2E never suppresses it.",
    );
  }
}

export class CleanupStack {
  constructor() {
    this.tasks = [];
  }

  use(task) {
    this.tasks.push(task);
  }

  async cleanup() {
    const errors = [];
    for (const task of this.tasks.reverse()) {
      try {
        await task();
      } catch (error) {
        errors.push(error);
      }
    }
    this.tasks = [];
    if (errors.length) throw errors[0];
  }
}

function mimeType(filename) {
  const extension = path.extname(filename).toLowerCase();
  return {
    ".html": "text/html; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
  }[extension] || "application/octet-stream";
}

export async function startStaticServer(root) {
  const realRoot = await fs.promises.realpath(root);
  const server = http.createServer(async (request, response) => {
    try {
      if (!["GET", "HEAD"].includes(request.method || "")) {
        response.writeHead(405, { Allow: "GET, HEAD" }).end();
        return;
      }
      const requestUrl = new URL(request.url || "/", "http://127.0.0.1");
      if (requestUrl.pathname === "/favicon.ico") {
        response.writeHead(204).end();
        return;
      }
      let decoded;
      try {
        decoded = decodeURIComponent(requestUrl.pathname);
      } catch {
        response.writeHead(400).end();
        return;
      }
      let candidate = path.resolve(realRoot, `.${decoded}`);
      if (decoded.endsWith("/")) candidate = path.join(candidate, "index.html");
      let realCandidate;
      try {
        realCandidate = await fs.promises.realpath(candidate);
      } catch {
        response.writeHead(404).end();
        return;
      }
      if (realCandidate !== realRoot && !realCandidate.startsWith(`${realRoot}${path.sep}`)) {
        response.writeHead(403).end();
        return;
      }
      const stat = await fs.promises.stat(realCandidate);
      if (!stat.isFile()) {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, {
        "Content-Type": mimeType(realCandidate),
        "Content-Length": stat.size,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      if (request.method === "HEAD") response.end();
      else fs.createReadStream(realCandidate).pipe(response);
    } catch {
      response.writeHead(500).end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("static server has no TCP address");
  return {
    baseUrl: `http://127.0.0.1:${address.port}/`,
    close: () => {
      server.closeAllConnections?.();
      return new Promise((resolve, reject) =>
        server.close((error) => error ? reject(error) : resolve())
      );
    },
  };
}

export function waitForDevTools(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => {
      finish(new Error("Chrome DevTools endpoint timeout"));
    }, timeoutMs);
    const onData = (chunk) => {
      buffer += String(chunk);
      const match = /DevTools listening on (ws:\/\/[^\s]+)/.exec(buffer);
      if (match) finish(null, match[1]);
      if (buffer.length > 32_000) buffer = buffer.slice(-16_000);
    };
    const onExit = (code, signal) => {
      finish(new Error(`Chrome exited before CDP was ready: code=${code} signal=${signal}`));
    };
    const onError = (error) => finish(error);
    const finish = (error, value) => {
      clearTimeout(timer);
      child.stderr?.off("data", onData);
      child.off("exit", onExit);
      child.off("error", onError);
      if (error) reject(error);
      else resolve(value);
    };
    child.stderr?.on("data", onData);
    child.once("exit", onExit);
    child.once("error", onError);
  });
}

async function terminateProcess(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const waitForExit = (timeoutMs) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      return Promise.resolve(true);
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.off("exit", onExit);
        resolve(false);
      }, timeoutMs);
      const onExit = () => {
        clearTimeout(timer);
        resolve(true);
      };
      child.once("exit", onExit);
    });
  };
  const exited = await waitForExit(1_500);
  if (!exited && child.exitCode === null) {
    child.kill("SIGKILL");
    await waitForExit(1_500);
  }
}

function connectWebSocket(url, timeoutMs) {
  if (typeof WebSocket !== "function") {
    throw new Error("Node 22 built-in WebSocket is required");
  }
  const socket = new WebSocket(url);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error("CDP WebSocket connection timeout"));
    }, timeoutMs);
    socket.addEventListener("open", () => {
      clearTimeout(timer);
      resolve(socket);
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error("CDP WebSocket connection failed"));
    }, { once: true });
  });
}

class CdpClient {
  constructor(socket, timeoutMs) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    socket.addEventListener("message", (event) => this.onMessage(event.data));
    socket.addEventListener("close", () => this.onClose());
  }

  onMessage(raw) {
    let message;
    try {
      message = JSON.parse(String(raw));
    } catch {
      return;
    }
    if (message.id !== undefined) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(`CDP ${pending.method}: ${message.error.message}`));
      else pending.resolve(message.result || {});
      return;
    }
    for (const listener of this.listeners) listener(message);
  }

  onClose() {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`CDP closed during ${pending.method}`));
    }
    this.pending.clear();
  }

  send(method, params = {}, sessionId = undefined) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId !== undefined) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP command timeout: ${method}`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer, method });
      this.socket.send(JSON.stringify(message));
    });
  }

  waitForEvent(method, sessionId, predicate = () => true) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.listeners.delete(listener);
        reject(new Error(`CDP event timeout: ${method}`));
      }, this.timeoutMs);
      const listener = (message) => {
        if (
          message.method === method &&
          (sessionId === undefined || message.sessionId === sessionId) &&
          predicate(message.params || {})
        ) {
          clearTimeout(timer);
          this.listeners.delete(listener);
          resolve(message.params || {});
        }
      };
      this.listeners.add(listener);
    });
  }

  async close() {
    if (this.socket.readyState === WebSocket.CLOSED) return;
    const closed = new Promise((resolve) =>
      this.socket.addEventListener("close", resolve, { once: true })
    );
    this.socket.close();
    await Promise.race([
      closed,
      new Promise((resolve) => setTimeout(resolve, 1_000)),
    ]);
  }
}

class PageSession {
  constructor(client, sessionId, allowedOrigin, timeoutMs) {
    this.client = client;
    this.sessionId = sessionId;
    this.allowedOrigin = allowedOrigin;
    this.timeoutMs = timeoutMs;
    this.consoleErrors = [];
    this.client.listeners.add((message) => {
      if (message.sessionId !== this.sessionId) return;
      if (message.method === "Runtime.exceptionThrown") {
        this.consoleErrors.push({
          type: "exception",
          text: message.params?.exceptionDetails?.text || "runtime exception",
        });
      }
      if (
        message.method === "Runtime.consoleAPICalled" &&
        ["error", "assert"].includes(message.params?.type)
      ) {
        this.consoleErrors.push({
          type: message.params.type,
          text: (message.params.args || []).map((item) => item.value ?? item.description ?? "").join(" "),
        });
      }
    });
  }

  send(method, params = {}) {
    return this.client.send(method, params, this.sessionId);
  }

  async initialize() {
    await this.send("Page.enable");
    await this.send("Runtime.enable");
    await this.send("Fetch.enable", {
      patterns: [
        { urlPattern: "http://*/*", requestStage: "Request" },
        { urlPattern: "https://*/*", requestStage: "Request" },
      ],
    });
    this.client.listeners.add((message) => {
      if (
        message.sessionId !== this.sessionId ||
        message.method !== "Fetch.requestPaused"
      ) {
        return;
      }
      const requestId = message.params?.requestId;
      const rawUrl = message.params?.request?.url;
      let allowed = false;
      try {
        allowed = new URL(rawUrl).origin === this.allowedOrigin;
      } catch {
        allowed = false;
      }
      const response = allowed
        ? this.send("Fetch.continueRequest", { requestId })
        : this.send("Fetch.failRequest", {
          requestId,
          errorReason: "BlockedByClient",
        });
      response.catch((error) => {
        this.consoleErrors.push({
          type: "network-policy",
          text: error.message,
        });
      });
    });
    await this.send("Input.setIgnoreInputEvents", { ignore: false });
    await this.send("Emulation.setDeviceMetricsOverride", {
      width: VIEWPORT.width,
      height: VIEWPORT.height,
      deviceScaleFactor: 1,
      mobile: true,
      screenWidth: VIEWPORT.width,
      screenHeight: VIEWPORT.height,
    });
    const origin = JSON.stringify(this.allowedOrigin);
    await this.send("Page.addScriptToEvaluateOnNewDocument", {
      source: `(() => {
        const allowedOrigin = ${origin};
        const nativeFetch = globalThis.fetch.bind(globalThis);
        globalThis.fetch = (input, init) => {
          const raw = typeof input === "string" ? input : input.url;
          const url = new URL(raw, location.href);
          if (url.origin === allowedOrigin || ["data:", "blob:", "about:"].includes(url.protocol)) {
            return nativeFetch(input, init);
          }
          return Promise.reject(new TypeError("External network disabled by browser E2E"));
        };
      })();`,
    });
  }

  async call(functionDeclaration, args = []) {
    const globalObject = await this.send("Runtime.evaluate", {
      expression: "globalThis",
      returnByValue: false,
    });
    const objectId = globalObject.result?.objectId;
    if (!objectId) throw new Error("CDP could not resolve global object");
    try {
      const response = await this.send("Runtime.callFunctionOn", {
        objectId,
        functionDeclaration: String(functionDeclaration),
        arguments: args.map((value) => ({ value })),
        returnByValue: true,
        awaitPromise: true,
      });
      if (response.exceptionDetails) {
        throw new Error(`page evaluation failed: ${response.exceptionDetails.text}`);
      }
      return response.result?.value;
    } finally {
      await this.send("Runtime.releaseObject", { objectId }).catch(() => {});
    }
  }

  async navigate(url) {
    this.consoleErrors = [];
    const loaded = this.client.waitForEvent("Page.loadEventFired", this.sessionId);
    await this.send("Page.navigate", { url });
    await loaded;
    await this.waitFor(
      function () { return document.readyState === "complete"; },
      [],
      "document complete",
    );
  }

  async waitFor(functionDeclaration, args, label) {
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      if (await this.call(functionDeclaration, args)) return;
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
    throw new Error(`page condition timeout: ${label}`);
  }

  async click(selector, edition, fixture, step) {
    const rect = await this.call(
      function (reviewedSelector) {
        const matches = document.querySelectorAll(reviewedSelector);
        if (matches.length !== 1) return { count: matches.length };
        matches[0].scrollIntoView({
          block: "center",
          inline: "center",
          behavior: "instant",
        });
        const box = matches[0].getBoundingClientRect();
        return {
          count: 1,
          x: box.left + box.width / 2,
          y: box.top + box.height / 2,
          width: box.width,
          height: box.height,
        };
      },
      [selector],
    );
    if (rect.count !== 1 || rect.width <= 0 || rect.height <= 0) {
      fail(edition, fixture, step, rect, "one visible reviewed selector", "Restore the code-reviewed UI selector and visible control.");
    }
    await this.send("Input.dispatchMouseEvent", {
      type: "mousePressed",
      x: rect.x,
      y: rect.y,
      button: "left",
      clickCount: 1,
    });
    await this.send("Input.dispatchMouseEvent", {
      type: "mouseReleased",
      x: rect.x,
      y: rect.y,
      button: "left",
      clickCount: 1,
    });
  }

  async setControl(selector, value, edition, fixture, step) {
    const result = await this.call(
      function (reviewedSelector, reviewedValue) {
        const matches = document.querySelectorAll(reviewedSelector);
        if (matches.length !== 1) return { count: matches.length };
        const element = matches[0];
        element.value = reviewedValue;
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.dispatchEvent(new Event("change", { bubbles: true }));
        return { count: 1, value: element.value };
      },
      [selector, value],
    );
    if (result.count !== 1 || result.value !== value) {
      fail(edition, fixture, step, result, { count: 1, value }, "Restore the reviewed input/select selector and option.");
    }
  }
}

async function createBrowserSession(browserPath, profilePath, timeoutMs, baseUrl) {
  const args = [
    "--headless=new",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-features=MediaRouter,OptimizationHints,Translate",
    "--disable-sync",
    "--metrics-recording-only",
    "--mute-audio",
    "--no-default-browser-check",
    "--no-first-run",
    "--remote-debugging-address=127.0.0.1",
    "--remote-debugging-port=0",
    `--user-data-dir=${profilePath}`,
    `--window-size=${VIEWPORT.width},${VIEWPORT.height}`,
    "about:blank",
  ];
  const child = childProcess.spawn(browserPath, args, {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let client = null;
  try {
    const endpoint = await waitForDevTools(child, timeoutMs);
    child.stderr.resume();
    const socket = await connectWebSocket(endpoint, timeoutMs);
    client = new CdpClient(socket, timeoutMs);
    const { browserContextId } = await client.send("Target.createBrowserContext");
    const { targetId } = await client.send("Target.createTarget", {
      url: "about:blank",
      browserContextId,
      width: VIEWPORT.width,
      height: VIEWPORT.height,
    });
    const { sessionId } = await client.send("Target.attachToTarget", {
      targetId,
      flatten: true,
    });
    const page = new PageSession(
      client,
      sessionId,
      new URL(baseUrl).origin,
      timeoutMs,
    );
    await page.initialize();
    return { child, client, browserContextId, targetId, page };
  } catch (error) {
    if (client !== null) await client.close();
    await terminateProcess(child);
    throw error;
  }
}

async function clickTab(page, edition, fixture, tabId) {
  await page.click(
    `#tabsContainer > button.tab[data-tab="${tabId}"]`,
    edition,
    fixture,
    `click-tab-${tabId}`,
  );
  await page.waitFor(
    function (expectedHash, panelId) {
      return location.hash === expectedHash &&
        document.getElementById(panelId)?.classList.contains("active");
    },
    [`#${tabId}`, tabId],
    `tab ${tabId}`,
  );
}

async function tabSnapshot(page, clicked) {
  return page.call(
    function (reviewedIds, clickedId) {
      const tabs = [...document.querySelectorAll("#tabsContainer > button.tab")];
      const panels = reviewedIds.map((id) => {
        const matches = document.querySelectorAll(`section#${id}`);
        if (matches.length !== 1) return { id, count: matches.length };
        const panel = matches[0];
        return {
          id,
          count: 1,
          active: panel.classList.contains("active"),
          hidden: panel.hasAttribute("hidden"),
          ariaHidden: panel.getAttribute("aria-hidden"),
          display: getComputedStyle(panel).display,
          textLength: panel.innerText.trim().length,
        };
      });
      return {
        clicked: clickedId,
        title: document.title,
        labels: tabs.map((tab) => tab.textContent.trim()),
        tabCount: tabs.length,
        panelCount: panels.filter((panel) => panel.count === 1).length,
        activeTabs: tabs.filter((tab) => tab.classList.contains("active")).length,
        activeTabIds: tabs
          .filter((tab) => tab.classList.contains("active"))
          .map((tab) => tab.dataset.tab || ""),
        activePanels: panels.filter((panel) => panel.active).length,
        hash: location.hash,
        panels,
        innerWidth: window.innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
      };
    },
    [TAB_IDS, clicked],
  );
}

async function runTabs(page, baseUrl, edition, fixture) {
  const spec = EDITIONS[edition];
  await page.navigate(new URL(spec.page, baseUrl).href);
  await page.call(function () { localStorage.clear(); });
  for (const tabId of TAB_IDS) {
    await clickTab(page, edition, fixture, tabId);
    validateTabSnapshot(edition, fixture, await tabSnapshot(page, tabId));
  }
  assertNoConsoleErrors(page.consoleErrors, edition, fixture);
}

async function runDiagnosis(page, baseUrl, caseId) {
  const spec = DIAGNOSIS_CASES[caseId];
  await page.navigate(new URL(EDITIONS[spec.edition].page, baseUrl).href);
  await page.call(function () { localStorage.clear(); });
  await clickTab(page, spec.edition, caseId, "diagnose");
  for (const field of INPUT_FIELDS) {
    const value = spec.input[field];
    if (typeof value !== "string") {
      fail(spec.edition, caseId, `input-${field}`, value, "reviewed string enum", "Correct the code-owned case.");
    }
    await page.click(
      `#diagnoseForm input[name="${field}"][value="${value}"]`,
      spec.edition,
      caseId,
      `input-${field}`,
    );
  }
  await page.click(
    "#diagnoseForm > button.cta-btn",
    spec.edition,
    caseId,
    "submit-diagnosis",
  );
  await page.waitFor(
    function () {
      return document.querySelectorAll("#diagnoseResult .result-card").length === 1;
    },
    [],
    "diagnosis result",
  );
  const snapshot = await page.call(function () {
    const cards = document.querySelectorAll("#diagnoseResult .result-card");
    const titles = document.querySelectorAll("#diagnoseResult .result-title");
    const timelines = document.querySelectorAll("#diagnoseResult .timeline-bar");
    const segments = [...document.querySelectorAll("#diagnoseResult .timeline-bar .timeline-segment")]
      .map((element) => element.innerText.trim());
    const moneyTables = document.querySelectorAll("#diagnoseResult details.fold table.snapshot-table");
    let state = null;
    try {
      state = {
        primary: lastDiagnoseResult?.primary ?? null,
        alt: lastDiagnoseResult?.alt ?? null,
      };
    } catch {
      state = { primary: null, alt: null };
    }
    return {
      resultCardCount: cards.length,
      titleCount: titles.length,
      title: titles[0]?.innerText.trim() || "",
      timelineCount: timelines.length,
      timeline: segments,
      moneyTableCount: moneyTables.length,
      moneyRows: moneyTables[0]?.querySelectorAll("tbody tr").length || 0,
      text: cards[0]?.innerText || "",
      primary: state.primary,
      alt: state.alt,
    };
  });
  validateDiagnosisSnapshot(caseId, snapshot);
  assertNoConsoleErrors(page.consoleErrors, spec.edition, caseId);
  return snapshot;
}

async function runCalculator(page, baseUrl, caseId) {
  const spec = CALCULATOR_CASES[caseId];
  await page.navigate(new URL(EDITIONS[spec.edition].page, baseUrl).href);
  await page.call(function () { localStorage.clear(); });
  await clickTab(page, spec.edition, caseId, spec.section);
  if (spec.kind === "netpay") {
    await page.click("#netPay > summary", spec.edition, caseId, "open-netpay");
    if (spec.input.mode) {
      await page.setControl("#npProv", spec.input.mode, spec.edition, caseId, "tax-mode");
    }
    await page.setControl("#npSalary", spec.input.salary, spec.edition, caseId, "salary");
    await page.waitFor(
      function (expected) {
        return document.querySelector("#npResult")?.innerText.includes(expected);
      },
      [spec.expected],
      "net pay output",
    );
    const snapshot = await page.call(function () {
      const outputs = document.querySelectorAll("#npResult");
      return { outputCount: outputs.length, text: outputs[0]?.innerText || "" };
    });
    validateCalculatorSnapshot(caseId, snapshot);
  } else if (spec.kind === "crs") {
    await page.click("#crsCalc > summary", spec.edition, caseId, "open-crs");
    const selectors = {
      age: "#crsAge",
      education: "#crsEducation",
      language: "#crsLanguage",
      experience: "#crsCanExperience",
    };
    for (const [field, selector] of Object.entries(selectors)) {
      await page.setControl(selector, spec.input[field], spec.edition, caseId, `crs-${field}`);
    }
    await page.waitFor(
      function (expected) {
        return document.querySelector("#crsCore")?.innerText.trim() === expected;
      },
      [spec.expected],
      "CRS output",
    );
    const snapshot = await page.call(function () {
      const outputs = document.querySelectorAll("#crsCore");
      return { outputCount: outputs.length, text: outputs[0]?.innerText.trim() || "" };
    });
    validateCalculatorSnapshot(caseId, snapshot);
  } else {
    fail(spec.edition, caseId, "calculator-kind", spec.kind, ["netpay", "crs"], "Use a reviewed calculator kind.");
  }
  assertNoConsoleErrors(page.consoleErrors, spec.edition, caseId);
}

async function runVerification(page, baseUrl, caseId) {
  const spec = VERIFICATION_CASES[caseId];
  await page.navigate(new URL("verification.html", baseUrl).href);
  await page.waitFor(
    function (expected) {
      return Object.entries(expected).every(([id, value]) =>
        document.getElementById(id)?.textContent.trim() === value
      );
    },
    [spec.audit],
    "verification audit",
  );
  const snapshot = await page.call(function (expectedHistory) {
    const auditIds = [
      "sourceAttestations",
      "attestedClaims",
      "attestedLeaves",
      "liveCapable",
      "liveExtractable",
      "fixtureOnly",
      "lineageDerived",
      "lineageMapped",
      "lineageExecuted",
      "lineageInputs",
      "criticalRemaining",
    ];
    const audit = Object.fromEntries(
      auditIds.map((id) => [id, document.getElementById(id)?.textContent.trim() || ""]),
    );
    const gates = document.querySelectorAll("#attestationGate, #lineageGate");
    const history = [...document.querySelectorAll(".history li")]
      .map((item) => item.innerText.trim());
    return {
      audit,
      gateCount: gates.length,
      gateText: [...gates].map((gate) => gate.innerText).join(" "),
      historyMatches: history.filter((text) => text.includes(expectedHistory)).length,
    };
  }, [spec.historyIncludes]);
  validateVerificationSnapshot(caseId, snapshot);
  assertNoConsoleErrors(page.consoleErrors, "verification", caseId);
}

function parseArgs(argv) {
  const options = {
    root: DEFAULT_ROOT,
    browser: null,
    baseUrl: null,
    timeoutMs: DEFAULT_TIMEOUT_MS,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = argv[index + 1];
    if (["--browser", "--base-url", "--timeout-ms"].includes(arg)) {
      if (value === undefined) throw new Error(`${arg} requires a value`);
      index += 1;
      if (arg === "--browser") options.browser = value;
      if (arg === "--base-url") options.baseUrl = validateBaseUrl(value);
      if (arg === "--timeout-ms") options.timeoutMs = Number(value);
      continue;
    }
    throw new Error(`unsupported argument: ${arg}`);
  }
  if (
    !Number.isInteger(options.timeoutMs) ||
    options.timeoutMs < MIN_TIMEOUT_MS ||
    options.timeoutMs > MAX_TIMEOUT_MS
  ) {
    throw new Error(`--timeout-ms must be an integer ${MIN_TIMEOUT_MS}..${MAX_TIMEOUT_MS}`);
  }
  return options;
}

async function runReviewedStep(edition, fixture, action) {
  try {
    return await action();
  } catch (error) {
    if (error instanceof E2EFailure) throw error;
    fail(
      edition,
      fixture,
      "browser-runtime",
      error instanceof Error ? error.message : String(error),
      "reviewed page completes within the bounded CDP timeout",
      "Restore the reviewed selector/event wiring or resolve the browser/CDP failure.",
    );
  }
}

export async function runBrowserE2E(options) {
  const cleanup = new CleanupStack();
  let primaryError = null;
  let checks = 0;
  try {
    const registry = validateFixtureRegistry(
      JSON.parse(
        await fs.promises.readFile(
          path.join(options.root, FIXTURE_PATH),
          "utf8",
        ),
      ),
    );
    const browserPath = findBrowser(options.browser);
    let baseUrl = options.baseUrl;
    if (baseUrl === null) {
      const server = await startStaticServer(options.root);
      cleanup.use(() => server.close());
      baseUrl = server.baseUrl;
    }
    const profilePath = await fs.promises.mkdtemp(
      path.join(os.tmpdir(), "nz-navigator-browser-e2e-"),
    );
    cleanup.use(() => fs.promises.rm(profilePath, { recursive: true, force: true }));
    const browser = await createBrowserSession(
      browserPath,
      profilePath,
      options.timeoutMs,
      baseUrl,
    );
    cleanup.use(() => terminateProcess(browser.child));
    cleanup.use(() => browser.client.close());

    for (const edition of registry.suites.tabs) {
      await runReviewedStep(edition, `tabs-${edition}`, () =>
        runTabs(browser.page, baseUrl, edition, `tabs-${edition}`)
      );
      checks += TAB_IDS.length;
      console.log(`PASS edition=${edition} fixture=tabs-${edition} steps=6`);
    }
    const diagnosis = new Map();
    for (const caseId of registry.suites.diagnosis) {
      diagnosis.set(
        caseId,
        await runReviewedStep(
          DIAGNOSIS_CASES[caseId].edition,
          caseId,
          () => runDiagnosis(browser.page, baseUrl, caseId),
        ),
      );
      checks += 1;
      console.log(`PASS edition=${DIAGNOSIS_CASES[caseId].edition} fixture=${caseId}`);
    }
    for (const [left, right] of [
      ["nz-student", "ja-student"],
      ["nz-none", "ja-none"],
    ]) {
      const actual = {
        primary: [diagnosis.get(left).primary, diagnosis.get(right).primary],
        timelineCount: [
          diagnosis.get(left).timeline.length,
          diagnosis.get(right).timeline.length,
        ],
        moneyRows: [
          diagnosis.get(left).moneyRows,
          diagnosis.get(right).moneyRows,
        ],
      };
      if (
        actual.primary[0] !== actual.primary[1] ||
        actual.timelineCount[0] !== actual.timelineCount[1] ||
        actual.moneyRows[0] !== actual.moneyRows[1]
      ) {
        fail("nz/ja", `${left}:${right}`, "parity", actual, "same primary, timeline count, and money rows", "Restore NZ/JA diagnosis parity.");
      }
      checks += 1;
    }
    for (const caseId of registry.suites.calculators) {
      await runReviewedStep(
        CALCULATOR_CASES[caseId].edition,
        caseId,
        () => runCalculator(browser.page, baseUrl, caseId),
      );
      checks += 1;
      console.log(`PASS edition=${CALCULATOR_CASES[caseId].edition} fixture=${caseId}`);
    }
    for (const caseId of registry.suites.verification) {
      await runReviewedStep(
        "verification",
        caseId,
        () => runVerification(browser.page, baseUrl, caseId),
      );
      checks += 1;
      console.log(`PASS edition=verification fixture=${caseId}`);
    }
    return {
      checks,
      browserPath,
      baseUrl,
      mode: options.baseUrl === null ? "local" : "live",
    };
  } catch (error) {
    primaryError = error instanceof E2EFailure
      ? error
      : new E2EFailure(
        "<browser>",
        "<runtime>",
        "infrastructure",
        error instanceof Error ? error.message : String(error),
        "allowlisted Chrome/Chromium and bounded CDP session",
        "Install the reviewed browser path or resolve the launch, CDP, server, or cleanup failure.",
      );
    throw primaryError;
  } finally {
    try {
      await cleanup.cleanup();
    } catch (cleanupError) {
      if (primaryError === null) throw cleanupError;
      console.error(`Cleanup error: ${cleanupError.message}`);
    }
  }
}

async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    const result = await runBrowserE2E(options);
    console.log(
      `Browser E2E passed: ${result.checks} check(s), mode=${result.mode}, ` +
      `viewport=${VIEWPORT.width}x${VIEWPORT.height}, browser=${result.browserPath}`,
    );
  } catch (error) {
    const reported = error instanceof E2EFailure
      ? error
      : new E2EFailure(
        "<browser>",
        "<cli>",
        "arguments",
        error instanceof Error ? error.message : String(error),
        "reviewed CLI options",
        "Use only --browser, --base-url, and --timeout-ms within documented bounds.",
      );
    console.error(reported.message);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT_PATH) {
  await main();
}

export const REVIEWED_CONTRACT = Object.freeze({
  browserPaths: BROWSER_PATHS,
  liveBaseUrl: LIVE_BASE_URL,
  editions: EDITIONS,
  diagnosisCases: DIAGNOSIS_CASES,
  calculatorCases: CALCULATOR_CASES,
  verificationCases: VERIFICATION_CASES,
  viewport: VIEWPORT,
});
