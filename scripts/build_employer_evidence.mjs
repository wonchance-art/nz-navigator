#!/usr/bin/env node
/**
 * Build and verify employer-to-source evidence lineage.
 *
 * The machine-extracted cohorts are parsed from checked-in official responses:
 * INZ RSE JSON, NZKGI PDF text representations, and the AFPA member HTML.
 * Heterogeneous Australian pages use a separately frozen reviewed snapshot and
 * are labelled as such; they are never promoted to machine-extracted evidence.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EMPLOYERS_PATH = path.join(ROOT, "data", "employers.json");
const EVIDENCE_PATH = path.join(ROOT, "data", "employer-evidence.json");
const FIXTURE_DIR = path.join(ROOT, "data", "employer-evidence-fixtures");
const REVIEWED_AU_PATH = path.join(FIXTURE_DIR, "reviewed-au-web-records.json");
const TODAY = "2026-07-19";
const NEXT_REVIEW = "2026-08-18";
const RSE_CITATION = "https://www.immigration.govt.nz/work/requirements-for-work-visas/approved-employers/recognised-seasonal-employers-list/";
const RSE_REQUEST = "https://www.immigration.govt.nz/_list-collection-search/api/as/v1/engines/--engine--/search.json";
const KGI_ORCHARD_CITATION = "https://www.nzkgi.org.nz/resource/orchard-and-contractors-employer-lists/";
const KGI_ORCHARD_REQUEST = "https://www.nzkgi.org.nz/wp-content/uploads/2026/07/2026-Orchard-and-Contractor-Employers-List-July-2026.pdf";
const KGI_PACK_CITATION = "https://www.nzkgi.org.nz/resource/packhouse-employers-list/";
const KGI_PACK_REQUEST = "https://www.nzkgi.org.nz/wp-content/uploads/2026/01/2025-Packhouse-Employers-List-Feb-26.pdf";
const AFPA_CITATION = "https://freshproduce.org.au/about/";

const PATHS = Object.freeze({
  rse: "data/employer-evidence-fixtures/inz-rse-2026-07-19.json",
  orchardPdf: "data/employer-evidence-fixtures/nzkgi-orchard-2026-07.pdf",
  orchardText: "data/employer-evidence-fixtures/nzkgi-orchard-2026-07.txt",
  packPdf: "data/employer-evidence-fixtures/nzkgi-packhouse-2026-02.pdf",
  packText: "data/employer-evidence-fixtures/nzkgi-packhouse-2026-02.txt",
  afpa: "data/employer-evidence-fixtures/afpa-members-2026-07-19.html",
  reviewedAu: "data/employer-evidence-fixtures/reviewed-au-web-records.json",
});

const KGI_ASSERTIONS = Object.freeze({
  "nz-bay-kiwi-connections-ltd-ef6d16a7": {
    tokens: ["Bay Kiwi Connections Ltd", "Te Puke", "baykiwiconnections@gmail.com"],
  },
  "nz-brix-group-ltd-aae4b333": {
    tokens: ["Brix Group Ltd", "Tauranga", "facebook.com/packworknz"],
  },
  "nz-hill-laboratories-bb00afe9": {
    tokens: ["Hill Laboratories", "BOP (Katikati", "jobs@hill-labs.co.nz"],
  },
  "nz-horticare-services-ltd-2093f051": {
    tokens: ["Horticare Services Ltd", "Katikati, Tauranga", "horticare@hotmail.co.nz"],
  },
  "nz-kiwiguard-horticulture-ltd-36dd44b0": {
    tokens: ["Kiwiguard Horticulture", "Te Puke, Maketu", "Info.kiwiguard@gmail.com"],
    aliases: ["Kiwiguard Horticulture Ltd"],
  },
  "nz-naveen-contracting-ltd-f33543e0": {
    tokens: ["Naveen Contracting Ltd", "Te Puke", "naveencontracting@outlook.co.nz"],
  },
  "nz-olivers-horticulture-a9b6508c": {
    tokens: ["Olivers Horticulture", "Paengaroa", "jobs@olivershorticulture.co.nz"],
  },
  "nz-oropi-management-services-limited-caa6d66d": {
    tokens: ["Oropi Management", "Services Limited", "recruitment@omsltd.co.nz"],
  },
  "nz-paengaroa-horticulture-ltd-9c6a0c83": {
    tokens: ["Paengaroa", "Horticulture Ltd", "admin@paengaroahort.co.nz"],
  },
  "nz-psg-horticulture-services-nz-ltd-e8e5ffa2": {
    tokens: ["PSG Horticulture", "Services NZ Ltd", "palwinderpali39@yahoo.com"],
  },
  "nz-southern-cross-horticulture-ltd-9e37fc11": {
    tokens: ["Southern Cross", "Horticulture Ltd", "ourpeople@schort.co.nz"],
  },
  "nz-trinity-lands-ltd-76311193": {
    tokens: ["Trinity Lands Ltd", "Paengaroa", "recruitment@trinitylands.co.nz"],
  },
  "nz-02-dive-ltd-53dd8427": {
    tokens: ["02 Dive Ltd", "Te Puna, Katikati", "02dive22@gmail.com"],
  },
  "nz-inglis-packers-ltd-19b08bd6": {
    tokens: ["Inglis", "Packers", "Motueka", "Ingpac.employment@xtra.co.nz"],
  },
  "nz-four-seasons-gisborne-aee7b75d": {
    tokens: ["Four Seasons", "Gisborne", "tanya@fourseasons.net.nz"],
    aliases: ["Four Seasons"],
  },
  "nz-under-the-vine-ltd-ef8ed239": {
    tokens: ["Under The Vine Ltd", "24 Riverpoint Rd", "markgeuze@underthevineltd.com"],
  },
  "nz-seeka-limited-9498cb4c": {
    tokens: ["Seeka Limited", "Kerikeri, Bay of", "careers@seeka.co.nz"],
  },
  "nz-yieldia-ltd-395e1fbb": {
    tokens: ["Yieldia Ltd", "Paengaroa", "employment@yieldia.co.nz"],
  },
  "nz-auckland-pack-and-cool-ltd-219dfaec": {
    tokens: ["Auckland", "151 Phillip Road", "Takanini", "https://www.apac.co.nz/"],
    aliases: ["Auckland Pack and Cool Ltd (APAC)"],
  },
  "nz-whitehall-fruitpackers-d4d9de4e": {
    tokens: ["Whitehall", "Fruitpackers", "Cambridge", "www.whitehallfruitpackers.co.nz"],
  },
});

const AFPA_ALIASES = Object.freeze({
  "au-montague-farms-apples-80bfbf51": "Montague Farms",
  "au-montague-farms-apples-75ed9018": "Montague Farms",
  "au-montague-farms-packing-6f0abdf8": "Montague Farms",
  "au-rugby-farming-group-c79fd209": "Rugby Farm",
  "au-rugby-farming-group-51b87eb1": "Rugby Farm",
  "au-mackays-bananas-854f6ada": "Mackays Marketing",
  "au-fresh-select-92d67544": "Fresh Select",
  "au-driscoll-s-australia-berries-faaf7b8c": "Driscoll's",
  "au-driscoll-s-australia-berries-955130f1": "Driscoll's",
  "au-premier-fresh-australia-5b158de1": "Premier Fresh Australia",
  "au-australian-produce-partners-1e37e40b": "Australian Produce Partners",
});

function fail(message) {
  throw new Error(message);
}

function readJson(relative) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8"));
}

function sha256(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

function sourceId(kind, url) {
  const digest = crypto.createHash("sha256").update(`${kind}\0${url}`).digest("hex").slice(0, 12);
  return `source-${kind}-${digest}`;
}

function normalize(value) {
  return String(value ?? "").normalize("NFKC").toLocaleLowerCase("en")
    .replace(/&/g, " and ").replace(/[^a-z0-9]+/g, "");
}

function collapse(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function parseEnglishDate(value) {
  const match = /^(\d{1,2}) ([A-Za-z]+) (\d{4})$/.exec(value || "");
  if (!match) fail(`unsupported RSE expiry date ${JSON.stringify(value)}`);
  const month = {
    january: 1, february: 2, march: 3, april: 4, may: 5, june: 6,
    july: 7, august: 8, september: 9, october: 10, november: 11, december: 12,
  }[match[2].toLowerCase()];
  if (!month) fail(`unsupported RSE expiry month ${JSON.stringify(value)}`);
  return `${match[3]}-${String(month).padStart(2, "0")}-${String(match[1]).padStart(2, "0")}`;
}

function rseRecords() {
  const raw = readJson(PATHS.rse);
  if (!Array.isArray(raw.results) || raw.results.length !== 167) {
    fail(`INZ RSE fixture must contain exactly 167 results, found ${raw.results?.length}`);
  }
  return raw.results.map((item) => {
    const fields = JSON.parse(item.field_schema.raw);
    const field = (title) => fields.find((entry) => entry.Title === title)?.Value ?? null;
    const coordinates = String(field("Location")).split(",").map(Number);
    if (coordinates.length !== 2 || coordinates.some((value) => !Number.isFinite(value))) {
      fail(`invalid INZ RSE coordinates for record ${item.record_id.raw}`);
    }
    return {
      key: String(item.record_id.raw),
      name: collapse(item.title.raw),
      location: collapse(field("Physical address")),
      lat: coordinates[0],
      lng: coordinates[1],
      effectiveTo: parseEnglishDate(field("Status expiry date")),
      website: field("Website") ? String(field("Website")).trim() : null,
    };
  });
}

function matchRse(employer, available) {
  const candidates = available.filter((record) => normalize(record.name) === normalize(employer.name));
  if (!candidates.length) fail(`no INZ RSE record for ${employer.id} (${employer.name})`);
  candidates.sort((left, right) => {
    const ld = Math.hypot(left.lat - employer.location.lat, left.lng - employer.location.lng);
    const rd = Math.hypot(right.lat - employer.location.lat, right.lng - employer.location.lng);
    return ld - rd;
  });
  const selected = candidates[0];
  available.splice(available.indexOf(selected), 1);
  return selected;
}

function afpaMembers() {
  const html = fs.readFileSync(path.join(ROOT, PATHS.afpa), "utf8");
  const records = new Map();
  const anchorPattern = /<a\b[^>]*href="([^"]+)"[^>]*>[\s\S]*?<\/a>/g;
  for (const anchor of html.matchAll(anchorPattern)) {
    const text = /<span data-text="true">([^<]+)<\/span>/.exec(anchor[0]);
    if (!text) continue;
    const name = text[1].replaceAll("&#x27;", "'").replaceAll("&amp;", "&").trim();
    if (Object.values(AFPA_ALIASES).includes(name)) records.set(name, anchor[1]);
  }
  const expected = new Set(Object.values(AFPA_ALIASES));
  for (const name of expected) {
    if (!records.has(name)) fail(`AFPA fixture does not contain exact member ${name}`);
  }
  return records;
}

function fixture(pathValue, mediaType, role) {
  return { role, path: pathValue, mediaType, sha256: sha256(pathValue) };
}

function sourceForEmployer(employer) {
  if (employer.source.url === RSE_CITATION) return "inz-rse-current";
  if (employer.source.url === KGI_ORCHARD_CITATION) return "nzkgi-orchard-2026-07";
  if (employer.source.url === KGI_PACK_CITATION) return "nzkgi-packhouse-2026-02";
  if (employer.source.url === AFPA_CITATION) return "afpa-members-2026-07";
  const kind = {
    "employer-official": "official-web-reviewed",
    "government-job-gateway": "government-gateway-reviewed",
    "verified-local-producer": "third-party-official-reviewed",
    "unverified": "candidate-web-reviewed",
  }[employer.source.kind];
  if (!kind) fail(`unsupported evidence source kind ${employer.source.kind} for ${employer.id}`);
  return sourceId(kind, employer.source.url);
}

function buildSources(employers) {
  const sources = [
    {
      id: "inz-rse-current",
      country: "NZ",
      kind: "government-api",
      citationUrl: RSE_CITATION,
      request: {
        method: "POST",
        url: RSE_REQUEST,
        jsonBody: {
          query: "",
          filters: { all: [{ identifier: "list-cc987ea763" }], any: [], none: [] },
          page: { size: 200, current: 1 },
          sort: [{ title: "asc" }],
        },
      },
      checkedAt: TODAY,
      nextReviewAt: NEXT_REVIEW,
      liveMode: "machine",
      extractor: "inz-rse-json",
      fixtures: [fixture(PATHS.rse, "application/json", "response")],
    },
    {
      id: "nzkgi-orchard-2026-07",
      country: "NZ",
      kind: "industry-pdf",
      citationUrl: KGI_ORCHARD_CITATION,
      request: { method: "GET", url: KGI_ORCHARD_REQUEST },
      checkedAt: TODAY,
      nextReviewAt: NEXT_REVIEW,
      liveMode: "machine-fingerprint",
      extractor: "nzkgi-reviewed-text",
      fixtures: [
        fixture(PATHS.orchardPdf, "application/pdf", "document"),
        fixture(PATHS.orchardText, "text/plain", "reviewed-text"),
      ],
    },
    {
      id: "nzkgi-packhouse-2026-02",
      country: "NZ",
      kind: "industry-pdf",
      citationUrl: KGI_PACK_CITATION,
      request: { method: "GET", url: KGI_PACK_REQUEST },
      checkedAt: TODAY,
      nextReviewAt: NEXT_REVIEW,
      liveMode: "machine-fingerprint",
      extractor: "nzkgi-reviewed-text",
      fixtures: [
        fixture(PATHS.packPdf, "application/pdf", "document"),
        fixture(PATHS.packText, "text/plain", "reviewed-text"),
      ],
    },
    {
      id: "afpa-members-2026-07",
      country: "AU",
      kind: "industry-membership-html",
      citationUrl: AFPA_CITATION,
      request: { method: "GET", url: AFPA_CITATION },
      checkedAt: TODAY,
      nextReviewAt: NEXT_REVIEW,
      liveMode: "machine",
      extractor: "afpa-member-links",
      fixtures: [
        fixture(PATHS.afpa, "text/html", "membership-page"),
        fixture(PATHS.reviewedAu, "application/json", "reviewed-location-snapshot"),
      ],
    },
  ];
  const seen = new Set(sources.map((source) => source.id));
  for (const employer of employers) {
    const id = sourceForEmployer(employer);
    if (seen.has(id)) continue;
    seen.add(id);
    const kind = id.split("-").slice(1, -1).join("-");
    sources.push({
      id,
      country: employer.country,
      kind,
      citationUrl: employer.source.url,
      request: { method: "GET", url: employer.source.url },
      checkedAt: employer.source.checkedAt,
      nextReviewAt: employer.nextReviewAt,
      liveMode: "link-only",
      extractor: "reviewed-records",
      fixtures: [fixture(PATHS.reviewedAu, "application/json", "reviewed-snapshot")],
    });
  }
  return sources.sort((left, right) => left.id.localeCompare(right.id));
}

function reviewedAuById() {
  const raw = readJson(PATHS.reviewedAu);
  if (raw.schemaVersion !== 1 || !Array.isArray(raw.records) || raw.records.length !== 113) {
    fail("reviewed AU fixture must contain schemaVersion 1 and exactly 113 records");
  }
  const map = new Map();
  for (const record of raw.records) {
    if (map.has(record.employerId)) fail(`duplicate reviewed AU record ${record.employerId}`);
    map.set(record.employerId, record);
  }
  return map;
}

function sameLocation(left, right) {
  const fields = ["label", "address", "region", "state", "postcode", "lat", "lng", "precision"];
  return fields.every((field) => (left[field] ?? null) === (right[field] ?? null));
}

function assertReviewedAu(employer, reviewed) {
  if (reviewed.sourceUrl !== employer.source.url) {
    fail(`reviewed AU source URL drift for ${employer.id}`);
  }
  const acceptedNames = [reviewed.sourceName, ...(reviewed.aliases || [])].map(normalize);
  const employerBase = normalize(employer.name.split(/\s+—\s+/)[0]);
  if (!acceptedNames.includes(normalize(employer.name)) && !acceptedNames.includes(employerBase)) {
    fail(`reviewed AU name/alias drift for ${employer.id}`);
  }
  if (!sameLocation(reviewed.location, employer.location)) {
    fail(`reviewed AU location drift for ${employer.id}`);
  }
  if ((reviewed.contactUrl || null) !== (employer.contact.url || null)) {
    fail(`reviewed AU contact drift for ${employer.id}`);
  }
  if (reviewed.reviewedAt !== TODAY) {
    fail(`reviewed AU date drift for ${employer.id}`);
  }
}

function assertKgiTokens(employer, assertion) {
  const relative = employer.source.url === KGI_ORCHARD_CITATION ? PATHS.orchardText : PATHS.packText;
  const text = normalize(fs.readFileSync(path.join(ROOT, relative), "utf8"));
  for (const token of assertion.tokens) {
    if (!text.includes(normalize(token))) {
      fail(`NZKGI fixture token ${JSON.stringify(token)} is missing for ${employer.id}`);
    }
  }
}

function commonLimitations(employer) {
  const values = ["directory-not-current-vacancy"];
  if (employer.country === "NZ") {
    values.push("role-eligibility-unverified");
  } else {
    values.push("role-and-postcode-eligibility-unverified");
  }
  return values;
}

function buildBindings(employers) {
  const availableRse = rseRecords();
  const reviewedAu = reviewedAuById();
  const afpa = afpaMembers();
  const bindings = [];
  for (const employer of employers) {
    const base = {
      id: `evidence-${employer.id}`,
      employerId: employer.id,
      sourceId: sourceForEmployer(employer),
    };
    if (employer.source.url === RSE_CITATION) {
      const record = matchRse(employer, availableRse);
      const expectedStatus = record.effectiveTo < TODAY ? "expired" : "active";
      if (
        normalize(record.name) !== normalize(employer.name)
        || collapse(employer.location.label) !== record.location
        || collapse(employer.location.address) !== record.location
        || Math.abs(employer.location.lat - record.lat) > 0.00001
        || Math.abs(employer.location.lng - record.lng) > 0.00001
        || employer.source.effectiveTo !== record.effectiveTo
        || employer.source.checkedAt !== TODAY
        || employer.status !== expectedStatus
      ) {
        fail(`INZ RSE runtime row drift for ${employer.id}; refresh from exact record ${record.key}`);
      }
      bindings.push({
        ...base,
        level: "machine-extracted",
        record: { ...record, aliases: record.name === employer.name ? [] : [employer.name] },
        scopes: ["entity", "expiry", "location"],
        locationScope: "registered-address",
        limitations: [...commonLimitations(employer), "registered-address-not-worksite"],
      });
      continue;
    }
    if ([KGI_ORCHARD_CITATION, KGI_PACK_CITATION].includes(employer.source.url)) {
      const assertion = KGI_ASSERTIONS[employer.id];
      if (!assertion) fail(`missing NZKGI reviewed assertion for ${employer.id}`);
      assertKgiTokens(employer, assertion);
      bindings.push({
        ...base,
        level: "machine-extracted",
        record: {
          key: employer.id,
          name: employer.name,
          aliases: assertion.aliases || [],
          location: employer.location.label,
          tokens: assertion.tokens,
          contactUrl: employer.contact.url || null,
        },
        scopes: employer.contact.kind === "none"
          ? ["entity", "location"]
          : ["contact", "entity", "location"],
        locationScope: "listed-operating-area",
        limitations: commonLimitations(employer),
      });
      continue;
    }
    const reviewed = reviewedAu.get(employer.id);
    if (!reviewed) fail(`missing reviewed AU record for ${employer.id}`);
    assertReviewedAu(employer, reviewed);
    const record = {
      key: employer.id,
      name: reviewed.sourceName,
      aliases: reviewed.aliases,
      location: reviewed.location.label,
      lat: reviewed.location.lat,
      lng: reviewed.location.lng,
      contactUrl: reviewed.contactUrl || null,
    };
    if (employer.source.url === AFPA_CITATION) {
      const alias = AFPA_ALIASES[employer.id];
      if (!alias || !afpa.has(alias)) fail(`missing AFPA exact member alias for ${employer.id}`);
      record.aliases = [...new Set([...(record.aliases || []), alias])].sort();
      record.memberUrl = afpa.get(alias);
      bindings.push({
        ...base,
        level: "hybrid",
        record,
        scopes: employer.contact.kind === "none"
          ? ["entity", "location"]
          : ["contact", "entity", "location"],
        locationScope: employer.location.precision === "region" ? "reviewed-service-area" : "reviewed-worksite",
        limitations: [
          ...commonLimitations(employer),
          "membership-does-not-prove-worksite",
          "location-reviewed-snapshot-not-live-extracted",
        ],
      });
      continue;
    }
    const limited = employer.source.kind === "unverified";
    if (limited && employer.status !== "uncertain") {
      fail(`limited candidate ${employer.id} must remain uncertain`);
    }
    bindings.push({
      ...base,
      level: limited ? "limited-candidate" : "reviewed-snapshot",
      record,
      scopes: employer.contact.kind === "none"
        ? ["entity", "location"]
        : ["contact", "entity", "location"],
      locationScope: employer.location.precision === "region" ? "reviewed-service-area" : "reviewed-worksite",
      limitations: [
        ...commonLimitations(employer),
        "reviewed-snapshot-not-live-extracted",
        ...(limited ? ["official-status-unverified"] : []),
        ...(employer.source.kind === "government-job-gateway" ? ["gateway-not-employer"] : []),
      ],
    });
  }
  if (availableRse.length) fail(`${availableRse.length} INZ RSE record(s) are orphaned`);
  return bindings.sort((left, right) => left.employerId.localeCompare(right.employerId));
}

function computeAudit(employers, sources, bindings) {
  const count = (predicate) => bindings.filter(predicate).length;
  return {
    employerCount: employers.length,
    bindingCount: bindings.length,
    sourceCount: sources.length,
    machineExtractedCount: count((item) => item.level === "machine-extracted"),
    hybridCount: count((item) => item.level === "hybrid"),
    reviewedSnapshotCount: count((item) => item.level === "reviewed-snapshot"),
    limitedCandidateCount: count((item) => item.level === "limited-candidate"),
    exactEntityCount: count((item) => ["machine-extracted", "hybrid"].includes(item.level)),
    exactLocationCount: count((item) => item.level === "machine-extracted"),
    reviewedLocationCount: count((item) => ["hybrid", "reviewed-snapshot"].includes(item.level)),
    limitedLocationCount: count((item) => item.level === "limited-candidate"),
    contactScopeCount: count((item) => item.scopes.includes("contact")),
    limitationBindingCount: count((item) => item.limitations.length > 0),
    machineLiveSourceCount: sources.filter((item) => item.liveMode.startsWith("machine")).length,
  };
}

function buildRegistry(employerRegistry) {
  const sources = buildSources(employerRegistry.employers);
  const bindings = buildBindings(employerRegistry.employers);
  return {
    schemaVersion: 1,
    generatedAt: TODAY,
    audit: computeAudit(employerRegistry.employers, sources, bindings),
    sources,
    bindings,
  };
}

function refreshRseEmployers(registry) {
  const available = rseRecords();
  for (const employer of registry.employers.filter((entry) => entry.source.url === RSE_CITATION)) {
    const record = matchRse(employer, available);
    employer.name = record.name;
    employer.location.label = record.location;
    employer.location.address = record.location;
    employer.location.lat = Number(record.lat.toFixed(5));
    employer.location.lng = Number(record.lng.toFixed(5));
    employer.source.checkedAt = TODAY;
    employer.source.effectiveTo = record.effectiveTo;
    employer.status = record.effectiveTo < TODAY ? "expired" : "active";
    employer.nextReviewAt = employer.status === "expired" ? TODAY : NEXT_REVIEW;
  }
  if (available.length) fail(`${available.length} INZ RSE record(s) not consumed during refresh`);
  const statusCounts = Object.fromEntries(
    ["active", "uncertain", "expired"].map((status) => [
      status,
      registry.employers.filter((entry) => entry.status === status).length,
    ]),
  );
  registry.generatedAt = TODAY;
  registry.audit.statusCounts = statusCounts;
  registry.audit.expiredCount = statusCounts.expired;
}

function stableStringify(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function main() {
  const args = new Set(process.argv.slice(2));
  const allowed = new Set(["--write", "--check", "--refresh-rse"]);
  for (const arg of args) if (!allowed.has(arg)) fail(`unknown argument ${arg}`);
  if (args.has("--write") && args.has("--check")) fail("--write and --check are mutually exclusive");
  const employerRegistry = JSON.parse(fs.readFileSync(EMPLOYERS_PATH, "utf8"));
  if (args.has("--refresh-rse")) {
    refreshRseEmployers(employerRegistry);
    fs.writeFileSync(EMPLOYERS_PATH, stableStringify(employerRegistry));
  }
  const expected = buildRegistry(employerRegistry);
  if (args.has("--write")) {
    fs.writeFileSync(EVIDENCE_PATH, stableStringify(expected));
  } else {
    if (!fs.existsSync(EVIDENCE_PATH)) fail("data/employer-evidence.json is missing; run with --write after review");
    const actual = JSON.parse(fs.readFileSync(EVIDENCE_PATH, "utf8"));
    if (stableStringify(actual) !== stableStringify(expected)) {
      fail("data/employer-evidence.json is stale or does not match its reviewed fixtures");
    }
  }
  console.log(
    `Employer evidence verified: ${expected.audit.bindingCount} binding(s), ` +
    `${expected.audit.sourceCount} source(s), ${expected.audit.machineExtractedCount} machine-extracted, ` +
    `${expected.audit.hybridCount} hybrid, ${expected.audit.reviewedSnapshotCount} reviewed snapshot, ` +
    `${expected.audit.limitedCandidateCount} limited candidate.`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`ERROR: ${error.message}`);
    process.exit(1);
  }
}

export {
  AFPA_ALIASES,
  KGI_ASSERTIONS,
  buildRegistry,
  computeAudit,
  normalize,
  parseEnglishDate,
  refreshRseEmployers,
  rseRecords,
};
