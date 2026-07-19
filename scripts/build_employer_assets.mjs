#!/usr/bin/env node
/**
 * Build the small browser compatibility assets from data/employers.json.
 *
 * `--migrate-legacy` is a one-time deterministic importer for the two legacy
 * JavaScript directories. Normal builds read only the reviewed JSON registry.
 */
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REGISTRY = path.join(ROOT, "data", "employers.json");
const TODAY = "2026-07-19";
const CHECKED_AT = "2026-07-14";
const NEXT_REVIEW = "2026-08-13";
const RSE_URL = "https://www.immigration.govt.nz/work/requirements-for-work-visas/approved-employers/recognised-seasonal-employers-list/";
const KGI_ORCHARD_URL = "https://www.nzkgi.org.nz/resource/orchard-and-contractors-employer-lists/";
const KGI_PACK_URL = "https://www.nzkgi.org.nz/resource/packhouse-employers-list/";
const WORKFORCE_URL = "https://www.workforceaustralia.gov.au/individuals/jobs/search";
const REVIEWED_EMPLOYER_OVERRIDES = Object.freeze({
  "nz-four-seasons-gisborne-aee7b75d": {
    contact: { kind: "none" },
  },
  "au-montague-farms-apples-80bfbf51": {
    contact: { kind: "recruitment", url: "https://montaguefarms.com.au/careers/" },
  },
  "au-montague-farms-apples-75ed9018": {
    contact: { kind: "recruitment", url: "https://montaguefarms.com.au/careers/" },
  },
  "au-montague-farms-packing-6f0abdf8": {
    contact: { kind: "recruitment", url: "https://montaguefarms.com.au/careers/" },
  },
  "au-macadamias-australia-d6c4c8c9": {
    source: { kind: "employer-official", url: "https://macadamiasaustralia.com/", checkedAt: TODAY },
    contact: { kind: "company", url: "https://macadamiasaustralia.com/" },
  },
  "au-howe-farming-921c6ef3": {
    source: { kind: "employer-official", url: "https://www.howefarms.com/contact-us-2/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://www.howefarms.com/contact-us-2/" },
  },
  "au-rocky-ponds-produce-c579bd06": {
    source: { kind: "verified-local-producer", url: "https://abr.business.gov.au/Search/ResultsActive?SearchText=rocky+ponds+produce", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://au.seek.com/rocky-ponds-jobs" },
  },
  "au-marto-farms-6a5cef33": {
    location: {
      label: "Bundaberg region",
      region: "QLD",
      state: "QLD",
      postcode: "4670",
      lat: -24.866,
      lng: 152.348,
      precision: "region",
    },
    source: { kind: "verified-local-producer", url: "https://ausveg.com.au/knowledge-hub/2024-australia-japan-horticulture-showcase/", checkedAt: TODAY },
    contact: { kind: "none" },
  },
  "au-rombola-family-farms-e85507e1": {
    source: { kind: "verified-local-producer", url: "https://abr.business.gov.au/ABN/View?id=94605093294", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://employmenthero.com/jobs/organisations/rombola-family-farms/" },
  },
  "au-geoffrey-thompson-holdings-46e84151": {
    name: "Redland Premium Fruit — Shepparton",
    source: { kind: "employer-official", url: "https://redlandfruit.com.au/our-farms/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://redlandfruit.com.au/job-application/" },
  },
  "au-accolade-wines-a9fe2fec": {
    name: "Vinarchy — Berri Estates",
    source: { kind: "employer-official", url: "https://careers.vinarchy.com/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://careers.vinarchy.com/" },
  },
  "au-treasury-wine-estates-78a6d0b3": {
    source: { kind: "employer-official", url: "https://www.tweglobal.com/life-at-twe", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://www.tweglobal.com/life-at-twe" },
  },
  "au-harvest-road-group-5eb2ee2b": {
    source: { kind: "employer-official", url: "https://www.harvestroad.com/work-with-us/career-opportunities", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://www.harvestroad.com/work-with-us/career-opportunities" },
  },
  "au-simplot-australia-6175c439": {
    source: { kind: "employer-official", url: "https://simplot.com.au/careers", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://simplot.com.au/careers" },
  },
  "au-teys-australia-9e60d8ec": {
    source: { kind: "employer-official", url: "https://au.teysgroup.com/people/current-vacancies/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://au.teysgroup.com/people/current-vacancies/" },
  },
  "au-teys-australia-b5de6d01": {
    source: { kind: "employer-official", url: "https://au.teysgroup.com/people/current-vacancies/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://au.teysgroup.com/people/current-vacancies/" },
  },
  "au-teys-australia-7cdc53b9": {
    source: { kind: "employer-official", url: "https://au.teysgroup.com/people/current-vacancies/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://au.teysgroup.com/people/current-vacancies/" },
  },
  "au-thiess-37894727": {
    source: { kind: "employer-official", url: "https://thiess.com/careers", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://thiess.com/careers" },
  },
  "au-ugl-a3537a0b": {
    source: { kind: "employer-official", url: "https://www.ugllimited.com/work-with-us", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://www.ugllimited.com/work-with-us" },
  },
  "au-monadelphous-5b5d3fc9": {
    source: { kind: "employer-official", url: "https://news.monadelphous.com.au/jobs-with-us", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://news.monadelphous.com.au/jobs-with-us" },
  },
  "au-nrw-holdings-f4fed357": {
    source: { kind: "employer-official", url: "https://nrw.com.au/people-careers/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://nrw.com.au/people-careers/" },
  },
  "au-fulton-hogan-c0eeaa08": {
    source: { kind: "employer-official", url: "https://www.fultonhogan.com/join-our-team/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://www.fultonhogan.com/join-our-team/" },
  },
  "au-q-i-t-e-harvest-trail-56051769": {
    contact: { kind: "company", url: "https://www.qite.com/" },
  },
  "au-downer-58e2fb4d": {
    source: { kind: "employer-official", url: "https://downergroup.com/life-at-downer/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://downergroup.com/life-at-downer/" },
  },
  "au-sunrice-911137c1": {
    source: { kind: "employer-official", url: "https://www.sunrice.com.au/careers/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://www.sunrice.com.au/careers/" },
  },
  "au-inghams-bd9cd108": {
    source: { kind: "employer-official", url: "https://inghams.com.au/working-with-us/", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://inghams.com.au/working-with-us/" },
  },
  "au-south32-cannington-2164d42f": {
    source: { kind: "employer-official", url: "https://www.south32.net/careers", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://careers.south32.net/?locale=en_US&wpmobileexternal=true" },
  },
  "au-south32-gemco-1b3247d6": {
    source: { kind: "employer-official", url: "https://www.south32.net/careers", checkedAt: TODAY },
    contact: { kind: "recruitment", url: "https://careers.south32.net/?locale=en_US&wpmobileexternal=true" },
  },
});
const LEGACY_WORK_TYPES = Object.freeze({
  "농장/원예": "horticulture",
  "과수원/계약": "orchard-contracting",
  "인력/계약": "labour-contracting",
  "종묘/육묘": "nursery",
  "팩하우스": "packhouse",
  "팩하우스/과수원": "packhouse-orchard",
  "포도/계약": "viticulture-contracting",
  "포도/와이너리": "viticulture-winery",
  "품질/검사": "quality-lab",
  "건설/현장": "construction",
  "곡물/가공": "grain-processing",
  "광업": "mining",
  "구직지원": "job-gateway",
  "농장/가공": "farm-processing",
  "농장/팩킹": "farm-packing",
  "식품가공": "food-processing",
  "와이너리/가공": "winery-processing",
  "와이너리/포도": "viticulture-winery",
  "축산/가공": "livestock-processing",
  "축산/육가공": "meat-processing",
  "팩하우스/가공": "packhouse-processing",
});

const NZ_REGIONS = [
  ["Northland", -35.2284, 173.9470],
  ["Auckland", -37.2012, 174.9010],
  ["Waikato", -37.8911, 175.4690],
  ["Bay of Plenty", -37.7833, 176.3250],
  ["Gisborne", -38.6623, 178.0176],
  ["Hawke's Bay", -39.6381, 176.8492],
  ["Manawatū-Whanganui", -40.6223, 175.2865],
  ["Wellington / Wairarapa", -41.2189, 175.4597],
  ["Marlborough", -41.5134, 173.9612],
  ["Nelson / Tasman", -41.1080, 173.0110],
  ["Canterbury", -43.9036, 171.7480],
  ["Otago", -45.0384, 169.2007],
];

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exit(1);
}

function canonicalSlug(value) {
  const slug = value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/&/g, " and ").replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "").slice(0, 48);
  return slug || "entry";
}

function stableId(country, sourceClass, name, branch) {
  const digest = crypto.createHash("sha256").update(`${country}\0${sourceClass}\0${name}\0${branch}`).digest("hex").slice(0, 8);
  return `${country.toLowerCase()}-${canonicalSlug(name)}-${digest}`;
}

function haversine(lat1, lng1, lat2, lng2) {
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLng = (lng2 - lng1) * rad;
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLng / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function nzRegion(lat, lng) {
  return NZ_REGIONS.map(([name, rLat, rLng]) => [name, haversine(lat, lng, rLat, rLng)])
    .sort((a, b) => a[1] - b[1])[0][0];
}

function parseEnglishDate(value) {
  const match = /^(\d{1,2}) ([A-Za-z]+) (\d{4})$/.exec(value || "");
  if (!match) return null;
  const month = {
    january: 1, february: 2, march: 3, april: 4, may: 5, june: 6,
    july: 7, august: 8, september: 9, october: 10, november: 11, december: 12,
  }[match[2].toLowerCase()];
  if (!month) return null;
  return `${match[3]}-${String(month).padStart(2, "0")}-${String(match[1]).padStart(2, "0")}`;
}

function contactKind(url) {
  if (!url) return "none";
  if (url.startsWith("mailto:")) return "email";
  return /career|job|work-with|employment|opportunit|recruit/i.test(url) ? "recruitment" : "company";
}

function normalizedWorkType(value) {
  return LEGACY_WORK_TYPES[value] || value;
}

function applyReviewedOverrides(employers) {
  const byId = new Map(employers.map(entry => [entry.id, entry]));
  for (const [id, override] of Object.entries(REVIEWED_EMPLOYER_OVERRIDES)) {
    const entry = byId.get(id);
    if (!entry) fail(`reviewed employer override references missing id ${id}`);
    Object.assign(entry, JSON.parse(JSON.stringify(override)));
  }
}

function precisionForNz(entry) {
  // The register supplies an employer address, not an official worksite
  // coordinate. Legacy points were geocoded for navigation and must never be
  // promoted to an exact workplace without a separately reviewed source.
  if (entry.source === "INZ RSE") return "town";
  return /Bay of Plenty|Western Bay|region|district|[·/]/i.test(entry.address || "")
    ? "region" : "town";
}

function precisionForAu(place) {
  return /\/|district|region|projects|area|전국|basin|goldfields|pilbara|tablelands|valley/i.test(place)
    ? "region" : "town";
}

function loadLegacy(file, globalName) {
  const window = {};
  const context = vm.createContext({ window });
  vm.runInContext(fs.readFileSync(file, "utf8"), context, { filename: file, timeout: 1_000 });
  if (!Array.isArray(window[globalName])) fail(`${file} did not expose ${globalName}`);
  return window[globalName];
}

function migrateLegacy() {
  const nzRows = loadLegacy(path.join(ROOT, "nz", "employers.js"), "NZ_EMPLOYERS");
  const auRows = loadLegacy(path.join(ROOT, "au", "employers.js"), "AU_EMPLOYERS");
  const employers = [];

  for (const row of nzRows) {
    const effectiveTo = parseEnglishDate(row.expiry);
    const sourceKind = row.source === "INZ RSE" ? "government-register" : "industry-association";
    const sourceUrl = row.source === "INZ RSE" ? RSE_URL : /팩하우스/.test(row.type) ? KGI_PACK_URL : KGI_ORCHARD_URL;
    const contact = { kind: contactKind(row.contact) };
    if (row.contact) contact.url = row.contact;
    const source = { kind: sourceKind, url: sourceUrl, checkedAt: CHECKED_AT };
    if (effectiveTo) source.effectiveTo = effectiveTo;
    employers.push({
      id: stableId("NZ", row.source, row.name, row.address),
      country: "NZ",
      name: row.name,
      location: {
        label: row.address,
        address: row.source === "INZ RSE" || /\d/.test(row.address || "") ? row.address : undefined,
        region: nzRegion(row.lat, row.lng),
        lat: row.lat,
        lng: row.lng,
        precision: precisionForNz(row),
      },
      workTypes: [normalizedWorkType(row.type)],
      source,
      contact,
      status: effectiveTo && effectiveTo < TODAY ? "expired" : "active",
      nextReviewAt: NEXT_REVIEW,
      vacancyStatus: "directory-only",
      eligibility: {
        scheme: "nz-whv-extension",
        classification: "conditional",
        requiresRoleCheck: true,
        requiresLocationCheck: false,
      },
    });
  }

  for (const row of auRows) {
    let sourceKind;
    let sourceUrl;
    if (/^https?:/.test(row.source)) {
      sourceUrl = row.source;
      sourceKind = /dewr\.gov\.au/.test(row.source) ? "government-job-gateway" : "industry-association";
    } else if (row.source === "호주 정부 구직") {
      sourceUrl = WORKFORCE_URL;
      sourceKind = "government-job-gateway";
    } else if (/기업 공식/.test(row.source)) {
      sourceUrl = row.contact || WORKFORCE_URL;
      sourceKind = "employer-official";
    } else {
      sourceUrl = row.contact || WORKFORCE_URL;
      sourceKind = "unverified";
    }
    const gateway = normalizedWorkType(row.type) === "job-gateway";
    const contact = { kind: contactKind(row.contact) };
    if (row.contact) contact.url = row.contact;
    employers.push({
      id: stableId("AU", row.source, row.name, `${row.state}-${row.postcode}-${row.place}`),
      country: "AU",
      name: row.name,
      location: {
        label: row.place,
        region: row.state,
        state: row.state,
        postcode: row.postcode,
        lat: row.lat,
        lng: row.lng,
        precision: precisionForAu(row.place),
      },
      workTypes: [normalizedWorkType(row.type)],
      source: { kind: sourceKind, url: sourceUrl, checkedAt: CHECKED_AT },
      contact,
      status: sourceKind === "unverified" || contact.kind === "none" ? "uncertain" : "active",
      nextReviewAt: NEXT_REVIEW,
      vacancyStatus: "directory-only",
      eligibility: {
        scheme: gateway ? "none" : "au-417-specified-work",
        classification: gateway ? "not-applicable" : "conditional",
        requiresRoleCheck: true,
        requiresLocationCheck: true,
      },
    });
  }

  const windolf = employers.find(entry => entry.id === "au-windolf-farms-6a130eb9");
  if (windolf) {
    windolf.source = {
      kind: "verified-local-producer",
      url: "https://www.qrida.qld.gov.au/news/lockyer-valley-horticulture-producer-combats-food-waste-help-red-grant",
      checkedAt: TODAY,
    };
  }
  const tousGarden = employers.find(entry => entry.id === "au-tou-s-garden-5f375828");
  if (tousGarden) {
    tousGarden.location = {
      label: "395 Acacia Gap Road, Manton",
      address: "395 Acacia Gap Road, Manton NT 0837",
      region: "NT",
      state: "NT",
      postcode: "0837",
      lat: tousGarden.location.lat,
      lng: tousGarden.location.lng,
      precision: "town",
    };
    tousGarden.source = {
      kind: "employer-official",
      url: "https://tousgarden.com.au/working-conditions/",
      checkedAt: TODAY,
    };
    tousGarden.contact = {
      kind: "recruitment",
      url: "https://tousgarden.com.au/jobapplication/",
    };
    tousGarden.status = "active";
  }
  applyReviewedOverrides(employers);

  const compact = JSON.parse(JSON.stringify(employers));
  const registry = {
    schemaVersion: 1,
    generatedAt: TODAY,
    audit: audit(compact),
    employers: compact,
  };
  fs.writeFileSync(REGISTRY, `${JSON.stringify(registry, null, 2)}\n`);
  console.log(`Migrated ${nzRows.length} NZ + ${auRows.length} AU entries -> ${path.relative(ROOT, REGISTRY)}`);
}

function audit(employers) {
  const normalize = value => String(value || "").normalize("NFKC").toLowerCase()
    .replace(/[^a-z0-9가-힣]/g, "");
  let nearDuplicateCandidateCount = 0;
  for (let i = 0; i < employers.length; i += 1) {
    for (let j = i + 1; j < employers.length; j += 1) {
      const a = employers[i];
      const b = employers[j];
      if (a.country !== b.country) continue;
      const sameName = normalize(a.name) === normalize(b.name);
      const aContact = normalize(a.contact.url);
      const sameContact = aContact && aContact === normalize(b.contact.url);
      if ((sameName || sameContact)
          && haversine(a.location.lat, a.location.lng, b.location.lat, b.location.lng) <= 0.2) {
        nearDuplicateCandidateCount += 1;
      }
    }
  }
  const urls = new Set();
  for (const entry of employers) {
    urls.add(entry.source.url);
    if (entry.contact.url) urls.add(entry.contact.url);
  }
  return {
    employerCount: employers.length,
    countryCounts: Object.fromEntries(["NZ", "AU"].map(country => [
      country, employers.filter(e => e.country === country).length,
    ])),
    statusCounts: Object.fromEntries(["active", "uncertain", "expired"].map(status => [
      status, employers.filter(e => e.status === status).length,
    ])),
    contactableCount: employers.filter(e => e.contact.kind !== "none").length,
    expiredCount: employers.filter(e => e.status === "expired").length,
    nearDuplicateCandidateCount,
    linkUrlCount: urls.size,
  };
}

function renderAsset(country, employers, generatedAt) {
  const subset = employers.filter(entry => entry.country === country);
  return `/* Generated by scripts/build_employer_assets.mjs from data/employers.json.\n`
    + ` * Directory entries are not live vacancies and never prove visa-work eligibility.\n */\n`
    + `window.${country}_EMPLOYERS=Object.freeze(${JSON.stringify(subset)});\n`
    + `window.${country}_EMPLOYER_REGISTRY_META=Object.freeze(${JSON.stringify({ schemaVersion: 1, generatedAt, count: subset.length })});\n`;
}

function build(checkOnly) {
  if (!fs.existsSync(REGISTRY)) fail(`missing ${REGISTRY}; run --migrate-legacy once`);
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  if (registry.schemaVersion !== 1 || !Array.isArray(registry.employers)) fail("invalid employer registry root");
  const expectedAudit = audit(registry.employers);
  if (JSON.stringify(registry.audit) !== JSON.stringify(expectedAudit)) fail("data/employers.json audit is stale");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(registry.generatedAt || "")) fail("data/employers.json generatedAt must be YYYY-MM-DD");
  for (const country of ["NZ", "AU"]) {
    const target = path.join(ROOT, country.toLowerCase(), "employers.js");
    const rendered = renderAsset(country, registry.employers, registry.generatedAt);
    if (checkOnly) {
      if (!fs.existsSync(target) || fs.readFileSync(target, "utf8") !== rendered) {
        fail(`${path.relative(ROOT, target)} is stale; run node scripts/build_employer_assets.mjs`);
      }
    } else {
      fs.writeFileSync(target, rendered);
      console.log(`Built ${path.relative(ROOT, target)}`);
    }
  }
}

const args = new Set(process.argv.slice(2));
if (args.has("--migrate-legacy")) migrateLegacy();
if (args.has("--refresh-audit")) {
  if (!fs.existsSync(REGISTRY)) fail(`missing ${REGISTRY}`);
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const refreshed = {
    schemaVersion: registry.schemaVersion,
    generatedAt: registry.generatedAt || registry.asOf || TODAY,
    audit: audit(registry.employers),
    employers: registry.employers,
  };
  fs.writeFileSync(REGISTRY, `${JSON.stringify(refreshed, null, 2)}\n`);
  console.log(`Refreshed ${path.relative(ROOT, REGISTRY)} audit`);
}
if (args.has("--normalize-work-types")) {
  if (!fs.existsSync(REGISTRY)) fail(`missing ${REGISTRY}`);
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  for (const employer of registry.employers) {
    employer.workTypes = employer.workTypes.map(normalizedWorkType);
  }
  registry.audit = audit(registry.employers);
  fs.writeFileSync(REGISTRY, `${JSON.stringify(registry, null, 2)}\n`);
  console.log(`Normalized ${path.relative(ROOT, REGISTRY)} work types`);
}
if (args.has("--downgrade-legacy-coordinates")) {
  if (!fs.existsSync(REGISTRY)) fail(`missing ${REGISTRY}`);
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  for (const employer of registry.employers) {
    if (employer.country === "NZ" && employer.location.precision === "exact") {
      employer.location.precision = "town";
    }
  }
  registry.audit = audit(registry.employers);
  fs.writeFileSync(REGISTRY, `${JSON.stringify(registry, null, 2)}\n`);
  console.log(`Downgraded unverified exact coordinates in ${path.relative(ROOT, REGISTRY)}`);
}
if (args.has("--normalize-regions")) {
  if (!fs.existsSync(REGISTRY)) fail(`missing ${REGISTRY}`);
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  for (const employer of registry.employers) {
    if (employer.country === "AU" && !employer.location.region) {
      employer.location.region = employer.location.state;
    }
  }
  registry.audit = audit(registry.employers);
  fs.writeFileSync(REGISTRY, `${JSON.stringify(registry, null, 2)}\n`);
  console.log(`Normalized ${path.relative(ROOT, REGISTRY)} region metadata`);
}
if (args.has("--apply-reviewed-overrides")) {
  if (!fs.existsSync(REGISTRY)) fail(`missing ${REGISTRY}`);
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  applyReviewedOverrides(registry.employers);
  registry.audit = audit(registry.employers);
  fs.writeFileSync(REGISTRY, `${JSON.stringify(registry, null, 2)}\n`);
  console.log(`Applied reviewed source and recruitment updates to ${path.relative(ROOT, REGISTRY)}`);
}
build(args.has("--check"));
