#!/usr/bin/env python3
"""Verify reviewed boundary constants against fingerprinted official sources."""

from __future__ import annotations

import argparse
import csv
import hashlib
from html.parser import HTMLParser
import io
import json
import math
import re
import ssl
import sys
import time
import zlib
from dataclasses import asdict, dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 2
REQUEST_AUDIT_SCHEMA_VERSION = 2
MAX_BODY_BYTES = 2_000_000
DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_ATTEMPTS = 1
DEFAULT_RETRY_BACKOFF_MS = 500
DEFAULT_REQUEST_BUDGET_SECONDS = 30.0
DEFAULT_ATTESTATION_BUDGET_SECONDS = 60.0
MAX_RETRY_ATTEMPTS = 4
MAX_RETRY_BACKOFF_MS = 2_000
MAX_REQUEST_BUDGET_SECONDS = 60.0
MAX_ATTESTATION_BUDGET_SECONDS = 120.0
DEFAULT_LIVE_REQUEST_HEADERS = {
    "User-Agent": "nz-navigator-source-attestation/1.0",
    "Accept": (
        "text/html,application/xhtml+xml,application/pdf,"
        "application/json;q=0.9,*/*;q=0.1"
    ),
    "Connection": "close",
}
CANADA_CURL_COMPAT_HOSTS = frozenset(
    {"canada.ca", "www.canada.ca", "ircc.canada.ca"}
)
CANADA_CURL_COMPAT_USER_AGENT = (
    "curl/8.7.1 NZ-Navigator-Source-Attestation/1.0"
)
MAX_ATTESTATIONS = 256
MAX_TARGETS_PER_ATTESTATION = 16
MAX_REQUEST_CANDIDATES = 3
MAX_PDF_OBJECTS = 256
MAX_PDF_STREAMS = 64
MAX_PDF_OBJECT_BYTES = 500_000
MAX_PDF_DECOMPRESSED_BYTES = 4_000_000
MAX_PDF_COMPRESSION_RATIO = 100
MAX_PARAMETER_TEXT = 200
MAX_ANCHOR_TEXT = 2_000
MAX_POINTER_DEPTH = 24
VALID_STATUSES = frozenset(
    {"match", "changed", "blocked", "transient", "unsupported"}
)
VALID_TYPES = frozenset({"number", "string", "array", "object"})
VALUE_TYPES = frozenset(
    {
        "number",
        "integer",
        "decimal",
        "percent-to-decimal",
        "nullable-number",
    }
)
EXTRACTOR_MODES = frozenset(
    {
        "html-table",
        "html-definition",
        "html-table-record",
        "html-labelled-values",
        "html-text-anchor",
        "html-section-text",
        "pdf-table",
        "json-pointer",
        "api-json-pointer",
        "api-json-record",
        "ato-lito",
        "ato-law-lito",
        "ato-law-resident-brackets",
        "ato-tax-free-band",
        "cra-t4127-version",
        "cra-t4127-csv",
        "cra-t4127-bc-annual-rate",
        "cra-t4032-on",
    }
)
OFFICIAL_DOMAINS = {
    "NZ": (
        "immigration.govt.nz",
        "employment.govt.nz",
        "ird.govt.nz",
    ),
    "CA": (
        "canada.ca",
        "ircc.canada.ca",
        "ontario.ca",
        "gov.bc.ca",
        "alberta.ca",
        "jobbank.gc.ca",
        "welcomebc.ca",
    ),
    "AU": (
        "immi.homeaffairs.gov.au",
        "ato.gov.au",
        "fairwork.gov.au",
    ),
}
REQUIRED_ROOT_FIELDS = frozenset(
    {"schemaVersion", "boundaryManifest", "attestations"}
)
OPTIONAL_ROOT_FIELDS = frozenset({"claimScope", "targetComponents"})
REQUIRED_ATTESTATION_FIELDS = frozenset(
    {
        "id",
        "jurisdiction",
        "sourceUrl",
        "request",
        "verifiedAt",
        "effectiveFrom",
        "reviewAfterDays",
        "extractor",
        "expected",
        "fixture",
    }
)
OPTIONAL_ATTESTATION_FIELDS = frozenset(
    {
        "effectiveTo",
        "targets",
        "claims",
        "livePolicy",
        "requestCandidates",
        "candidatePolicy",
    }
)
LIVE_POLICY_FIELDS = frozenset({"mode", "reason", "manualReviewDays"})
LIVE_POLICY_MODES = frozenset({"extract", "fixture-only"})
REQUIRED_TARGET_FIELDS = frozenset({"targetId", "reviewedPath"})
OPTIONAL_TARGET_FIELDS = frozenset({"expectedPath", "componentId"})
REQUIRED_CLAIM_MAPPING_FIELDS = frozenset({"claimId"})
OPTIONAL_CLAIM_MAPPING_FIELDS = frozenset({"expectedPath"})
EXTRACTOR_FIELDS = frozenset({"mode", "params"})
EXPECTED_FIELDS = frozenset({"type", "unit", "value"})
FIXTURE_FIELDS = frozenset(
    {"path", "mediaType", "sha256", "httpStatus", "finalUrl"}
)
TABLE_PARAMETER_FIELDS = frozenset(
    {
        "caption",
        "headers",
        "unitLabel",
        "valueTypes",
        "nullToken",
    }
)
DEFINITION_PARAMETER_FIELDS = frozenset(
    {"section", "fields", "unitLabel", "result"}
)
DEFINITION_FIELD_FIELDS = frozenset({"key", "label", "valueType"})
PDF_PARAMETER_FIELDS = frozenset(
    {
        "anchor",
        "headers",
        "unitLabel",
        "valueTypes",
        "nullToken",
        "delimiter",
    }
)
JSON_PARAMETER_FIELDS = frozenset({"pointer"})
API_RECORD_REQUIRED_FIELDS = frozenset(
    {"arrayPointer", "match", "valuePointer"}
)
API_RECORD_OPTIONAL_FIELDS = frozenset({"transform"})
REQUEST_GET_FIELDS = frozenset({"method"})
REQUEST_GET_URL_FIELDS = frozenset({"method", "url"})
REQUEST_POST_FIELDS = frozenset({"method", "url", "jsonBody"})
REQUEST_FINAL_STATUSES = frozenset(
    {"ready", "transient", "blocked", "changed", "unsupported"}
)
OBSERVATION_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
VALID_CLAIM_STATUSES = frozenset({"official", "derived"})
API_RECORD_TRANSFORMS = frozenset({"identity", "currency-to-number"})
HTML_RECORD_PARAMETER_FIELDS = frozenset(
    {"section", "headers", "result", "fields"}
)
HTML_RECORD_FIELD_FIELDS = frozenset(
    {"key", "rowLabels", "valueHeader", "transform", "unit"}
)
HTML_LABELLED_PARAMETER_FIELDS = frozenset(
    {"anchor", "result", "fields"}
)
HTML_LABELLED_FIELD_FIELDS = frozenset(
    {"key", "label", "transform", "unit"}
)
HTML_TEXT_PARAMETER_FIELDS = frozenset({"anchor", "transform", "unit"})
HTML_SECTION_TEXT_PARAMETER_FIELDS = frozenset(
    {"heading", "anchor", "transform", "unit"}
)
HTML_SECTION_TEXT_TRANSFORMS = frozenset(
    {"inclusive-range", "duration-months"}
)
ATO_LITO_PARAMETER_FIELDS = frozenset({"anchor", "items"})
ATO_LAW_LITO_PARAMETER_FIELDS = frozenset(
    {"actTitle", "section", "sectionTitle", "tableTitle"}
)
ATO_LAW_RESIDENT_PARAMETER_FIELDS = frozenset({"tableTitle"})
ATO_TAX_FREE_PARAMETER_FIELDS = frozenset({"heading", "anchor"})
CRA_T4127_PARAMETER_FIELDS = frozenset({"language"})
CRA_T4127_CSV_PARAMETER_FIELDS = frozenset(
    {"publication", "effectiveDate", "encoding", "cohort"}
)
CRA_T4127_BC_PARAMETER_FIELDS = frozenset({"effectiveYear"})
CRA_T4032_ON_PARAMETER_FIELDS = frozenset({"effectiveDate"})
TARGET_COMPONENT_SCOPE_FIELDS = frozenset({"targetId", "components"})
TARGET_COMPONENT_FIELDS = frozenset({"id", "reviewedPaths"})
ATO_LAW_RESIDENT_HEADERS = [
    "Item",
    "For the part of the ordinary taxable income of the taxpayer that:",
    "The rate is:",
]
ATO_LAW_LITO_HEADERS = [
    "Item",
    "If your relevant income:",
    "The amount of your tax offset is:",
]
REQUEST_CANDIDATE_REQUIRED_FIELDS = frozenset(
    {"id", "sourceRelation", "request", "mediaType", "fixture"}
)
REQUEST_CANDIDATE_OPTIONAL_FIELDS = frozenset({"extractor"})
CANDIDATE_RELATIONS = frozenset(
    {"citation", "same-host", "jurisdiction-official"}
)
CANDIDATE_POLICY_FIELDS = frozenset({"mode"})
CANDIDATE_POLICY_MODES = frozenset(
    {"first-match", "available-parity"}
)
ATO_FIRST_BAND_UNIT = {"cap": "AUD", "rate": "decimal rate"}
ATO_LAW_FIRST_BAND_TITLE = (
    "Tax rates for working holiday makers for the 2024-25 year of "
    "income or a later year of income"
)
ATO_LAW_FIRST_BAND_HEADERS = [
    "Item",
    (
        "For the part of the taxpayer's working holiday taxable "
        "income that:"
    ),
    "The rate is:",
]
ATO_LITO_UNIT = {
    "maxOffset": "AUD",
    "fullTo": "AUD",
    "taper1To": "AUD",
    "taper1Rate": "decimal rate",
    "cutOut": "AUD",
    "taper2Rate": "decimal rate",
}
HTML_VALUE_TRANSFORMS = frozenset(
    {
        "number",
        "integer",
        "currency-to-number",
        "percent-to-decimal",
        "tax-brackets",
        "tax-brackets-serialization",
        "duration-months",
        "duration-weeks",
        "inclusive-range",
        "embedded-percent",
        "embedded-percent-to-decimal",
        "leading-currency-to-number",
        "single-iso-currency-to-number",
        "single-dollar-amount-to-number",
        "single-hourly-dollar-amount-to-number",
        "final-inclusive-range",
        "ato-first-tax-band",
        "ato-law-first-tax-band",
        "percentage-number-to-decimal",
    }
)
HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})
PDF_MEDIA_TYPES = frozenset({"application/pdf"})
JSON_MEDIA_TYPES = frozenset(
    {"application/json", "application/problem+json"}
)
CSV_MEDIA_TYPES = frozenset({"text/csv", "application/csv"})
SUPPORTED_CANDIDATE_MEDIA = (
    HTML_MEDIA_TYPES | PDF_MEDIA_TYPES | JSON_MEDIA_TYPES | CSV_MEDIA_TYPES
)

CRA_T4127_CSV_SPECS = {
    "table-8.1-federal-rates": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "rates-income-thresholds-constants-26e.csv",
        "table": "rates",
        "region": "Federal",
    },
    "table-8.1-ab-rates": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "rates-income-thresholds-constants-26e.csv",
        "table": "rates",
        "region": "AB",
    },
    "table-8.1-bc-thresholds-tail-rates": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "rates-income-thresholds-constants-26e.csv",
        "table": "rates-bc-split",
        "region": "BC",
    },
    "table-8.1-on-rates": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "rates-income-thresholds-constants-26e.csv",
        "table": "rates",
        "region": "ON",
    },
    "table-8.2-federal-amounts": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "other-rates-amounts-26e.csv",
        "table": "amounts-federal",
    },
    "table-8.2-ab-amounts": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "other-rates-amounts-26e.csv",
        "table": "amounts-bpa",
        "region": "AB",
    },
    "table-8.2-bc-amounts": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "other-rates-amounts-26e.csv",
        "table": "amounts-bpa",
        "region": "BC",
    },
    "table-8.2-on-amounts": {
        "publication": "T4127-123rd",
        "effectiveDate": "2026-07-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jul/"
        "other-rates-amounts-26e.csv",
        "table": "amounts-on",
    },
    "table-8.3-cpp-total": {
        "publication": "T4127-122nd",
        "effectiveDate": "2026-01-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jan/"
        "cpp-qpp-ttl-01-26e.csv",
        "table": "cpp-total",
    },
    "table-8.4-cpp-base": {
        "publication": "T4127-122nd",
        "effectiveDate": "2026-01-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jan/"
        "cpp-qpp-br-01-26e.csv",
        "table": "cpp-base",
    },
    "table-8.5-cpp-first-additional": {
        "publication": "T4127-122nd",
        "effectiveDate": "2026-01-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jan/"
        "cpp-qpp-addntl-01-26e.csv",
        "table": "cpp-first",
    },
    "table-8.6-cpp-second-additional": {
        "publication": "T4127-122nd",
        "effectiveDate": "2026-01-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jan/"
        "cpp-qpp-scnd-addntl-01-26e.csv",
        "table": "cpp-second",
    },
    "table-8.7-ei": {
        "publication": "T4127-122nd",
        "effectiveDate": "2026-01-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jan/ei-01-26e.csv",
        "table": "ei",
    },
    "table-8.9-federal-bpa": {
        "publication": "T4127-122nd",
        "effectiveDate": "2026-01-01",
        "path": "/content/dam/cra-arc/formspubs/pub/t4127-jan/cc-fd-01-26e.csv",
        "table": "federal-bpa",
    },
}
CRA_T4127_CSV_ENCODINGS = frozenset(
    {"utf-8", "utf-8-bom", "windows-1252"}
)
class RegistryError(ValueError):
    pass


class ChangedExtraction(ValueError):
    pass


class UnsupportedExtraction(ValueError):
    pass


@dataclass(frozen=True)
class AttemptAudit:
    number: int
    status: str
    latencyBucket: str


@dataclass(frozen=True)
class AttestationResult:
    id: str
    source: str
    requestUrl: str
    path: str
    status: str
    actual: Any
    expected: Any
    contextFingerprint: str
    fix: str
    requestKey: str = ""
    attemptCount: int = 1
    requestFinalStatus: str = "ready"
    latencyBucket: str = "offline"
    selectedCandidate: str | None = None
    candidatePolicy: str = "first-match"
    candidateChain: tuple[dict[str, Any], ...] = ()
    manualReview: dict[str, Any] | None = None

    def render(self) -> str:
        return (
            f"ERROR attestation={self.id} source={self.source} "
            f"request={self.requestUrl} "
            f"path={self.path} status={self.status} "
            f"actual={_display(self.actual)} expected={_display(self.expected)}\n"
            f"  Fix: {self.fix}"
        )


@dataclass
class AttestationReport:
    mode: str
    generatedAt: str
    observationId: str | None = "offline"
    retryPolicy: dict[str, Any] = field(
        default_factory=lambda: {
            "maxAttempts": DEFAULT_MAX_ATTEMPTS,
            "backoffMs": DEFAULT_RETRY_BACKOFF_MS,
            "timeoutSeconds": DEFAULT_TIMEOUT,
            "requestBudgetSeconds": DEFAULT_REQUEST_BUDGET_SECONDS,
            "attestationBudgetSeconds": DEFAULT_ATTESTATION_BUDGET_SECONDS,
        }
    )
    results: list[AttestationResult] = field(default_factory=list)
    fetchedUrls: int = 0
    requests: list[Any] = field(default_factory=list)
    audit: dict[str, int] = field(
        default_factory=lambda: {
            "attestationCount": 0,
            "claimCount": 0,
            "reviewedLeafCount": 0,
            "liveCapableCount": 0,
            "liveExtractableCount": 0,
            "fixtureOnlyCount": 0,
        }
    )

    @property
    def ok(self) -> bool:
        return bool(self.results) and all(
            result.status == "match" for result in self.results
        )

    def to_json(self) -> dict[str, Any]:
        summary = {status: 0 for status in sorted(VALID_STATUSES)}
        for result in self.results:
            summary[result.status] += 1
        request_items = [request.to_json() for request in self.requests]
        observation_id = (
            self.observationId
            if self.observationId is not None
            else _automatic_observation_id(self)
        )
        return {
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "mode": self.mode,
            "generatedAt": self.generatedAt,
            "observationId": observation_id,
            "retryPolicy": self.retryPolicy,
            "summary": summary,
            "fetchedUrls": self.fetchedUrls,
            "audit": self.audit,
            "requestAudit": {
                "schemaVersion": REQUEST_AUDIT_SCHEMA_VERSION,
                "requestCount": len(request_items),
                "totalAttemptCount": sum(
                    item["attemptCount"] for item in request_items
                ),
                "retriedRequestCount": sum(
                    item["attemptCount"] > 1 for item in request_items
                ),
                "requests": request_items,
            },
            "results": [asdict(result) for result in self.results],
        }


@dataclass(frozen=True)
class SourceResponse:
    status: int | None
    final_url: str
    media_type: str
    body: bytes
    error: str | None = None
    too_large: bool = False


@dataclass(frozen=True)
class RequestExecution:
    requestKey: str
    requestUrl: str
    method: str
    attempts: tuple[AttemptAudit, ...]
    finalStatus: str
    latencyBucket: str
    response: SourceResponse
    budgetSeconds: float = DEFAULT_REQUEST_BUDGET_SECONDS
    budgetExhausted: bool = False
    elapsedSeconds: float = 0.0

    @property
    def attemptCount(self) -> int:
        return len(self.attempts)

    def to_json(self) -> dict[str, Any]:
        return {
            "requestKey": self.requestKey,
            "requestUrl": self.requestUrl,
            "method": self.method,
            "attemptCount": self.attemptCount,
            "finalStatus": self.finalStatus,
            "latencyBucket": self.latencyBucket,
            "budgetSeconds": self.budgetSeconds,
            "budgetExhausted": self.budgetExhausted,
            "attempts": [asdict(attempt) for attempt in self.attempts],
        }


def _automatic_observation_id(report: AttestationReport) -> str:
    semantic = {
        "audit": report.audit,
        "results": sorted(
            (
                {
                    "id": item.id,
                    "source": item.source,
                    "requestUrl": item.requestUrl,
                    "path": item.path,
                    "status": item.status,
                    "actual": item.actual,
                    "expected": item.expected,
                    "contextFingerprint": (
                        item.contextFingerprint
                        if item.status != "match"
                        else None
                    ),
                    "fix": item.fix,
                    "requestKey": item.requestKey,
                    "requestFinalStatus": item.requestFinalStatus,
                    "selectedCandidate": item.selectedCandidate,
                    "candidatePolicy": item.candidatePolicy,
                    "candidateChain": [
                        {
                            "candidateId": candidate.get("candidateId"),
                            "requestKey": candidate.get("requestKey"),
                            "outcome": candidate.get("outcome"),
                            "reason": candidate.get("reason"),
                            "attemptCount": candidate.get("attemptCount"),
                            "budgetExhausted": candidate.get(
                                "budgetExhausted"
                            ),
                            "attemptStatuses": [
                                attempt.get("status")
                                for attempt in candidate.get("attempts", [])
                                if isinstance(attempt, dict)
                            ],
                        }
                        for candidate in item.candidateChain
                    ],
                    "manualReview": item.manualReview,
                }
                for item in report.results
            ),
            key=lambda item: (
                item["status"],
                item["id"],
                item["source"],
                item["requestUrl"],
                item["path"],
                _display(item["actual"]),
                _display(item["expected"]),
            ),
        ),
        "requests": sorted(
            (
                {
                    "requestKey": item.requestKey,
                    "finalStatus": item.finalStatus,
                    "attemptStatuses": [
                        attempt.status for attempt in item.attempts
                    ],
                    "budgetExhausted": item.budgetExhausted,
                }
                for item in report.requests
            ),
            key=lambda item: item["requestKey"],
        ),
    }
    return hashlib.sha256(
        json.dumps(
            semantic,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _display(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return repr(value)


def _json_loads(raw: str) -> Any:
    return json.loads(
        raw,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant {value}")
        ),
    )


def _load_json(path: Path) -> Any:
    try:
        return _json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RegistryError(f"{path}: {exc}") from exc


def _fingerprint_bytes(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _fingerprint_value(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _fingerprint_bytes(canonical)


def _result(
    attestation_id: str,
    source: str,
    path: str,
    status: str,
    actual: Any,
    expected: Any,
    fix: str,
    *,
    context: bytes | Any = b"",
    request_url: str | None = None,
) -> AttestationResult:
    if isinstance(context, bytes):
        fingerprint = _fingerprint_bytes(context)
    else:
        fingerprint = _fingerprint_value(context)
    return AttestationResult(
        attestation_id,
        source,
        request_url or source,
        path,
        status,
        actual,
        expected,
        fingerprint,
        fix,
    )


def _safe_path(root: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise RegistryError("path must be a non-empty repository-relative string")
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise RegistryError(f"path escapes repository root: {relative_path}") from exc
    return candidate


def _exact_fields(value: Any, expected: frozenset[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _parse_date(value: Any, field_name: str) -> date:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", value
    ):
        raise RegistryError(f"{field_name} must be ISO YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"{field_name} is not a real calendar day") from exc
    if parsed.isoformat() != value:
        raise RegistryError(f"{field_name} must use canonical ISO format")
    return parsed


def _finite_json(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return not isinstance(value, float) or math.isfinite(value)
    if value is None or isinstance(value, str):
        return True
    if isinstance(value, list):
        return all(_finite_json(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _finite_json(item)
            for key, item in value.items()
        )
    return False


def _value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__


def _valid_unit_tree(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value) and len(value) <= MAX_PARAMETER_TEXT
    if isinstance(value, list):
        return bool(value) and all(_valid_unit_tree(item) for item in value)
    if isinstance(value, dict):
        return bool(value) and all(
            isinstance(key, str) and _valid_unit_tree(item)
            for key, item in value.items()
        )
    return False


def _unit_tree_aligned(unit: Any, value: Any) -> bool:
    if isinstance(unit, str):
        return True
    if isinstance(unit, dict):
        return (
            isinstance(value, dict)
            and set(unit) == set(value)
            and all(_unit_tree_aligned(unit[key], value[key]) for key in unit)
        )
    if isinstance(unit, list):
        return (
            isinstance(value, list)
            and len(unit) == len(value)
            and all(
                _unit_tree_aligned(unit_item, value_item)
                for unit_item, value_item in zip(unit, value)
            )
        )
    return False


def _resolve_expected_unit(unit: Any, pointer: str) -> str:
    if isinstance(unit, str):
        return unit
    resolved = _resolve_pointer(unit, pointer)
    if not isinstance(resolved, str):
        raise RegistryError("expected unit path did not resolve to a string")
    return resolved


def _host_allowed(hostname: str, jurisdiction: str) -> bool:
    normalized = hostname.lower().rstrip(".")
    return any(
        normalized == domain or normalized.endswith("." + domain)
        for domain in OFFICIAL_DOMAINS.get(jurisdiction, ())
    )


def _validate_official_url(value: Any, jurisdiction: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegistryError("source URL must be a non-empty string")
    try:
        parsed = urllib_parse.urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise RegistryError(f"malformed source URL: {exc}") from exc
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RegistryError(
            "source URL must be absolute HTTPS without embedded credentials"
        )
    if not _host_allowed(hostname, jurisdiction):
        raise RegistryError(
            f"host {hostname!r} is not official for {jurisdiction}"
        )
    return value


def _canonical_hostname(url: str) -> str:
    hostname = urllib_parse.urlsplit(url).hostname
    if hostname is None:
        raise RegistryError("URL has no hostname")
    return hostname.encode("idna").decode("ascii").lower().rstrip(".")


def _pointer_parts(pointer: Any) -> list[str]:
    if pointer == "/":
        return []
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise RegistryError("reviewedPath/JSON pointer must start with '/'")
    parts = [
        item.replace("~1", "/").replace("~0", "~")
        for item in pointer[1:].split("/")
    ]
    if len(parts) > MAX_POINTER_DEPTH or any(not item for item in parts):
        raise RegistryError("pointer is empty, too deep, or contains empty segments")
    return parts


def _resolve_pointer(value: Any, pointer: str) -> Any:
    current = value
    traversed = "/"
    for part in _pointer_parts(pointer):
        if isinstance(current, dict):
            if part not in current:
                raise RegistryError(f"{traversed} has no property {part!r}")
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                raise RegistryError(f"{traversed} has no index {index}")
            current = current[index]
        else:
            raise RegistryError(f"{traversed} cannot traverse {part!r}")
        traversed = (
            f"/{part}" if traversed == "/" else f"{traversed}/{part}"
        )
    return current


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _leaf_paths(value: Any, pointer: str = "/") -> list[str]:
    if isinstance(value, dict):
        paths: list[str] = []
        for key, child in value.items():
            child_path = (
                f"/{_escape_pointer(key)}"
                if pointer == "/"
                else f"{pointer}/{_escape_pointer(key)}"
            )
            paths.extend(_leaf_paths(child, child_path))
        return paths
    if isinstance(value, list):
        paths = []
        for index, child in enumerate(value):
            child_path = (
                f"/{index}" if pointer == "/" else f"{pointer}/{index}"
            )
            paths.extend(_leaf_paths(child, child_path))
        return paths
    return [pointer]


def _path_covers(parent: str, child: str) -> bool:
    return parent == "/" or parent == child or child.startswith(parent + "/")


def _validate_text(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_PARAMETER_TEXT
    ):
        raise RegistryError(
            f"{field_name} must be a non-empty string up to "
            f"{MAX_PARAMETER_TEXT} characters"
        )
    return value


def _validate_anchor_text(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ANCHOR_TEXT
    ):
        raise RegistryError(
            f"{field_name} must be a non-empty exact string up to "
            f"{MAX_ANCHOR_TEXT} characters"
        )
    return value


def _validate_value_types(value: Any, expected_length: int) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) != expected_length
        or any(item not in VALUE_TYPES for item in value)
    ):
        raise RegistryError(
            f"valueTypes must contain {expected_length} allowlisted parser enums"
        )
    return value


def _validate_request(
    value: Any,
    source_url: str,
    jurisdiction: str,
    *,
    source_relation: str = "same-host",
    candidate: bool = False,
) -> None:
    if not isinstance(value, dict) or value.get("method") not in {
        "GET",
        "POST",
    }:
        raise RegistryError("request.method must be GET or POST")
    if value["method"] == "GET":
        if set(value) == REQUEST_GET_FIELDS:
            return
        if set(value) != REQUEST_GET_URL_FIELDS:
            raise RegistryError(
                "GET request supports exact {method} or {method,url}"
            )
        request_url = value["url"]
        if not isinstance(request_url, str) or len(request_url) > 2048:
            raise RegistryError("GET request.url must be at most 2048 characters")
        _validate_official_url(request_url, jurisdiction)
        parsed_request = urllib_parse.urlsplit(request_url)
        if parsed_request.fragment:
            raise RegistryError("GET request.url may not contain a fragment")
        if not candidate and parsed_request.query:
            raise RegistryError(
                "GET request.url override may not contain query or fragment"
            )
        _validate_source_relation(
            request_url, source_url, source_relation, jurisdiction
        )
        return
    if set(value) != REQUEST_POST_FIELDS:
        raise RegistryError(
            "POST request requires exactly method, url, and jsonBody"
        )
    request_url = value["url"]
    if not isinstance(request_url, str) or len(request_url) > 2048:
        raise RegistryError("POST request.url must be at most 2048 characters")
    _validate_official_url(request_url, jurisdiction)
    _validate_source_relation(
        request_url, source_url, source_relation, jurisdiction
    )
    body = value["jsonBody"]
    if (
        not isinstance(body, dict)
        or not 1 <= len(body) <= 16
        or any(
            not isinstance(key, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key)
            for key in body
        )
        or any(
            isinstance(item, (dict, list))
            or not _finite_json(item)
            for item in body.values()
        )
    ):
        raise RegistryError(
            "POST jsonBody must be a 1-16 item flat bounded scalar object"
        )
    serialized = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(serialized) > 4096:
        raise RegistryError("POST jsonBody exceeds 4096 canonical bytes")


def _validate_source_relation(
    request_url: str,
    source_url: str,
    source_relation: str,
    jurisdiction: str,
) -> None:
    if source_relation not in CANDIDATE_RELATIONS:
        raise RegistryError("sourceRelation is unsupported")
    if source_relation == "citation" and request_url != source_url:
        raise RegistryError(
            "citation candidate request URL must exactly equal sourceUrl"
        )
    if (
        source_relation == "same-host"
        and _canonical_hostname(source_url)
        != _canonical_hostname(request_url)
    ):
        raise RegistryError(
            "same-host candidate must use the citation canonical hostname"
        )
    if source_relation == "jurisdiction-official":
        _validate_official_url(request_url, jurisdiction)


def _validate_live_policy(value: Any) -> dict[str, Any]:
    if not _exact_fields(value, LIVE_POLICY_FIELDS):
        raise RegistryError(
            "livePolicy must contain exactly mode, reason, and manualReviewDays"
        )
    if value["mode"] not in LIVE_POLICY_MODES:
        raise RegistryError("livePolicy.mode must be extract or fixture-only")
    _validate_text(value["reason"], "livePolicy.reason")
    days = value["manualReviewDays"]
    if (
        not isinstance(days, int)
        or isinstance(days, bool)
        or not 1 <= days <= 30
    ):
        raise RegistryError(
            "livePolicy.manualReviewDays must be an integer 1-30"
        )
    return value


def _live_policy(attestation: dict[str, Any]) -> dict[str, Any]:
    return attestation.get(
        "livePolicy",
        {
            "mode": "extract",
            "reason": "Safe reviewed extractor is available.",
            "manualReviewDays": 30,
        },
    )


def _manual_review_status(
    attestation: dict[str, Any], today: date
) -> dict[str, Any] | None:
    policy = _live_policy(attestation)
    if policy["mode"] != "fixture-only":
        return None
    verified = _parse_date(attestation["verifiedAt"], "verifiedAt")
    due = verified + timedelta(days=policy["manualReviewDays"])
    return {
        "verifiedAt": verified.isoformat(),
        "dueDate": due.isoformat(),
        "daysOverdue": max(0, (today - due).days),
        "evidenceFingerprint": attestation["fixture"]["sha256"],
        "reason": policy["reason"],
        "manualReviewDays": policy["manualReviewDays"],
    }


def _validate_extractor(extractor: Any) -> None:
    if not _exact_fields(extractor, EXTRACTOR_FIELDS):
        raise RegistryError("extractor must contain exactly mode and params")
    mode = extractor["mode"]
    params = extractor["params"]
    if mode not in EXTRACTOR_MODES or not isinstance(params, dict):
        raise RegistryError(f"unsupported extractor mode {mode!r}")
    if mode == "html-table":
        if not _exact_fields(params, TABLE_PARAMETER_FIELDS):
            raise RegistryError("html-table params do not match the strict schema")
        _validate_text(params["caption"], "caption")
        headers = params["headers"]
        if (
            not isinstance(headers, list)
            or not 1 <= len(headers) <= 12
            or any(_validate_text(item, "header") != item for item in headers)
        ):
            raise RegistryError("headers must contain 1-12 exact text labels")
        _validate_text(params["unitLabel"], "unitLabel")
        _validate_text(params["nullToken"], "nullToken")
        _validate_value_types(params["valueTypes"], len(headers))
        return
    if mode == "html-definition":
        if not _exact_fields(params, DEFINITION_PARAMETER_FIELDS):
            raise RegistryError(
                "html-definition params do not match the strict schema"
            )
        _validate_text(params["section"], "section")
        _validate_text(params["unitLabel"], "unitLabel")
        if params["result"] not in {"scalar", "object"}:
            raise RegistryError("html-definition result must be scalar or object")
        fields = params["fields"]
        if not isinstance(fields, list) or not 1 <= len(fields) <= 24:
            raise RegistryError("html-definition fields must contain 1-24 items")
        if params["result"] == "scalar" and len(fields) != 1:
            raise RegistryError("scalar html-definition requires exactly one field")
        keys: set[str] = set()
        for field_spec in fields:
            if not _exact_fields(field_spec, DEFINITION_FIELD_FIELDS):
                raise RegistryError("definition field has unsupported keys")
            key = _validate_text(field_spec["key"], "field.key")
            _validate_text(field_spec["label"], "field.label")
            if field_spec["valueType"] not in VALUE_TYPES:
                raise RegistryError("definition valueType is unsupported")
            if key in keys:
                raise RegistryError("definition field keys must be unique")
            keys.add(key)
        return
    if mode == "html-table-record":
        if not _exact_fields(params, HTML_RECORD_PARAMETER_FIELDS):
            raise RegistryError(
                "html-table-record params do not match the strict schema"
            )
        _validate_text(params["section"], "section")
        headers = params["headers"]
        if (
            not isinstance(headers, list)
            or not 2 <= len(headers) <= 12
            or any(_validate_text(item, "header") != item for item in headers)
            or len(set(headers)) != len(headers)
        ):
            raise RegistryError(
                "html-table-record headers require 2-12 unique labels"
            )
        if params["result"] not in {"scalar", "object"}:
            raise RegistryError(
                "html-table-record result must be scalar or object"
            )
        fields = params["fields"]
        if not isinstance(fields, list) or not 1 <= len(fields) <= 24:
            raise RegistryError(
                "html-table-record fields must contain 1-24 items"
            )
        if params["result"] == "scalar" and len(fields) != 1:
            raise RegistryError(
                "scalar html-table-record requires exactly one field"
            )
        keys: set[str] = set()
        for field_spec in fields:
            if not _exact_fields(field_spec, HTML_RECORD_FIELD_FIELDS):
                raise RegistryError(
                    "html-table-record field has unsupported keys"
                )
            key = _validate_text(field_spec["key"], "field.key")
            if key in keys:
                raise RegistryError("html-table-record field keys must be unique")
            keys.add(key)
            labels = field_spec["rowLabels"]
            if (
                not isinstance(labels, list)
                or not 1 <= len(labels) <= 32
                or len(set(labels)) != len(labels)
                or any(
                    _validate_text(label, "rowLabel") != label
                    for label in labels
                )
            ):
                raise RegistryError(
                    "rowLabels require 1-32 unique exact strings"
                )
            if field_spec["valueHeader"] not in headers:
                raise RegistryError("valueHeader must occur in headers")
            if field_spec["transform"] not in HTML_VALUE_TRANSFORMS:
                raise RegistryError("html table transform is unsupported")
            if not _valid_unit_tree(field_spec["unit"]):
                raise RegistryError("field.unit must be a non-empty safe unit tree")
            if (
                field_spec["transform"] in {
                    "tax-brackets",
                    "tax-brackets-serialization",
                }
                and len(labels) < 2
            ):
                raise RegistryError(
                    "tax-brackets requires at least two exact rows"
                )
            if field_spec["transform"] == "ato-first-tax-band" and (
                len(labels) != 1
                or field_spec["unit"] != ATO_FIRST_BAND_UNIT
            ):
                raise RegistryError(
                    "ato-first-tax-band requires one row and its fixed unit tree"
                )
            if field_spec["transform"] == "ato-law-first-tax-band" and (
                params["result"] != "scalar"
                or len(fields) != 1
                or headers != ATO_LAW_FIRST_BAND_HEADERS
                or labels != ["1"]
                or field_spec["valueHeader"] != "The rate is:"
                or field_spec["unit"] != ATO_FIRST_BAND_UNIT
            ):
                raise RegistryError(
                    "ato-law-first-tax-band requires its exact title-table "
                    "headers, item 1, rate column, scalar result, and fixed "
                    "unit tree"
                )
        return
    if mode == "html-labelled-values":
        if not _exact_fields(params, HTML_LABELLED_PARAMETER_FIELDS):
            raise RegistryError(
                "html-labelled-values params do not match the strict schema"
            )
        _validate_text(params["anchor"], "anchor")
        if params["result"] not in {"scalar", "object"}:
            raise RegistryError(
                "html-labelled-values result must be scalar or object"
            )
        fields = params["fields"]
        if not isinstance(fields, list) or not 1 <= len(fields) <= 24:
            raise RegistryError(
                "html-labelled-values fields must contain 1-24 items"
            )
        if params["result"] == "scalar" and len(fields) != 1:
            raise RegistryError(
                "scalar html-labelled-values requires exactly one field"
            )
        keys: set[str] = set()
        labels: set[str] = set()
        for field_spec in fields:
            if not _exact_fields(field_spec, HTML_LABELLED_FIELD_FIELDS):
                raise RegistryError(
                    "html-labelled-values field has unsupported keys"
                )
            key = _validate_text(field_spec["key"], "field.key")
            label = _validate_text(field_spec["label"], "field.label")
            if key in keys or label in labels:
                raise RegistryError("labelled field keys/labels must be unique")
            keys.add(key)
            labels.add(label)
            if field_spec["transform"] not in (
                HTML_VALUE_TRANSFORMS
                - {"tax-brackets", "tax-brackets-serialization"}
            ):
                raise RegistryError("labelled value transform is unsupported")
            _validate_text(field_spec["unit"], "field.unit")
        return
    if mode == "html-text-anchor":
        if not _exact_fields(params, HTML_TEXT_PARAMETER_FIELDS):
            raise RegistryError(
                "html-text-anchor params do not match the strict schema"
            )
        _validate_anchor_text(params["anchor"], "anchor")
        if params["transform"] not in (
            HTML_VALUE_TRANSFORMS
            - {"tax-brackets", "tax-brackets-serialization"}
        ):
            raise RegistryError("text anchor transform is unsupported")
        _validate_text(params["unit"], "unit")
        return
    if mode == "html-section-text":
        if not _exact_fields(params, HTML_SECTION_TEXT_PARAMETER_FIELDS):
            raise RegistryError(
                "html-section-text requires heading, anchor, transform, and unit"
            )
        _validate_anchor_text(params["heading"], "heading")
        _validate_anchor_text(params["anchor"], "anchor")
        if params["transform"] not in HTML_SECTION_TEXT_TRANSFORMS:
            raise RegistryError(
                "html-section-text transform must be inclusive-range or "
                "duration-months"
            )
        _validate_text(params["unit"], "unit")
        return
    if mode == "ato-lito":
        if not _exact_fields(params, ATO_LITO_PARAMETER_FIELDS):
            raise RegistryError("ato-lito params require anchor and items")
        _validate_text(params["anchor"], "anchor")
        items = params["items"]
        if (
            not isinstance(items, list)
            or len(items) != 3
            or len(set(items)) != 3
            or any(
                _validate_anchor_text(item, "ato-lito item") != item
                for item in items
            )
        ):
            raise RegistryError("ato-lito items require 3 unique exact texts")
        return
    if mode == "ato-law-lito":
        if not _exact_fields(params, ATO_LAW_LITO_PARAMETER_FIELDS):
            raise RegistryError(
                "ato-law-lito requires actTitle, section, sectionTitle, and tableTitle"
            )
        for key in ATO_LAW_LITO_PARAMETER_FIELDS:
            _validate_anchor_text(params[key], f"ato-law-lito {key}")
        return
    if mode == "ato-law-resident-brackets":
        if not _exact_fields(params, ATO_LAW_RESIDENT_PARAMETER_FIELDS):
            raise RegistryError(
                "ato-law-resident-brackets requires exact tableTitle"
            )
        _validate_anchor_text(params["tableTitle"], "resident tableTitle")
        return
    if mode == "ato-tax-free-band":
        if not _exact_fields(params, ATO_TAX_FREE_PARAMETER_FIELDS):
            raise RegistryError(
                "ato-tax-free-band requires exact heading and anchor"
            )
        _validate_anchor_text(params["heading"], "tax-free heading")
        _validate_anchor_text(params["anchor"], "tax-free anchor")
        return
    if mode == "cra-t4127-version":
        if (
            not _exact_fields(params, CRA_T4127_PARAMETER_FIELDS)
            or params["language"] not in {"en", "fr"}
        ):
            raise RegistryError(
                "cra-t4127-version requires exact language en or fr"
            )
        return
    if mode == "cra-t4127-csv":
        if not _exact_fields(params, CRA_T4127_CSV_PARAMETER_FIELDS):
            raise RegistryError(
                "cra-t4127-csv requires publication, effectiveDate, "
                "encoding, and cohort"
            )
        spec = CRA_T4127_CSV_SPECS.get(params["cohort"])
        if spec is None:
            raise RegistryError("cra-t4127-csv cohort is unsupported")
        if params["encoding"] not in CRA_T4127_CSV_ENCODINGS:
            raise RegistryError("cra-t4127-csv encoding is unsupported")
        _parse_date(params["effectiveDate"], "csv effectiveDate")
        if (
            params["publication"] != spec["publication"]
            or params["effectiveDate"] != spec["effectiveDate"]
        ):
            raise RegistryError(
                "cra-t4127-csv publication/effectiveDate differs from its "
                "reviewed cohort"
            )
        return
    if mode == "cra-t4127-bc-annual-rate":
        if (
            not _exact_fields(params, CRA_T4127_BC_PARAMETER_FIELDS)
            or params["effectiveYear"] != 2026
        ):
            raise RegistryError(
                "cra-t4127-bc-annual-rate requires effectiveYear 2026"
            )
        return
    if mode == "cra-t4032-on":
        if not _exact_fields(params, CRA_T4032_ON_PARAMETER_FIELDS):
            raise RegistryError(
                "cra-t4032-on requires exact effectiveDate"
            )
        if params["effectiveDate"] != "2026-01-01":
            raise RegistryError(
                "cra-t4032-on currently supports effectiveDate 2026-01-01"
            )
        return
    if mode == "pdf-table":
        if not _exact_fields(params, PDF_PARAMETER_FIELDS):
            raise RegistryError("pdf-table params do not match the strict schema")
        _validate_text(params["anchor"], "anchor")
        _validate_text(params["unitLabel"], "unitLabel")
        _validate_text(params["nullToken"], "nullToken")
        delimiter = _validate_text(params["delimiter"], "delimiter")
        if len(delimiter) != 1:
            raise RegistryError("pdf delimiter must be exactly one character")
        headers = params["headers"]
        if (
            not isinstance(headers, list)
            or not 1 <= len(headers) <= 12
            or any(_validate_text(item, "header") != item for item in headers)
        ):
            raise RegistryError("pdf headers must contain 1-12 labels")
        _validate_value_types(params["valueTypes"], len(headers))
        return
    if mode == "api-json-record":
        keys = set(params) if isinstance(params, dict) else set()
        if not API_RECORD_REQUIRED_FIELDS <= keys or not keys <= (
            API_RECORD_REQUIRED_FIELDS | API_RECORD_OPTIONAL_FIELDS
        ):
            raise RegistryError(
                "api-json-record params contain unsupported or missing fields"
            )
        _pointer_parts(params["arrayPointer"])
        _pointer_parts(params["valuePointer"])
        match = params["match"]
        if (
            not isinstance(match, dict)
            or not 1 <= len(match) <= 3
            or any(
                not isinstance(key, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key)
                or not isinstance(value, str)
                or not 1 <= len(value) <= MAX_PARAMETER_TEXT
                for key, value in match.items()
            )
        ):
            raise RegistryError(
                "api-json-record match requires 1-3 exact bounded strings"
            )
        transform = params.get("transform", "identity")
        if transform not in API_RECORD_TRANSFORMS:
            raise RegistryError("api-json-record transform is unsupported")
        return
    if not _exact_fields(params, JSON_PARAMETER_FIELDS):
        raise RegistryError("JSON extractor params must contain exactly pointer")
    _pointer_parts(params["pointer"])


def _media_type(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def _validate_fixture(root: Path, fixture: Any, jurisdiction: str) -> None:
    if not _exact_fields(fixture, FIXTURE_FIELDS):
        raise RegistryError("fixture has unsupported or missing fields")
    fixture_path = _safe_path(root, fixture["path"])
    if not fixture_path.is_file():
        raise RegistryError(f"fixture file does not exist: {fixture['path']}")
    if (
        not isinstance(fixture["mediaType"], str)
        or not fixture["mediaType"]
    ):
        raise RegistryError("fixture.mediaType must be a non-empty string")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(fixture["sha256"])):
        raise RegistryError("fixture.sha256 must be a full lowercase SHA-256")
    if (
        not isinstance(fixture["httpStatus"], int)
        or isinstance(fixture["httpStatus"], bool)
        or not 100 <= fixture["httpStatus"] <= 599
    ):
        raise RegistryError("fixture.httpStatus must be an integer HTTP status")
    _validate_official_url(fixture["finalUrl"], jurisdiction)


def _candidate_policy(attestation: dict[str, Any]) -> str:
    policy = attestation.get("candidatePolicy", {"mode": "first-match"})
    return policy["mode"]


def _candidate_contexts(
    attestation: dict[str, Any],
) -> list[tuple[str, dict[str, Any], str]]:
    candidates = attestation.get("requestCandidates")
    if candidates is None:
        return [
            (
                "primary",
                attestation,
                attestation["fixture"]["mediaType"],
            )
        ]
    contexts: list[tuple[str, dict[str, Any], str]] = []
    for candidate in candidates:
        context = dict(attestation)
        context["request"] = candidate["request"]
        context["fixture"] = candidate["fixture"]
        context["extractor"] = candidate.get(
            "extractor", attestation["extractor"]
        )
        context["_sourceRelation"] = candidate["sourceRelation"]
        context["_candidateMediaType"] = candidate["mediaType"]
        contexts.append((candidate["id"], context, candidate["mediaType"]))
    return contexts


def _validate_request_candidates(
    root: Path,
    attestation: dict[str, Any],
    jurisdiction: str,
    source_fixtures: dict[str, tuple[Any, ...]],
) -> None:
    raw_policy = attestation.get("candidatePolicy")
    if raw_policy is not None and (
        not _exact_fields(raw_policy, CANDIDATE_POLICY_FIELDS)
        or raw_policy["mode"] not in CANDIDATE_POLICY_MODES
    ):
        raise RegistryError(
            "candidatePolicy requires exact mode first-match or available-parity"
        )
    candidates = attestation.get("requestCandidates")
    if candidates is None:
        if raw_policy is not None:
            raise RegistryError(
                "candidatePolicy requires requestCandidates"
            )
        candidates = [
            {
                "id": "primary",
                "sourceRelation": (
                    "citation"
                    if _request_url(attestation) == attestation["sourceUrl"]
                    else "same-host"
                ),
                "request": attestation["request"],
                "mediaType": attestation["fixture"]["mediaType"],
                "extractor": attestation["extractor"],
                "fixture": attestation["fixture"],
            }
        ]
    if (
        not isinstance(candidates, list)
        or not 1 <= len(candidates) <= MAX_REQUEST_CANDIDATES
    ):
        raise RegistryError(
            f"requestCandidates must contain 1-{MAX_REQUEST_CANDIDATES} items"
        )
    seen_ids: set[str] = set()
    seen_requests: set[str] = set()
    for index, candidate_spec in enumerate(candidates):
        if (
            not isinstance(candidate_spec, dict)
            or not REQUEST_CANDIDATE_REQUIRED_FIELDS
            <= set(candidate_spec)
            or not set(candidate_spec)
            <= (
                REQUEST_CANDIDATE_REQUIRED_FIELDS
                | REQUEST_CANDIDATE_OPTIONAL_FIELDS
            )
        ):
            raise RegistryError(
                "candidate requires id, sourceRelation, request, mediaType, "
                "fixture, and optional extractor"
            )
        candidate_id = candidate_spec["id"]
        if (
            not isinstance(candidate_id, str)
            or not re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{1,39}", candidate_id
            )
            or candidate_id in seen_ids
        ):
            raise RegistryError(
                "candidate id must be a unique 2-40 character slug"
            )
        seen_ids.add(candidate_id)
        relation = candidate_spec["sourceRelation"]
        _validate_request(
            candidate_spec["request"],
            attestation["sourceUrl"],
            jurisdiction,
            source_relation=relation,
            candidate=True,
        )
        media_type = candidate_spec["mediaType"]
        if media_type not in SUPPORTED_CANDIDATE_MEDIA:
            raise RegistryError(
                "candidate mediaType must be a supported exact media type"
            )
        extractor = candidate_spec.get(
            "extractor", attestation["extractor"]
        )
        _validate_extractor(extractor)
        if not _expected_media(extractor["mode"], media_type):
            raise RegistryError(
                "candidate mediaType is incompatible with its extractor"
            )
        fixture = candidate_spec["fixture"]
        _validate_fixture(root, fixture, jurisdiction)
        candidate_context = dict(attestation)
        candidate_context["request"] = candidate_spec["request"]
        candidate_context["extractor"] = extractor
        candidate_context["fixture"] = fixture
        _validate_cra_csv_context(candidate_context, media_type)
        if fixture["finalUrl"] != _request_url(candidate_context):
            raise RegistryError(
                "candidate fixture.finalUrl must equal its request URL"
            )
        if fixture["mediaType"] != media_type:
            raise RegistryError(
                "candidate fixture.mediaType must equal candidate mediaType"
            )
        if index == 0 and (
            candidate_spec["request"] != attestation["request"]
            or extractor != attestation["extractor"]
            or fixture != attestation["fixture"]
        ):
            raise RegistryError(
                "first candidate must exactly mirror root request/extractor/fixture"
            )
        request_key = _request_key(candidate_context)
        if request_key in seen_requests:
            raise RegistryError(
                "one attestation may not repeat a canonical candidate request"
            )
        seen_requests.add(request_key)
        fixture_key = (
            fixture["path"],
            fixture["mediaType"],
            fixture["sha256"],
            fixture["httpStatus"],
            fixture["finalUrl"],
        )
        previous_fixture = source_fixtures.setdefault(
            request_key, fixture_key
        )
        if previous_fixture != fixture_key:
            raise RegistryError(
                "one canonical candidate request must use one fixture response"
            )


def _target_map(boundary_data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(boundary_data, dict) or not isinstance(
        boundary_data.get("targets"), list
    ):
        raise RegistryError("boundary manifest must contain targets[]")
    targets: dict[str, dict[str, Any]] = {}
    for target in boundary_data["targets"]:
        if not isinstance(target, dict) or not isinstance(
            target.get("id"), str
        ):
            raise RegistryError("boundary target must have a string id")
        if target["id"] in targets:
            raise RegistryError(f"duplicate boundary target {target['id']}")
        if not isinstance(target.get("reviewed"), dict):
            raise RegistryError(f"target {target['id']} has no reviewed object")
        targets[target["id"]] = target
    return targets


def _target_component_map(
    registry: dict[str, Any],
    targets: dict[str, dict[str, Any]],
    target_leaf_paths: dict[str, set[str]],
) -> dict[str, dict[str, set[str]]]:
    raw_scopes = registry.get("targetComponents")
    if raw_scopes is None:
        return {}
    if (
        not isinstance(raw_scopes, list)
        or not 1 <= len(raw_scopes) <= len(targets)
    ):
        raise RegistryError(
            "targetComponents must contain 1..target-count scopes"
        )
    scoped: dict[str, dict[str, set[str]]] = {}
    for raw_scope in raw_scopes:
        if not _exact_fields(raw_scope, TARGET_COMPONENT_SCOPE_FIELDS):
            raise RegistryError(
                "targetComponents entry requires targetId and components"
            )
        target_id = raw_scope["targetId"]
        if target_id not in targets:
            raise RegistryError(
                f"targetComponents contains unknown target {target_id!r}"
            )
        if target_id in scoped:
            raise RegistryError(
                f"targetComponents repeats target {target_id!r}"
            )
        raw_components = raw_scope["components"]
        if (
            not isinstance(raw_components, list)
            or not 2 <= len(raw_components) <= 64
        ):
            raise RegistryError(
                "component target requires 2-64 reviewed components"
            )
        components: dict[str, set[str]] = {}
        declared: list[tuple[str, str]] = []
        for raw_component in raw_components:
            if not _exact_fields(raw_component, TARGET_COMPONENT_FIELDS):
                raise RegistryError(
                    "component requires exactly id and reviewedPaths"
                )
            component_id = raw_component["id"]
            if (
                not isinstance(component_id, str)
                or not re.fullmatch(
                    r"[a-z0-9][a-z0-9._-]{2,79}", component_id
                )
                or component_id in components
            ):
                raise RegistryError(
                    "component id must be a unique 3-80 character slug"
                )
            raw_paths = raw_component["reviewedPaths"]
            if (
                not isinstance(raw_paths, list)
                or not 1 <= len(raw_paths) <= 64
                or len(set(raw_paths)) != len(raw_paths)
            ):
                raise RegistryError(
                    "component reviewedPaths requires 1-64 unique pointers"
                )
            paths: set[str] = set()
            for reviewed_path in raw_paths:
                _pointer_parts(reviewed_path)
                if reviewed_path == "/":
                    raise RegistryError(
                        "component coverage forbids a monolithic root mapping"
                    )
                _resolve_pointer(
                    targets[target_id]["reviewed"], reviewed_path
                )
                for other_path, other_component in declared:
                    if _path_covers(
                        other_path, reviewed_path
                    ) or _path_covers(reviewed_path, other_path):
                        raise RegistryError(
                            "component path overlaps "
                            f"{other_component}:{target_id}{other_path}"
                        )
                declared.append((reviewed_path, component_id))
                paths.add(reviewed_path)
            components[component_id] = paths
        for leaf in target_leaf_paths[target_id]:
            owners = [
                component_id
                for reviewed_path, component_id in declared
                if _path_covers(reviewed_path, leaf)
            ]
            if len(owners) != 1:
                raise RegistryError(
                    f"component declaration covers {target_id}{leaf} "
                    f"{len(owners)} times"
                )
        scoped[target_id] = components
    return scoped


def _request_key(attestation: dict[str, Any]) -> str:
    request = attestation["request"]
    body = (
        json.dumps(
            request["jsonBody"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if request["method"] == "POST"
        else ""
    )
    return f"{_request_url(attestation)}\0{request['method']}\0{body}"


def _public_request_key(attestation: dict[str, Any]) -> str:
    return _fingerprint_bytes(_request_key(attestation).encode("utf-8"))


def _request_url(attestation: dict[str, Any]) -> str:
    request = attestation["request"]
    return request.get("url", attestation["sourceUrl"])


def _validate_cra_csv_context(
    attestation: dict[str, Any], media_type: str
) -> None:
    extractor = attestation["extractor"]
    if extractor["mode"] != "cra-t4127-csv":
        return
    spec = CRA_T4127_CSV_SPECS[extractor["params"]["cohort"]]
    request_url = _request_url(attestation)
    parsed = urllib_parse.urlsplit(request_url)
    if (
        attestation["request"]["method"] != "GET"
        or _canonical_hostname(request_url) != "www.canada.ca"
        or parsed.path != spec["path"]
        or parsed.query
        or parsed.fragment
    ):
        raise RegistryError(
            "cra-t4127-csv request must use its exact reviewed www.canada.ca "
            "CSV path without query or fragment"
        )
    if _media_type(media_type) not in CSV_MEDIA_TYPES:
        raise RegistryError("cra-t4127-csv requires exact CSV media")


def _validate_registry(
    root: Path,
    registry: Any,
    boundary_data: Any,
    claims_data: Any,
    today: date,
    report: AttestationReport,
) -> list[dict[str, Any]]:
    if (
        not isinstance(registry, dict)
        or not REQUIRED_ROOT_FIELDS <= set(registry)
        or not set(registry) <= (REQUIRED_ROOT_FIELDS | OPTIONAL_ROOT_FIELDS)
    ):
        report.results.append(
            _result(
                "<registry>",
                "<none>",
                "/",
                "unsupported",
                sorted(registry) if isinstance(registry, dict) else registry,
                {
                    "required": sorted(REQUIRED_ROOT_FIELDS),
                    "optional": sorted(OPTIONAL_ROOT_FIELDS),
                },
                "Use the exact attestation root schema.",
            )
        )
        return []
    if registry["schemaVersion"] != SCHEMA_VERSION:
        report.results.append(
            _result(
                "<registry>",
                "<none>",
                "/schemaVersion",
                "unsupported",
                registry["schemaVersion"],
                SCHEMA_VERSION,
                "Migrate the attestation registry schema.",
            )
        )
        return []
    if not isinstance(registry["boundaryManifest"], str):
        raise RegistryError("boundaryManifest must be a path string")
    raw_attestations = registry["attestations"]
    if (
        not isinstance(raw_attestations, list)
        or not 1 <= len(raw_attestations) <= MAX_ATTESTATIONS
    ):
        raise RegistryError(
            f"attestations must contain 1-{MAX_ATTESTATIONS} entries"
        )

    targets = _target_map(boundary_data)
    if not isinstance(claims_data, dict) or not isinstance(
        claims_data.get("claims"), list
    ):
        raise RegistryError("claims registry must contain claims[]")
    claims: dict[str, dict[str, Any]] = {}
    for claim in claims_data["claims"]:
        if not isinstance(claim, dict) or not isinstance(claim.get("id"), str):
            raise RegistryError("every claim must be an object with string id")
        if claim["id"] in claims:
            raise RegistryError(f"duplicate claim id {claim['id']}")
        claims[claim["id"]] = claim
    raw_scope = registry.get("claimScope")
    scope: set[str] | None = None
    if raw_scope is not None:
        if (
            not isinstance(raw_scope, list)
            or any(
                not isinstance(claim_id, str) or not claim_id
                for claim_id in raw_scope
            )
            or len(set(raw_scope)) != len(raw_scope)
        ):
            raise RegistryError("claimScope must contain unique non-empty ids")
        scope = set(raw_scope)
        for claim_id in scope:
            claim = claims.get(claim_id)
            if claim is None:
                raise RegistryError(f"claimScope contains unknown {claim_id!r}")
            if claim.get("status") not in VALID_CLAIM_STATUSES:
                raise RegistryError(
                    f"claimScope {claim_id!r} is not official/derived"
                )
    target_leaf_paths = {
        target_id: set(_leaf_paths(target["reviewed"]))
        for target_id, target in targets.items()
    }
    target_components = _target_component_map(
        registry, targets, target_leaf_paths
    )
    seen_ids: set[str] = set()
    mapped_paths: dict[str, list[tuple[str, str]]] = {
        target_id: [] for target_id in targets
    }
    mapped_claims: dict[str, str] = {}
    source_fixtures: dict[str, tuple[Any, ...]] = {}
    valid: list[dict[str, Any]] = []

    for index, raw in enumerate(raw_attestations):
        attestation_id = (
            raw.get("id")
            if isinstance(raw, dict) and isinstance(raw.get("id"), str)
            else f"<attestation {index + 1}>"
        )
        source = (
            raw.get("sourceUrl", "<none>")
            if isinstance(raw, dict)
            else "<none>"
        )
        try:
            if not isinstance(raw, dict):
                raise RegistryError("attestation must be an object")
            keys = set(raw)
            if not REQUIRED_ATTESTATION_FIELDS <= keys or not keys <= (
                REQUIRED_ATTESTATION_FIELDS | OPTIONAL_ATTESTATION_FIELDS
            ):
                raise RegistryError(
                    "attestation has unsupported or missing fields"
                )
            if (
                not isinstance(attestation_id, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,79}", attestation_id)
            ):
                raise RegistryError("id must be a stable 3-80 character slug")
            if attestation_id in seen_ids:
                raise RegistryError(f"duplicate attestation id {attestation_id}")
            seen_ids.add(attestation_id)
            jurisdiction = raw["jurisdiction"]
            if jurisdiction not in OFFICIAL_DOMAINS:
                raise RegistryError("jurisdiction must be NZ, CA, or AU")
            _validate_official_url(raw["sourceUrl"], jurisdiction)
            _validate_request(
                raw["request"], raw["sourceUrl"], jurisdiction
            )
            if "livePolicy" in raw:
                _validate_live_policy(raw["livePolicy"])
            verified_at = _parse_date(raw["verifiedAt"], "verifiedAt")
            effective_from = _parse_date(
                raw["effectiveFrom"], "effectiveFrom"
            )
            effective_to = (
                _parse_date(raw["effectiveTo"], "effectiveTo")
                if "effectiveTo" in raw
                else None
            )
            review_days = raw["reviewAfterDays"]
            if (
                not isinstance(review_days, int)
                or isinstance(review_days, bool)
                or not 1 <= review_days <= 3650
            ):
                raise RegistryError("reviewAfterDays must be an integer 1-3650")
            if verified_at > today:
                raise RegistryError("verifiedAt must not be in the future")
            if effective_to is not None and effective_from > effective_to:
                raise RegistryError("effectiveFrom must not exceed effectiveTo")
            if today > verified_at + timedelta(days=review_days):
                raise RegistryError(
                    f"attestation expired after {review_days} review days"
                )
            if effective_to is not None and today > effective_to:
                raise RegistryError("attestation effective range has expired")
            _validate_extractor(raw["extractor"])
            expected = raw["expected"]
            if not _exact_fields(expected, EXPECTED_FIELDS):
                raise RegistryError("expected must contain type, unit, and value")
            if expected["type"] not in VALID_TYPES:
                raise RegistryError("expected.type is unsupported")
            if (
                _value_type(expected["value"]) != expected["type"]
                or not _finite_json(expected["value"])
                or not _valid_unit_tree(expected["unit"])
                or not _unit_tree_aligned(
                    expected["unit"], expected["value"]
                )
            ):
                raise RegistryError(
                    "expected value/unit has wrong shape, empty unit, or non-finite value"
                )
            _validate_fixture(root, raw["fixture"], jurisdiction)
            if raw["fixture"]["finalUrl"] != _request_url(raw):
                raise RegistryError(
                    "fixture.finalUrl must equal the deterministic request URL"
                )
            _validate_request_candidates(
                root, raw, jurisdiction, source_fixtures
            )

            target_mappings = raw.get("targets", [])
            claim_mappings = raw.get("claims", [])
            if not target_mappings and not claim_mappings:
                raise RegistryError(
                    "attestation requires non-empty targets or claims"
                )
            if "targets" in raw and (
                not isinstance(target_mappings, list)
                or not 1 <= len(target_mappings) <= MAX_TARGETS_PER_ATTESTATION
            ):
                raise RegistryError(
                    f"targets must contain 1-{MAX_TARGETS_PER_ATTESTATION} mappings"
                )
            if "claims" in raw and (
                not isinstance(claim_mappings, list)
                or not 1 <= len(claim_mappings) <= 64
            ):
                raise RegistryError("claims must contain 1-64 mappings")

            local_target_pairs: list[tuple[str, str]] = []
            seen_local_targets: set[tuple[str, str]] = set()
            for mapping in target_mappings:
                if (
                    not isinstance(mapping, dict)
                    or not REQUIRED_TARGET_FIELDS <= set(mapping)
                    or not set(mapping) <= (
                        REQUIRED_TARGET_FIELDS | OPTIONAL_TARGET_FIELDS
                    )
                ):
                    raise RegistryError(
                        "target mapping requires targetId, reviewedPath, and "
                        "optional expectedPath"
                    )
                target_id = mapping["targetId"]
                reviewed_path = mapping["reviewedPath"]
                expected_path = mapping.get("expectedPath", "/")
                component_id = mapping.get("componentId")
                if target_id not in targets:
                    raise RegistryError(f"unknown boundary target {target_id!r}")
                if target_id in target_components:
                    if not isinstance(component_id, str):
                        raise RegistryError(
                            f"component target {target_id!r} requires componentId"
                        )
                    component_paths = target_components[target_id].get(
                        component_id
                    )
                    if (
                        component_paths is None
                        or reviewed_path not in component_paths
                    ):
                        raise RegistryError(
                            f"{target_id}{reviewed_path} is not declared for "
                            f"component {component_id!r}"
                        )
                elif component_id is not None:
                    raise RegistryError(
                        f"unscoped target {target_id!r} may not use componentId"
                    )
                _pointer_parts(reviewed_path)
                _pointer_parts(expected_path)
                resolved = _resolve_pointer(
                    targets[target_id]["reviewed"], reviewed_path
                )
                expected_resolved = _resolve_pointer(
                    expected["value"], expected_path
                )
                pair = (target_id, reviewed_path)
                if pair in seen_local_targets:
                    raise RegistryError("duplicate target mapping in attestation")
                seen_local_targets.add(pair)
                if resolved != expected_resolved:
                    raise RegistryError(
                        f"{target_id}{reviewed_path} differs from "
                        f"expected.value{expected_path}"
                    )
                for other_path, other_id in mapped_paths[target_id]:
                    if _path_covers(other_path, reviewed_path) or _path_covers(
                        reviewed_path, other_path
                    ):
                        raise RegistryError(
                            f"mapping overlaps {other_id}:{target_id}{other_path}"
                        )
                local_target_pairs.append(pair)

            local_claim_ids: list[str] = []
            seen_local_claims: set[str] = set()
            for mapping in claim_mappings:
                if (
                    not isinstance(mapping, dict)
                    or not REQUIRED_CLAIM_MAPPING_FIELDS <= set(mapping)
                    or not set(mapping) <= (
                        REQUIRED_CLAIM_MAPPING_FIELDS
                        | OPTIONAL_CLAIM_MAPPING_FIELDS
                    )
                ):
                    raise RegistryError(
                        "claim mapping supports claimId and optional expectedPath"
                    )
                claim_id = mapping["claimId"]
                expected_path = mapping.get("expectedPath", "/")
                if not isinstance(claim_id, str) or not claim_id:
                    raise RegistryError("claimId must be a non-empty string")
                if claim_id in seen_local_claims or claim_id in mapped_claims:
                    raise RegistryError(f"duplicate claim mapping {claim_id!r}")
                seen_local_claims.add(claim_id)
                claim = claims.get(claim_id)
                if claim is None:
                    raise RegistryError(f"unknown claim {claim_id!r}")
                if scope is not None and claim_id not in scope:
                    raise RegistryError(
                        f"claim mapping {claim_id!r} is outside claimScope"
                    )
                if claim.get("status") not in VALID_CLAIM_STATUSES:
                    raise RegistryError(
                        f"claim {claim_id!r} is not official/derived"
                    )
                if claim.get("sourceUrl") != raw["sourceUrl"]:
                    raise RegistryError(
                        f"claim {claim_id!r} sourceUrl differs from attestation"
                    )
                _pointer_parts(expected_path)
                claim_expected = _resolve_pointer(
                    expected["value"], expected_path
                )
                if claim.get("value") != claim_expected:
                    raise RegistryError(
                        f"claim {claim_id!r} value differs from expected"
                    )
                claim_unit = _resolve_expected_unit(
                    expected["unit"], expected_path
                )
                if claim.get("unit") != claim_unit:
                    raise RegistryError(
                        f"claim {claim_id!r} unit differs from expected.unit"
                    )
                local_claim_ids.append(claim_id)

            for target_id, reviewed_path in local_target_pairs:
                mapped_paths[target_id].append(
                    (reviewed_path, attestation_id)
                )
            for claim_id in local_claim_ids:
                mapped_claims[claim_id] = attestation_id
            valid.append(raw)
        except RegistryError as exc:
            report.results.append(
                _result(
                    attestation_id,
                    str(source),
                    "/schema",
                    "unsupported",
                    str(exc),
                    "valid strict attestation entry",
                    "Correct or remove this attestation; no partial entry is accepted.",
                    context=raw,
                )
            )

    for target_id, leaves in target_leaf_paths.items():
        for leaf in sorted(leaves):
            owners = [
                attestation_id
                for mapped_path, attestation_id in mapped_paths[target_id]
                if _path_covers(mapped_path, leaf)
            ]
            if len(owners) != 1:
                report.results.append(
                    _result(
                        "<coverage>",
                        "<none>",
                        f"{target_id}{leaf}",
                        "unsupported",
                        owners,
                        "exactly one attestation cohort",
                        "Add one non-overlapping attestation mapping for this reviewed leaf.",
                    )
                )
    if scope is not None:
        for claim_id in sorted(scope - set(mapped_claims)):
            report.results.append(
                _result(
                    "<claim-coverage>",
                    claims[claim_id].get("sourceUrl", "<none>"),
                    claim_id,
                    "unsupported",
                    "unmapped",
                    "exactly one claim attestation",
                    "Map this claimScope id once or remove it from claimScope.",
                )
            )
    report.audit = {
        "attestationCount": len(valid),
        "claimCount": len(mapped_claims),
        "reviewedLeafCount": sum(
            len(leaves) for leaves in target_leaf_paths.values()
        ),
        "liveCapableCount": len(valid),
        "liveExtractableCount": sum(
            _live_policy(attestation)["mode"] == "extract"
            for attestation in valid
        ),
        "fixtureOnlyCount": sum(
            _live_policy(attestation)["mode"] == "fixture-only"
            for attestation in valid
        ),
    }
    if (
        report.audit["liveExtractableCount"]
        + report.audit["fixtureOnlyCount"]
        != report.audit["attestationCount"]
    ):
        raise RegistryError("live policy audit partition is inconsistent")
    declared_audit = (
        claims_data.get("audit", {}).get("sourceAttestations")
        if isinstance(claims_data.get("audit"), dict)
        else None
    )
    if declared_audit is not None and declared_audit != report.audit:
        report.results.append(
            _result(
                "<audit>",
                "<none>",
                "/audit/sourceAttestations",
                "unsupported",
                declared_audit,
                report.audit,
                "Update the production claims audit counts from a reviewed successful run.",
                context=declared_audit,
            )
        )
    return valid


def _normalize_text(value: str) -> str:
    return " ".join(value.split())


class _HtmlSourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[dict[str, Any]] = []
        self.headings: list[str] = []
        self.heading_records: list[tuple[int, str]] = []
        self.definitions: list[tuple[str, str, str]] = []
        self.block_texts: list[str] = []
        self.loose_texts: list[str] = []
        self.labelled_values: list[tuple[str, str, str]] = []
        self.list_items: list[tuple[str, str]] = []
        self.section_blocks: list[tuple[str, str, str]] = []
        self.heading_blocks: list[tuple[str, str, str]] = []
        self.law_strongs: list[str] = []
        self._recent_anchors: list[str] = []
        self._table: dict[str, Any] | None = None
        self._row: list[str] | None = None
        self._cell_parts: list[str] | None = None
        self._caption_parts: list[str] | None = None
        self._heading_parts: list[str] | None = None
        self._heading_level = 0
        self._current_heading = ""
        self._current_h3 = ""
        self._outer_heading = ""
        self._pending_label: tuple[str, str] | None = None
        self._block_stack: list[dict[str, Any]] = []
        self._dt_parts: list[str] | None = None
        self._dd_parts: list[str] | None = None
        self._pending_dt: str | None = None
        self._law_strong_parts: list[str] | None = None
        self._ignored_depth = 0
        self._tag_stack: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        lowered = tag.lower()
        normalized_attrs = {
            key.lower(): (value or "") for key, value in attrs
        }
        if lowered in {"script", "style", "template", "noscript"}:
            self._ignored_depth += 1
        if lowered == "table":
            hidden = any(
                item_attrs.get("id", "").startswith("History_")
                or re.sub(
                    r"\s+", "", item_attrs.get("style", "").lower()
                )
                == "display:none"
                for _item_tag, item_attrs in self._tag_stack
            )
            direct_law_body = bool(
                any(
                    item_tag == "div"
                    and item_attrs.get("id") in {"lawBody", "LawBody"}
                    for item_tag, item_attrs in self._tag_stack
                )
            )
            self._table = {
                "caption": "",
                "rows": [],
                "anchors": list(self._recent_anchors),
                "hidden": hidden,
                "directLawBody": direct_law_body,
                "section": (
                    self._recent_anchors[-1] if self._recent_anchors else ""
                ),
            }
        elif lowered == "caption" and self._table is not None:
            self._caption_parts = []
        elif lowered == "tr" and self._table is not None:
            self._row = []
        elif lowered in {"th", "td"} and self._row is not None:
            self._cell_parts = []
        elif re.fullmatch(r"h[1-6]", lowered):
            self._heading_parts = []
            self._heading_level = int(lowered[1])
        elif lowered in {"p", "li"}:
            if self._block_stack:
                self._block_stack[-1]["hasChildBlock"] = True
            self._block_stack.append(
                {"tag": lowered, "parts": [], "hasChildBlock": False}
            )
        elif lowered == "dt":
            self._dt_parts = []
        elif lowered == "dd":
            self._dd_parts = []
        elif (
            lowered == "strong"
            and self._table is None
            and self._law_strong_parts is None
            and any(
                item_tag == "div"
                and item_attrs.get("id") in {"lawBody", "LawBody"}
                for item_tag, item_attrs in self._tag_stack
            )
            and not any(
                item_attrs.get("id", "").startswith("History_")
                or re.sub(
                    r"\s+", "", item_attrs.get("style", "").lower()
                )
                == "display:none"
                for _item_tag, item_attrs in self._tag_stack
            )
        ):
            self._law_strong_parts = []
        if lowered not in {
            "area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr",
        }:
            self._tag_stack.append((lowered, normalized_attrs))

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style", "template", "noscript"}:
            self._ignored_depth = max(0, self._ignored_depth - 1)
        if lowered == "caption" and self._caption_parts is not None:
            if self._table is not None:
                self._table["caption"] = _normalize_text(
                    "".join(self._caption_parts)
                )
            self._caption_parts = None
        elif lowered in {"th", "td"} and self._cell_parts is not None:
            if self._row is not None:
                self._row.append(
                    _normalize_text("".join(self._cell_parts))
                )
            self._cell_parts = None
        elif lowered == "tr" and self._row is not None:
            if self._table is not None and any(self._row):
                self._table["rows"].append(self._row)
            self._row = None
        elif lowered == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None
        elif re.fullmatch(r"h[1-6]", lowered) and self._heading_parts is not None:
            heading = _normalize_text("".join(self._heading_parts))
            self._current_heading = heading
            self.headings.append(heading)
            self.heading_records.append((self._heading_level, heading))
            if self._heading_level == 3:
                self._current_h3 = heading
            self._remember_anchor(heading)
            if self._heading_level <= 3:
                self._outer_heading = heading
                self._pending_label = None
            else:
                self._pending_label = (self._outer_heading, heading)
            self._heading_parts = None
        elif (
            lowered in {"p", "li"}
            and self._block_stack
            and self._block_stack[-1]["tag"] == lowered
        ):
            current = self._block_stack.pop()
            block = _normalize_text("".join(current["parts"]))
            if block and not current["hasChildBlock"]:
                self.block_texts.append(block)
                self.section_blocks.append(
                    (self._current_h3, lowered, block)
                )
                self.heading_blocks.append(
                    (self._current_heading, lowered, block)
                )
                self._remember_anchor(block)
                if lowered == "li":
                    self.list_items.append((self._current_heading, block))
                if lowered == "p" and self._pending_label is not None:
                    outer, label = self._pending_label
                    self.labelled_values.append((outer, label, block))
        elif lowered == "dt" and self._dt_parts is not None:
            self._pending_dt = _normalize_text("".join(self._dt_parts))
            self._dt_parts = None
        elif lowered == "dd" and self._dd_parts is not None:
            value = _normalize_text("".join(self._dd_parts))
            if self._pending_dt is not None:
                self.definitions.append(
                    (self._current_heading, self._pending_dt, value)
                )
            self._pending_dt = None
            self._dd_parts = None
        elif lowered == "strong" and self._law_strong_parts is not None:
            value = _normalize_text("".join(self._law_strong_parts))
            if value:
                self.law_strongs.append(value)
            self._law_strong_parts = None
        for index in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[index][0] == lowered:
                del self._tag_stack[index:]
                break

    def handle_data(self, data: str) -> None:
        tracked = any(
            (
                self._cell_parts is not None,
                self._caption_parts is not None,
                self._heading_parts is not None,
                bool(self._block_stack),
                self._dt_parts is not None,
                self._dd_parts is not None,
                self._table is not None,
            )
        )
        if not tracked and self._ignored_depth == 0:
            loose = _normalize_text(data)
            if loose:
                self.loose_texts.append(loose)
        if self._cell_parts is not None:
            self._cell_parts.append(data)
        if self._caption_parts is not None:
            self._caption_parts.append(data)
        if self._heading_parts is not None:
            self._heading_parts.append(data)
        if self._block_stack:
            self._block_stack[-1]["parts"].append(data)
        if self._dt_parts is not None:
            self._dt_parts.append(data)
        if self._dd_parts is not None:
            self._dd_parts.append(data)
        if self._law_strong_parts is not None:
            self._law_strong_parts.append(data)

    def _remember_anchor(self, text: str) -> None:
        if text:
            self._recent_anchors.append(text)
            self._recent_anchors = self._recent_anchors[-8:]


def _parse_number(value: str, value_type: str, null_token: str) -> Any:
    normalized = _normalize_text(value).replace(",", "")
    if value_type == "nullable-number" and normalized == null_token:
        return None
    if value_type == "percent-to-decimal":
        match = re.fullmatch(r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*%", normalized)
        if not match:
            raise ChangedExtraction(
                f"{value!r} is not an exact percentage"
            )
        number = float(match.group(1)) / 100
    else:
        pattern = (
            r"[+-]?\d+"
            if value_type == "integer"
            else r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)"
        )
        if not re.fullmatch(pattern, normalized):
            raise ChangedExtraction(
                f"{value!r} is not an exact {value_type} token"
            )
        number = int(normalized) if value_type == "integer" else float(normalized)
    if not math.isfinite(number):
        raise ChangedExtraction("extracted number is non-finite")
    return number


def _extract_table_rows(
    rows: list[list[str]],
    headers: list[str],
    unit_label: str,
    value_types: list[str],
    null_token: str,
) -> tuple[str, list[list[Any]]]:
    unit_rows = [
        row for row in rows if len(row) == 2 and row[0] == unit_label
    ]
    if len(unit_rows) != 1:
        raise ChangedExtraction(
            f"unit row {unit_label!r} matched {len(unit_rows)} times"
        )
    unit = unit_rows[0][1]
    content_rows = [row for row in rows if row is not unit_rows[0]]
    header_indexes = [
        index for index, row in enumerate(content_rows) if row == headers
    ]
    if len(header_indexes) != 1:
        raise ChangedExtraction(
            f"header row matched {len(header_indexes)} times"
        )
    header_index = header_indexes[0]
    data_rows = content_rows[header_index + 1 :]
    if not data_rows:
        raise ChangedExtraction("table has no data rows")
    parsed: list[list[Any]] = []
    for row_index, row in enumerate(data_rows):
        if len(row) != len(headers):
            raise ChangedExtraction(
                f"row {row_index + 1} is partial: {row!r}"
            )
        parsed.append(
            [
                _parse_number(cell, value_types[index], null_token)
                for index, cell in enumerate(row)
            ]
        )
    return unit, parsed


def _extract_html_table(
    body: bytes, params: dict[str, Any]
) -> tuple[str, Any]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedExtraction("HTML is not UTF-8") from exc
    parser = _HtmlSourceParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:
        raise ChangedExtraction(f"HTML parser failed: {exc}") from exc
    matches = [
        table for table in parser.tables
        if table["caption"] == params["caption"]
    ]
    if len(matches) != 1:
        raise ChangedExtraction(
            f"caption {params['caption']!r} matched {len(matches)} tables"
        )
    return _extract_table_rows(
        matches[0]["rows"],
        params["headers"],
        params["unitLabel"],
        params["valueTypes"],
        params["nullToken"],
    )


def _extract_html_definition(
    body: bytes, params: dict[str, Any]
) -> tuple[str, Any]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedExtraction("HTML is not UTF-8") from exc
    parser = _HtmlSourceParser()
    parser.feed(text)
    parser.close()
    if parser.headings.count(params["section"]) != 1:
        raise ChangedExtraction(
            f"section {params['section']!r} matched "
            f"{parser.headings.count(params['section'])} headings"
        )
    definitions = [
        (label, value)
        for heading, label, value in parser.definitions
        if heading == params["section"]
    ]

    def unique(label: str) -> str:
        values = [value for item_label, value in definitions if item_label == label]
        if len(values) != 1:
            raise ChangedExtraction(
                f"definition {label!r} matched {len(values)} times"
            )
        return values[0]

    unit = unique(params["unitLabel"])
    extracted: dict[str, Any] = {}
    for field_spec in params["fields"]:
        extracted[field_spec["key"]] = _parse_number(
            unique(field_spec["label"]),
            field_spec["valueType"],
            "",
        )
    if params["result"] == "scalar":
        return unit, next(iter(extracted.values()))
    return unit, extracted


def _parse_html(body: bytes) -> _HtmlSourceParser:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedExtraction("HTML is not UTF-8") from exc
    parser = _HtmlSourceParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:
        raise ChangedExtraction(f"HTML parser failed: {exc}") from exc
    return parser


def _single_numeric_match(
    value: str, pattern: str, description: str
) -> re.Match[str]:
    matches = list(re.finditer(pattern, _normalize_text(value), flags=re.IGNORECASE))
    if len(matches) != 1:
        raise ChangedExtraction(
            f"{value!r} contains {len(matches)} supported {description} tokens"
        )
    return matches[0]


def _finite_number(raw: str) -> int | float:
    number = float(raw.replace(",", ""))
    if not math.isfinite(number):
        raise ChangedExtraction("extracted number is non-finite")
    return int(number) if number.is_integer() else number


def _plain_number(value: int | float) -> str:
    if isinstance(value, int) or float(value).is_integer():
        return str(int(value))
    return format(value, ".15g")


def _transform_html_value(value: str, transform: str) -> Any:
    normalized = _normalize_text(value)
    if transform == "single-dollar-amount-to-number":
        matches = list(
            re.finditer(
                r"(?<![A-Za-z0-9$])\$"
                r"([0-9][0-9,]*(?:\.[0-9]+)?)(?![A-Za-z0-9])",
                normalized,
            )
        )
        if len(matches) != 1:
            raise ChangedExtraction(
                f"{value!r} contains {len(matches)} exact dollar amounts; "
                "exactly 1 required"
            )
        return _finite_number(matches[0].group(1))
    if transform == "single-hourly-dollar-amount-to-number":
        matches = list(
            re.finditer(
                r"(?<![A-Za-z0-9$])\$"
                r"([0-9][0-9,]*(?:\.[0-9]+)?)\s+(?:per|an)\s+hour"
                r"(?![A-Za-z0-9])",
                normalized,
                flags=re.IGNORECASE,
            )
        )
        if len(matches) != 1:
            raise ChangedExtraction(
                f"{value!r} contains {len(matches)} exact hourly dollar "
                "amounts; exactly 1 required"
            )
        return _finite_number(matches[0].group(1))
    if transform == "single-iso-currency-to-number":
        matches = list(
            re.finditer(
                r"(?<![A-Za-z0-9])(NZD|CAD|AUD)\s+\$"
                r"([0-9][0-9,]*(?:\.[0-9]+)?)(?![A-Za-z0-9])",
                normalized,
            )
        )
        if len(matches) != 1:
            raise ChangedExtraction(
                f"{value!r} contains {len(matches)} exact ISO currency amounts; "
                "exactly 1 required"
            )
        return _finite_number(matches[0].group(2))
    if transform == "leading-currency-to-number":
        currency_tokens = list(
            re.finditer(
                r"(?<![A-Za-z0-9])(?:NZD|CAD|AUD) "
                r"\$[0-9][0-9,]*(?:\.[0-9]+)?(?![A-Za-z0-9])",
                normalized,
            )
        )
        match = re.match(
            r"^(?:NZD|CAD|AUD) \$([0-9][0-9,]*(?:\.[0-9]+)?)"
            r"(?![A-Za-z0-9])",
            normalized,
        )
        if not match or len(currency_tokens) != 1:
            raise ChangedExtraction(
                f"{value!r} must contain exactly one leading ISO currency amount"
            )
        return _finite_number(match.group(1))
    if transform == "final-inclusive-range":
        ranges = list(
            re.finditer(
                r"(?<![A-Za-z0-9])([0-9][0-9,]*)"
                r"\s*[\-\u2013\u2014]\s*([0-9][0-9,]*)(?![A-Za-z0-9])",
                normalized,
            )
        )
        if len(ranges) != 2:
            raise ChangedExtraction(
                f"{value!r} contains {len(ranges)} ranges; exactly 2 required"
            )
        lower = _finite_number(ranges[-1].group(1))
        upper = _finite_number(ranges[-1].group(2))
        if not isinstance(lower, int) or not isinstance(upper, int) or lower > upper:
            raise ChangedExtraction("final inclusive range is not ascending integers")
        return f"{lower}-{upper}"
    if transform in {"embedded-percent", "embedded-percent-to-decimal"}:
        match = re.fullmatch(
            r"\$([0-9]+(?:\.[0-9]+)?) per \$100 "
            r"\(([0-9]+(?:\.[0-9]+)?)%\)",
            normalized,
        )
        if not match:
            raise ChangedExtraction(
                f"{value!r} is not an exact '$N per $100 (P%)' cell"
            )
        per_hundred = _finite_number(match.group(1))
        percent = _finite_number(match.group(2))
        if float(per_hundred) != float(percent):
            raise ChangedExtraction(
                f"embedded rate mismatch: per-$100={per_hundred}, percent={percent}"
            )
        return (
            percent
            if transform == "embedded-percent"
            else float(percent) / 100
        )
    if transform == "currency-to-number":
        match = _single_numeric_match(
            normalized,
            r"(?<![A-Za-z0-9])(?:(?:NZD|CAD|AUD)\s*)?\$?\s*"
            r"([0-9][0-9,]*(?:\.[0-9]+)?)(?![A-Za-z0-9])",
            "currency",
        )
        return _finite_number(match.group(1))
    if transform == "percent-to-decimal":
        match = _single_numeric_match(
            normalized,
            r"(?<![A-Za-z0-9])([0-9]+(?:\.[0-9]+)?)\s*%(?![A-Za-z0-9])",
            "percentage",
        )
        return _finite_number(match.group(1)) / 100
    if transform == "percentage-number-to-decimal":
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", normalized):
            raise ChangedExtraction(
                f"{value!r} is not one exact unsigned percentage number"
            )
        percent = _finite_number(normalized)
        if not 0 <= percent <= 100:
            raise ChangedExtraction(
                f"percentage number {percent!r} is outside 0..100"
            )
        return float(percent) / 100
    if transform in {"duration-months", "duration-weeks"}:
        word = (
            r"(?:months?|mois)"
            if transform == "duration-months"
            else "weeks?"
        )
        match = _single_numeric_match(
            normalized,
            rf"(?<![A-Za-z0-9])([0-9][0-9,]*(?:\.[0-9]+)?)\s+{word}\b",
            transform,
        )
        return _finite_number(match.group(1))
    if transform == "inclusive-range":
        english_age = re.fullmatch(
            r"be between the ages of ([0-9][0-9,]*) and "
            r"([0-9][0-9,]*) \(inclusive\)",
            normalized,
            flags=re.IGNORECASE,
        )
        if english_age is not None:
            lower = _finite_number(english_age.group(1))
            upper = _finite_number(english_age.group(2))
            if (
                not isinstance(lower, int)
                or not isinstance(upper, int)
                or lower > upper
            ):
                raise ChangedExtraction(
                    "English inclusive age bounds must be ascending integers"
                )
            return f"{lower}-{upper}"
        if re.search(
            r"\bbetween the ages of\b", normalized, flags=re.IGNORECASE
        ):
            raise ChangedExtraction(
                "English inclusive age prose does not match the fixed grammar"
            )
        matches = list(
            re.finditer(
                r"(?<![A-Za-z0-9])([0-9][0-9,]*(?:\.[0-9]+)?)"
                r"\s*(?:[\-\u2013\u2014]|\bto\b|\bà\b)\s*"
                r"([0-9][0-9,]*(?:\.[0-9]+)?)(?![A-Za-z0-9])",
                normalized,
                flags=re.IGNORECASE,
            )
        )
        if len(matches) != 1:
            raise ChangedExtraction(
                f"{value!r} contains {len(matches)} supported inclusive ranges"
            )
        lower = _finite_number(matches[0].group(1))
        upper = _finite_number(matches[0].group(2))
        if lower > upper:
            raise ChangedExtraction("inclusive range lower bound exceeds upper bound")
        if not isinstance(lower, int) or not isinstance(upper, int):
            raise ChangedExtraction("inclusive range requires integer bounds")
        return f"{lower}-{upper}"
    if transform in {"number", "integer"}:
        pattern = (
            r"(?<![A-Za-z0-9.])([0-9][0-9,]*)(?![A-Za-z0-9.])"
            if transform == "integer"
            else r"(?<![A-Za-z0-9.])([0-9][0-9,]*(?:\.[0-9]+)?)"
            r"(?![A-Za-z0-9.])"
        )
        match = _single_numeric_match(normalized, pattern, transform)
        parsed = _finite_number(match.group(1))
        if transform == "integer" and not isinstance(parsed, int):
            raise ChangedExtraction(f"{value!r} is not an integer")
        return parsed
    raise UnsupportedExtraction(f"transform {transform!r} is not implemented")


def _parse_tax_bracket(
    label: str, rate_text: str
) -> tuple[int | float, int | float | None, int | float, str]:
    normalized = _normalize_text(label).replace(",", "")
    numbers = [
        _finite_number(match.group(0))
        for match in re.finditer(r"[0-9]+(?:\.[0-9]+)?", normalized)
    ]
    if len(numbers) == 2 and re.search(r"[\-\u2013\u2014]|(?:\bto\b)", normalized):
        lower, upper = numbers
    elif len(numbers) == 1 and re.search(
        r"\b(?:over|above|more)\b|\+$", normalized, flags=re.IGNORECASE
    ):
        lower, upper = numbers[0], None
    else:
        raise ChangedExtraction(
            f"tax bracket label {label!r} is not a supported closed/open range"
        )
    rate_match = re.fullmatch(
        r"([0-9]+(?:\.([0-9]+))?)\s*%", _normalize_text(rate_text)
    )
    if not rate_match:
        raise ChangedExtraction(f"{rate_text!r} is not an exact tax percentage")
    percent = _finite_number(rate_match.group(1))
    rate = float(percent) / 100
    if percent == 0:
        serialized_rate = "0"
    else:
        decimal_places = len(rate_match.group(2) or "") + 2
        serialized_rate = f"{rate:.{decimal_places}f}"
    return lower, upper, rate, serialized_rate


def _parse_ato_first_tax_band(
    label: str, rate_text: str
) -> dict[str, int | float]:
    label_match = re.fullmatch(
        r"0 \u2013 \$([0-9][0-9,]*)", _normalize_text(label)
    )
    if not label_match:
        raise ChangedExtraction(
            f"ATO first-band label {label!r} is not exact '0 – $N'"
        )
    rate_match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)c for each \$1",
        _normalize_text(rate_text),
    )
    if not rate_match:
        raise ChangedExtraction(
            f"ATO first-band cell {rate_text!r} is not exact 'Pc for each $1'"
        )
    cap = _finite_number(label_match.group(1))
    cents = _finite_number(rate_match.group(1))
    if not isinstance(cap, int) or cap <= 0:
        raise ChangedExtraction("ATO first-band cap must be a positive integer")
    if not 0 <= cents <= 100:
        raise ChangedExtraction("ATO first-band cents rate is outside 0..100")
    return {"cap": cap, "rate": float(cents) / 100}


def _parse_ato_law_first_tax_band(
    row: list[str],
) -> dict[str, int | float]:
    if len(row) != 3 or row[0] != "1":
        raise ChangedExtraction(
            "ATO law first-band row must be exact 3-column item 1"
        )
    band_match = re.fullmatch(
        r"does not exceed \$([0-9][0-9,]*)", row[1]
    )
    if not band_match:
        raise ChangedExtraction(
            f"ATO law band {row[1]!r} is not exact 'does not exceed $N'"
        )
    rate_match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)%", row[2]
    )
    if not rate_match:
        raise ChangedExtraction(
            f"ATO law rate {row[2]!r} is not one exact percentage"
        )
    cap = _finite_number(band_match.group(1))
    percent = _finite_number(rate_match.group(1))
    if not isinstance(cap, int) or cap <= 0:
        raise ChangedExtraction("ATO law first-band cap must be a positive integer")
    if not 0 <= percent <= 100:
        raise ChangedExtraction("ATO law first-band rate is outside 0..100")
    return {"cap": cap, "rate": float(percent) / 100}


def _extract_html_table_record(
    body: bytes, params: dict[str, Any]
) -> tuple[Any, Any]:
    parser = _parse_html(body)
    headers = params["headers"]
    candidates: list[tuple[dict[str, Any], int]] = []
    for table in parser.tables:
        if params["section"] != table["section"]:
            continue
        header_indexes = [
            index for index, row in enumerate(table["rows"]) if row == headers
        ]
        if len(header_indexes) == 1:
            candidates.append((table, header_indexes[0]))
    if len(candidates) != 1:
        raise ChangedExtraction(
            f"section/header matched {len(candidates)} tables"
        )
    table, header_index = candidates[0]
    if any(
        field_spec["transform"] == "ato-law-first-tax-band"
        for field_spec in params["fields"]
    ):
        expected_title_row = [ATO_LAW_FIRST_BAND_TITLE] + [""] * (
            len(headers) - 1
        )
        title_rows = [
            index
            for index, row in enumerate(table["rows"])
            if row == expected_title_row
        ]
        caption_match = table["caption"] == ATO_LAW_FIRST_BAND_TITLE
        if (
            len(title_rows) + int(caption_match) != 1
            or (title_rows and title_rows[0] >= header_index)
        ):
            raise ChangedExtraction(
                "ATO law table requires one exact reviewed caption or "
                "header-width title row before headers"
            )
    data_rows = table["rows"][header_index + 1 :]
    if not data_rows:
        raise ChangedExtraction("matched table has no data rows")
    header_positions = {label: index for index, label in enumerate(headers)}
    extracted: dict[str, Any] = {}
    units: dict[str, Any] = {}
    for field_spec in params["fields"]:
        row_values: list[Any] = []
        tax_rows: list[
            tuple[int | float, int | float | None, int | float, str]
        ] = []
        for label in field_spec["rowLabels"]:
            matches = [
                row for row in data_rows
                if len(row) == len(headers) and row[0] == label
            ]
            if len(matches) != 1:
                raise ChangedExtraction(
                    f"row label {label!r} matched {len(matches)} rows"
                )
            row = matches[0]
            value_text = row[header_positions[field_spec["valueHeader"]]]
            if field_spec["transform"] in {
                "tax-brackets",
                "tax-brackets-serialization",
            }:
                tax_rows.append(_parse_tax_bracket(label, value_text))
            elif field_spec["transform"] == "ato-first-tax-band":
                row_values.append(
                    _parse_ato_first_tax_band(label, value_text)
                )
            elif field_spec["transform"] == "ato-law-first-tax-band":
                row_values.append(
                    _parse_ato_law_first_tax_band(row)
                )
            else:
                row_values.append(
                    _transform_html_value(value_text, field_spec["transform"])
                )
        if field_spec["transform"] in {
            "tax-brackets",
            "tax-brackets-serialization",
        }:
            if tax_rows[0][0] != 0:
                raise ChangedExtraction("tax brackets must start at zero")
            for previous, current in zip(tax_rows, tax_rows[1:]):
                if previous[1] is None or current[0] != previous[1] + 1:
                    raise ChangedExtraction(
                        "tax bracket ranges are not integer-contiguous"
                    )
            if tax_rows[-1][1] is not None:
                raise ChangedExtraction("last tax bracket must have an open cap")
            if field_spec["transform"] == "tax-brackets":
                value = [
                    [upper, rate]
                    for _lower, upper, rate, _serialized_rate in tax_rows
                ]
            else:
                tokens = [
                    f"{'above' if upper is None else _plain_number(upper)}"
                    f"@{serialized_rate}"
                    for _lower, upper, _rate, serialized_rate in tax_rows
                ]
                value = ";".join(tokens)
        else:
            value = row_values[0] if len(row_values) == 1 else row_values
        extracted[field_spec["key"]] = value
        units[field_spec["key"]] = field_spec["unit"]
    if params["result"] == "scalar":
        key = params["fields"][0]["key"]
        return units[key], extracted[key]
    return units, extracted


def _extract_html_labelled_values(
    body: bytes, params: dict[str, Any]
) -> tuple[Any, Any]:
    parser = _parse_html(body)
    if parser.headings.count(params["anchor"]) != 1:
        raise ChangedExtraction(
            f"outer anchor {params['anchor']!r} matched "
            f"{parser.headings.count(params['anchor'])} headings"
        )
    extracted: dict[str, Any] = {}
    units: dict[str, str] = {}
    for field_spec in params["fields"]:
        matches = [
            value
            for outer, label, value in parser.labelled_values
            if outer == params["anchor"] and label == field_spec["label"]
        ]
        transformed: list[Any] = []
        for candidate in matches:
            try:
                transformed.append(
                    _transform_html_value(
                        candidate, field_spec["transform"]
                    )
                )
            except ChangedExtraction:
                continue
        if len(transformed) != 1:
            raise ChangedExtraction(
                f"label {field_spec['label']!r} had "
                f"{len(transformed)} transform-compatible values "
                f"across {len(matches)} bounded paragraphs"
            )
        extracted[field_spec["key"]] = transformed[0]
        units[field_spec["key"]] = field_spec["unit"]
    if params["result"] == "scalar":
        key = params["fields"][0]["key"]
        return units[key], extracted[key]
    return units, extracted


def _extract_html_text_anchor(
    body: bytes, params: dict[str, Any]
) -> tuple[str, Any]:
    parser = _parse_html(body)
    matches = [
        text
        for text in parser.block_texts + parser.headings + parser.loose_texts
        if text == params["anchor"]
    ]
    if len(matches) != 1:
        raise ChangedExtraction(
            f"text anchor {params['anchor']!r} matched {len(matches)} blocks"
        )
    return params["unit"], _transform_html_value(
        matches[0], params["transform"]
    )


def _ato_lito_amount(raw: str) -> int:
    value = _finite_number(raw)
    if not isinstance(value, int) or value < 0:
        raise ChangedExtraction("ATO LITO amount must be a non-negative integer")
    return value


def _extract_ato_lito(
    body: bytes, params: dict[str, Any]
) -> tuple[dict[str, str], dict[str, int | float]]:
    parser = _parse_html(body)
    if parser.headings.count(params["anchor"]) != 1:
        raise ChangedExtraction(
            f"ATO LITO anchor {params['anchor']!r} matched "
            f"{parser.headings.count(params['anchor'])} headings"
        )
    items = [
        text
        for heading, text in parser.list_items
        if heading == params["anchor"]
    ]
    if items != params["items"]:
        raise ChangedExtraction(
            "ATO LITO requires exactly the 3 reviewed leaf items in order"
        )

    normalized = [_normalize_text(item) for item in items]
    first = re.fullmatch(
        r"\$([0-9][0-9,]*) or less, you will get "
        r"the maximum offset of \$([0-9][0-9,]*)",
        normalized[0],
    )
    second = re.fullmatch(
        r"between \$([0-9][0-9,]*) and \$([0-9][0-9,]*), "
        r"you will get \$([0-9][0-9,]*) minus "
        r"([0-9]+(?:\.[0-9]+)?) cents? for every \$1 above "
        r"\$([0-9][0-9,]*)",
        normalized[1],
    )
    third = re.fullmatch(
        r"between \$([0-9][0-9,]*) and \$([0-9][0-9,]*), "
        r"you will get \$([0-9][0-9,]*) minus "
        r"([0-9]+(?:\.[0-9]+)?) cents? for every \$1 above "
        r"\$([0-9][0-9,]*)\.",
        normalized[2],
    )
    if first is None or second is None or third is None:
        raise ChangedExtraction("ATO LITO items do not match the fixed rule grammar")
    full_to = _ato_lito_amount(first.group(1))
    max_offset = _ato_lito_amount(first.group(2))
    taper1_from = _ato_lito_amount(second.group(1))
    taper1_to = _ato_lito_amount(second.group(2))
    taper1_offset = _ato_lito_amount(second.group(3))
    taper1_rate = float(_finite_number(second.group(4))) / 100
    taper1_base = _ato_lito_amount(second.group(5))
    taper2_from = _ato_lito_amount(third.group(1))
    cut_out = _ato_lito_amount(third.group(2))
    taper2_offset = _ato_lito_amount(third.group(3))
    taper2_rate = float(_finite_number(third.group(4))) / 100
    taper2_base = _ato_lito_amount(third.group(5))
    if (
        taper1_from != full_to + 1
        or taper1_base != full_to
        or taper1_offset != max_offset
        or taper2_from != taper1_to + 1
        or taper2_base != taper1_to
    ):
        raise ChangedExtraction("ATO LITO boundaries are not integer-contiguous")
    expected_taper2_offset = max_offset - taper1_rate * (
        taper1_to - full_to
    )
    if abs(expected_taper2_offset - taper2_offset) > 1e-9:
        raise ChangedExtraction(
            "ATO LITO second taper offset is arithmetically inconsistent"
        )
    residual = taper2_offset - taper2_rate * (cut_out - taper1_to)
    if abs(residual) > 0.01:
        raise ChangedExtraction(
            "ATO LITO cut-out does not reduce the offset to zero within one cent"
        )
    return ATO_LITO_UNIT, {
        "maxOffset": max_offset,
        "fullTo": full_to,
        "taper1To": taper1_to,
        "taper1Rate": taper1_rate,
        "cutOut": cut_out,
        "taper2Rate": taper2_rate,
    }


def _extract_html_section_text(
    body: bytes, params: dict[str, Any]
) -> tuple[str, Any]:
    parser = _parse_html(body)
    heading = params["heading"]
    heading_count = sum(
        level == 3 and text == heading
        for level, text in parser.heading_records
    )
    if heading_count != 1:
        raise ChangedExtraction(
            f"H3 section {heading!r} matched {heading_count} times"
        )
    matches = [
        text
        for current_heading, tag, text in parser.section_blocks
        if current_heading == heading
        and tag in {"p", "li"}
        and text == params["anchor"]
    ]
    if len(matches) != 1:
        raise ChangedExtraction(
            f"section leaf anchor matched {len(matches)} times"
        )
    return (
        params["unit"],
        _transform_html_value(matches[0], params["transform"]),
    )


def _extract_ato_law_lito(
    body: bytes, params: dict[str, Any]
) -> tuple[dict[str, str], dict[str, int | float]]:
    parser = _parse_html(body)
    title_count = sum(
        level == 1 and text == params["actTitle"]
        for level, text in parser.heading_records
    )
    if title_count != 1:
        raise ChangedExtraction(
            f"ATO Act H1 matched {title_count} times"
        )
    section_count = sum(
        first == params["section"] and second == params["sectionTitle"]
        for first, second in zip(
            parser.law_strongs, parser.law_strongs[1:]
        )
    )
    if section_count != 1:
        raise ChangedExtraction(
            "ATO LITO requires exactly one reviewed strong-pair section "
            f"paragraph; found {section_count}"
        )

    candidates: list[tuple[list[list[str]], int]] = []
    expected_title_row = [params["tableTitle"]]
    for table in parser.tables:
        if table["hidden"] or not table["directLawBody"]:
            continue
        rows = table["rows"]
        header_indexes = [
            index
            for index, row in enumerate(rows)
            if row == ATO_LAW_LITO_HEADERS
        ]
        title_indexes = [
            index
            for index, row in enumerate(rows)
            if row == expected_title_row
        ]
        caption_match = table["caption"] == params["tableTitle"]
        title_count_for_table = len(title_indexes) + int(caption_match)
        if (
            len(header_indexes) == 1
            and title_count_for_table == 1
            and (
                caption_match
                or title_indexes[0] < header_indexes[0]
            )
        ):
            candidates.append((rows, header_indexes[0]))
    if len(candidates) != 1:
        raise ChangedExtraction(
            "ATO LITO law table requires one exact title before exact headers"
        )
    rows, header_index = candidates[0]
    data_rows = rows[header_index + 1 :]
    if len(data_rows) != 3 or any(len(row) != 3 for row in data_rows):
        raise ChangedExtraction(
            "ATO LITO law table requires exactly three complete rows"
        )
    expected_items = ["1", "2", "3"]
    if [row[0] for row in data_rows] != expected_items:
        raise ChangedExtraction("ATO LITO law items must be exactly 1, 2, 3")

    first_band = re.fullmatch(
        r"does not exceed \$ ([0-9][0-9,]*)", data_rows[0][1]
    )
    first_value = re.fullmatch(
        r"\$ ([0-9][0-9,]*)", data_rows[0][2]
    )
    second_band = re.fullmatch(
        r"exceeds \$ ([0-9][0-9,]*) but is not more than "
        r"\$ ([0-9][0-9,]*)",
        data_rows[1][1],
    )
    second_value = re.fullmatch(
        r"\$ ([0-9][0-9,]*), less an amount equal to "
        r"([0-9]+(?:\.[0-9]+)?)% of the excess",
        data_rows[1][2],
    )
    third_band = re.fullmatch(
        r"exceeds \$ ([0-9][0-9,]*) but is not more than "
        r"\$ ([0-9][0-9,]*)",
        data_rows[2][1],
    )
    third_value = re.fullmatch(
        r"\$ ([0-9][0-9,]*), less an amount equal to "
        r"([0-9]+(?:\.[0-9]+)?)% of the excess",
        data_rows[2][2],
    )
    if any(item is None for item in (
        first_band,
        first_value,
        second_band,
        second_value,
        third_band,
        third_value,
    )):
        raise ChangedExtraction(
            "ATO LITO law rows do not match the reviewed exact grammar"
        )
    full_to = _ato_lito_amount(first_band.group(1))
    max_offset = _ato_lito_amount(first_value.group(1))
    taper1_from = _ato_lito_amount(second_band.group(1))
    taper1_to = _ato_lito_amount(second_band.group(2))
    taper1_offset = _ato_lito_amount(second_value.group(1))
    taper1_rate = float(_finite_number(second_value.group(2))) / 100
    taper2_from = _ato_lito_amount(third_band.group(1))
    cut_out = _ato_lito_amount(third_band.group(2))
    taper2_offset = _ato_lito_amount(third_value.group(1))
    taper2_rate = float(_finite_number(third_value.group(2))) / 100
    if (
        taper1_from != full_to
        or taper1_offset != max_offset
        or taper2_from != taper1_to
    ):
        raise ChangedExtraction(
            "ATO LITO law thresholds/bases are not boundary-contiguous"
        )
    expected_taper2 = max_offset - taper1_rate * (
        taper1_to - full_to
    )
    if abs(expected_taper2 - taper2_offset) > 1e-9:
        raise ChangedExtraction(
            "ATO LITO law second taper base is arithmetically inconsistent"
        )
    residual = taper2_offset - taper2_rate * (cut_out - taper1_to)
    if abs(residual) > 0.01:
        raise ChangedExtraction(
            "ATO LITO law cut-out does not reduce offset to zero"
        )
    return ATO_LITO_UNIT, {
        "maxOffset": max_offset,
        "fullTo": full_to,
        "taper1To": taper1_to,
        "taper1Rate": taper1_rate,
        "cutOut": cut_out,
        "taper2Rate": taper2_rate,
    }


def _extract_ato_law_resident_brackets(
    body: bytes, params: dict[str, Any]
) -> tuple[str, list[list[int | float | None]]]:
    parser = _parse_html(body)
    candidates: list[tuple[list[list[str]], int]] = []
    for table in parser.tables:
        if table["hidden"] or not table["directLawBody"]:
            continue
        rows = table["rows"]
        header_indexes = [
            index
            for index, row in enumerate(rows)
            if row == ATO_LAW_RESIDENT_HEADERS
        ]
        title_rows = [
            index
            for index, row in enumerate(rows)
            if row in (
                [params["tableTitle"]],
                [params["tableTitle"], "", ""],
            )
        ]
        title_count = len(title_rows) + int(
            table["caption"] == params["tableTitle"]
        )
        if (
            len(header_indexes) == 1
            and title_count == 1
            and (
                table["caption"] == params["tableTitle"]
                or title_rows[0] < header_indexes[0]
            )
        ):
            candidates.append((rows, header_indexes[0]))
    if len(candidates) != 1:
        raise ChangedExtraction(
            "ATO resident law table requires one exact current title/header"
        )
    rows, header_index = candidates[0]
    data_rows = rows[header_index + 1 :]
    if (
        len(data_rows) != 4
        or any(len(row) != 3 for row in data_rows)
        or [row[0] for row in data_rows] != ["1", "2", "3", "4"]
    ):
        raise ChangedExtraction(
            "ATO resident law table requires exact complete items 1-4"
        )
    phrases = [
        r"exceeds the tax-free threshold but does not exceed \$([0-9][0-9,]*)",
        r"exceeds \$([0-9][0-9,]*) but does not exceed \$([0-9][0-9,]*)",
        r"exceeds \$([0-9][0-9,]*) but does not exceed \$([0-9][0-9,]*)",
        r"exceeds \$([0-9][0-9,]*)",
    ]
    matches = [
        re.fullmatch(pattern, row[1])
        for pattern, row in zip(phrases, data_rows)
    ]
    rate_matches = [
        re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)%", row[2])
        for row in data_rows
    ]
    if any(match is None for match in matches + rate_matches):
        raise ChangedExtraction(
            "ATO resident law bands/rates do not match the fixed grammar"
        )
    caps = [
        _ato_lito_amount(matches[0].group(1)),
        _ato_lito_amount(matches[1].group(2)),
        _ato_lito_amount(matches[2].group(2)),
    ]
    if (
        _ato_lito_amount(matches[1].group(1)) != caps[0]
        or _ato_lito_amount(matches[2].group(1)) != caps[1]
        or _ato_lito_amount(matches[3].group(1)) != caps[2]
        or not caps[0] < caps[1] < caps[2]
    ):
        raise ChangedExtraction(
            "ATO resident law bands are not strictly contiguous"
        )
    rates = [
        float(_finite_number(match.group(1))) / 100
        for match in rate_matches
    ]
    if any(not 0 <= rate <= 1 for rate in rates):
        raise ChangedExtraction("ATO resident rate is outside 0..1")
    return "AUD/rate", [
        [caps[0], rates[0]],
        [caps[1], rates[1]],
        [caps[2], rates[2]],
        [None, rates[3]],
    ]


def _extract_ato_tax_free_band(
    body: bytes, params: dict[str, Any]
) -> tuple[str, list[int | float]]:
    parser = _parse_html(body)
    heading_count = sum(
        level == 2 and text == params["heading"]
        for level, text in parser.heading_records
    )
    if heading_count != 1:
        raise ChangedExtraction(
            f"ATO tax-free H2 matched {heading_count} times"
        )
    matches = [
        text
        for heading, tag, text in parser.heading_blocks
        if heading == params["heading"]
        and tag == "p"
        and text == params["anchor"]
    ]
    if len(matches) != 1:
        raise ChangedExtraction(
            f"ATO tax-free paragraph matched {len(matches)} times"
        )
    grammar = re.fullmatch(
        r"The tax-free threshold is the amount of income you can earn "
        r"before you pay tax\. Most Australian residents can claim "
        r"tax-free threshold on the first \$([0-9][0-9,]*) of the "
        r"income they earn in the income year\.",
        matches[0],
    )
    if grammar is None:
        raise ChangedExtraction(
            "ATO tax-free paragraph does not match the fixed zero-band grammar"
        )
    threshold = _ato_lito_amount(grammar.group(1))
    if threshold <= 0:
        raise ChangedExtraction("ATO tax-free threshold must be positive")
    return "AUD/rate", [threshold, 0]


def _english_ordinal(number: int) -> str:
    if 10 <= number % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(number % 10, "th")
    return f"{number}{suffix}"


def _extract_cra_t4127_version(
    body: bytes, params: dict[str, Any]
) -> tuple[str, str]:
    parser = _parse_html(body)
    h1_values = [
        text for level, text in parser.heading_records if level == 1
    ]
    if len(h1_values) != 1:
        raise ChangedExtraction(
            f"CRA T4127 requires exactly one H1, found {len(h1_values)}"
        )
    heading = h1_values[0]
    language = params["language"]
    if language == "en":
        match = re.fullmatch(
            r"T4127-JUL Payroll Deductions Formulas - "
            r"([1-9][0-9]*)(st|nd|rd|th) "
            r"Edition - Effective "
            r"(January|February|March|April|May|June|July|August|"
            r"September|October|November|December) ([1-9]|[12][0-9]|3[01]), "
            r"([0-9]{4})",
            heading,
        )
        if match is None:
            raise ChangedExtraction(
                "CRA English T4127 H1 does not match the fixed version grammar"
            )
        edition = int(match.group(1))
        if match.group(1) + match.group(2) != _english_ordinal(edition):
            raise ChangedExtraction("CRA English edition ordinal is inconsistent")
        month_names = [
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
        ]
        month = month_names.index(match.group(3)) + 1
        year = int(match.group(5))
        day = int(match.group(4))
    else:
        match = re.fullmatch(
            r"T4127-JUL Formules pour le calcul des retenues sur la paie - "
            r"([1-9][0-9]*)e édition - En vigueur le "
            r"(1er|[2-9]|[12][0-9]|3[01]) "
            r"(janvier|février|mars|avril|mai|juin|juillet|août|"
            r"septembre|octobre|novembre|décembre) ([0-9]{4})",
            heading,
        )
        if match is None:
            raise ChangedExtraction(
                "CRA French T4127 H1 does not match the fixed version grammar"
            )
        edition = int(match.group(1))
        day = int(match.group(2).removesuffix("er"))
        month_names = [
            "janvier", "février", "mars", "avril", "mai", "juin",
            "juillet", "août", "septembre", "octobre", "novembre", "décembre",
        ]
        month = month_names.index(match.group(3)) + 1
        year = int(match.group(4))
    try:
        date(year, month, day)
    except ValueError as exc:
        raise ChangedExtraction("CRA T4127 effective date is invalid") from exc
    return (
        "table version",
        f"T4127-{_english_ordinal(edition)}-{year:04d}-{month:02d}",
    )


def _decode_reviewed_csv(body: bytes, encoding: str) -> str:
    bom = body.startswith(b"\xef\xbb\xbf")
    try:
        if encoding == "utf-8":
            if bom:
                raise ChangedExtraction(
                    "CSV has a BOM but encoding requires BOM-free UTF-8"
                )
            return body.decode("utf-8")
        if encoding == "utf-8-bom":
            if not bom:
                raise ChangedExtraction(
                    "CSV is missing the required UTF-8 BOM"
                )
            return body.decode("utf-8-sig")
        if bom:
            raise ChangedExtraction(
                "Windows-1252 CSV may not contain a UTF-8 BOM"
            )
        return body.decode("cp1252")
    except UnicodeDecodeError as exc:
        raise UnsupportedExtraction(
            f"CSV cannot be decoded as reviewed {encoding}: {exc}"
        ) from exc


def _reviewed_csv_rows(body: bytes, encoding: str) -> list[list[str]]:
    text = _decode_reviewed_csv(body, encoding)
    if "\x00" in text:
        raise UnsupportedExtraction("CSV contains a NUL byte")
    try:
        rows = list(
            csv.reader(
                io.StringIO(text, newline=""),
                dialect="excel",
                strict=True,
            )
        )
    except csv.Error as exc:
        raise ChangedExtraction(f"CSV syntax is invalid: {exc}") from exc
    if not 2 <= len(rows) <= 256:
        raise UnsupportedExtraction("CSV row count exceeds safe bounds")
    if any(
        len(row) > 16
        or any(len(cell) > 500 for cell in row)
        for row in rows
    ):
        raise UnsupportedExtraction("CSV column or field size exceeds safe bounds")
    return [row for row in rows if any(cell != "" for cell in row)]


def _csv_number(value: str, field: str) -> int | float:
    if not re.fullmatch(
        r"(?:0|[1-9][0-9]{0,2}(?:,[0-9]{3})*)(?:\.[0-9]+)?",
        value,
    ):
        raise ChangedExtraction(
            f"CRA CSV {field} is not one exact finite number: {value!r}"
        )
    number = float(value.replace(",", ""))
    if not math.isfinite(number):
        raise ChangedExtraction(f"CRA CSV {field} is non-finite")
    return int(number) if number.is_integer() else number


def _csv_values_until_blank(
    row: list[str], start: int, field: str
) -> list[int | float]:
    values: list[int | float] = []
    saw_blank = False
    for index, cell in enumerate(row[start:], start):
        if cell == "":
            saw_blank = True
            continue
        if saw_blank:
            raise ChangedExtraction(
                f"CRA CSV {field} has a value after an empty trailing cell"
            )
        values.append(_csv_number(cell, f"{field}[{index - start}]"))
    if not values:
        raise ChangedExtraction(f"CRA CSV {field} has no numeric values")
    return values


def _one_csv_row(
    rows: list[list[str]], predicate: Callable[[list[str]], bool], label: str
) -> tuple[int, list[str]]:
    matches = [
        (index, row) for index, row in enumerate(rows) if predicate(row)
    ]
    if len(matches) != 1:
        raise ChangedExtraction(
            f"CRA CSV {label} matched {len(matches)} rows; expected exactly one"
        )
    return matches[0]


def _extract_cra_rates_csv(
    rows: list[list[str]], spec: dict[str, Any]
) -> tuple[Any, Any]:
    title = (
        "Table 8.1 Rates (R, V), income thresholds (A), and constants "
        "(K, KP) effective July 1, 2026"
    )
    if rows[0] != [title] + [""] * 9:
        raise ChangedExtraction("CRA Table 8.1 title/date row changed")
    if rows[1] != ["", "", "1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th"]:
        raise ChangedExtraction("CRA Table 8.1 ordinal header changed")
    region = spec["region"]
    index, threshold_row = _one_csv_row(
        rows,
        lambda row: len(row) == 10 and row[:2] == [region, "A"],
        f"Table 8.1 {region} A",
    )
    rate_label = "R" if region == "Federal" else "V"
    constant_label = "K" if region == "Federal" else "KP"
    if index + 2 >= len(rows):
        raise ChangedExtraction(f"CRA Table 8.1 {region} component is partial")
    rate_row, constant_row = rows[index + 1 : index + 3]
    if (
        len(rate_row) != 10
        or rate_row[:2] != ["", rate_label]
        or len(constant_row) != 10
        or constant_row[:2] != ["", constant_label]
    ):
        raise ChangedExtraction(
            f"CRA Table 8.1 {region} rate/constant rows changed or are partial"
        )
    thresholds = _csv_values_until_blank(
        threshold_row, 2, f"{region}.thresholds"
    )
    rates = _csv_values_until_blank(rate_row, 2, f"{region}.rates")
    constants = _csv_values_until_blank(
        constant_row, 2, f"{region}.constants"
    )
    if (
        thresholds[0] != 0
        or constants[0] != 0
        or len(thresholds) != len(rates)
        or len(constants) != len(rates)
    ):
        raise ChangedExtraction(
            f"CRA Table 8.1 {region} component cardinality/base changed"
        )
    if spec["table"] == "rates-bc-split":
        if rates[0] != 0.0614:
            raise ChangedExtraction(
                "CRA Table 8.1 BC H2 payroll rate no longer equals reviewed 0.0614"
            )
        return (
            {
                "thresholds": "CAD",
                "ratesAfterFirst": "decimal rate",
            },
            {
                "thresholds": thresholds[1:] + [None],
                "ratesAfterFirst": rates[1:],
            },
        )
    brackets = [
        [thresholds[position + 1], rates[position]]
        for position in range(len(rates) - 1)
    ] + [[None, rates[-1]]]
    return {"brackets": "CAD/rate"}, {"brackets": brackets}


def _extract_cra_amounts_csv(
    rows: list[list[str]], spec: dict[str, Any]
) -> tuple[Any, Any]:
    title = "Table 8.2 Other rates and amounts effective July 1, 2026"
    if rows[0] != [title] + [""] * 10:
        raise ChangedExtraction("CRA Table 8.2 title/date row changed")
    header = [
        "", "Basic amount", "Index rate", "LCP rate", "LCP amount",
        "CEA", "S2", "T4 to V1", "V1 rate", "Abatement", "Surtax",
    ]
    if rows[1] != header:
        raise ChangedExtraction("CRA Table 8.2 header changed")
    table = spec["table"]
    if table == "amounts-federal":
        _index, row = _one_csv_row(
            rows,
            lambda item: len(item) == 11 and item[0] == "Federal",
            "Table 8.2 Federal",
        )
        if row[1] != "BPAF":
            raise ChangedExtraction("CRA Table 8.2 Federal BPAF marker changed")
        value = _csv_number(row[5], "Federal.CEA")
        return {"employmentAmount": "CAD"}, {"employmentAmount": value}
    if table == "amounts-bpa":
        region = spec["region"]
        _index, row = _one_csv_row(
            rows,
            lambda item: len(item) == 11 and item[0] == region,
            f"Table 8.2 {region}",
        )
        return {"bpa": "CAD"}, {"bpa": _csv_number(row[1], f"{region}.bpa")}
    index, row = _one_csv_row(
        rows,
        lambda item: len(item) == 11 and item[0] == "ON",
        "Table 8.2 ON",
    )
    if index + 2 >= len(rows):
        raise ChangedExtraction("CRA Table 8.2 ON surtax component is partial")
    lower, upper = rows[index + 1 : index + 3]
    if (
        len(lower) != 11
        or len(upper) != 11
        or any(lower[position] for position in range(7))
        or any(upper[position] for position in range(7))
        or any(lower[position] for position in range(9, 11))
        or any(upper[position] for position in range(9, 11))
    ):
        raise ChangedExtraction("CRA Table 8.2 ON continuation rows changed")
    value = {
        "bpa": _csv_number(row[1], "ON.bpa"),
        "surtaxLower": _csv_number(lower[7], "ON.surtaxLower"),
        "surtaxLowerRate": _csv_number(lower[8], "ON.surtaxLowerRate"),
        "surtaxUpper": _csv_number(upper[7], "ON.surtaxUpper"),
        "surtaxUpperRate": _csv_number(upper[8], "ON.surtaxUpperRate"),
    }
    unit = {
        "bpa": "CAD",
        "surtaxLower": "CAD",
        "surtaxLowerRate": "decimal rate",
        "surtaxUpper": "CAD",
        "surtaxUpperRate": "decimal rate",
    }
    return unit, value


def _extract_cra_contribution_csv(
    rows: list[list[str]], spec: dict[str, Any]
) -> tuple[Any, Any]:
    table = spec["table"]
    if table == "federal-bpa":
        title = "Table 8.9 Federal claim codes (using maximum BPAF)"
        headers = [
            "Claim code", "Total claim amount ($) from",
            "Total claim amount ($) to", "Option 1, TC ($)",
            "Option 1, K1 ($)",
        ]
        if rows[0] != [title] + [""] * 4 or rows[1] != headers:
            raise ChangedExtraction(
                "CRA Table 8.9 title/header or maximum-BPA marker changed"
            )
        _index, row = _one_csv_row(
            rows,
            lambda item: len(item) == 5 and item[0] == "1",
            "Table 8.9 claim code 1",
        )
        if row[1] != "0":
            raise ChangedExtraction(
                "CRA Table 8.9 claim code 1 lower bound changed"
            )
        for position in range(1, 5):
            _csv_number(row[position], f"claimCode1[{position}]")
        upper = _csv_number(row[2], "claimCode1.maximumBpa")
        if _csv_number(row[3], "claimCode1.option1Tc") != upper:
            raise ChangedExtraction(
                "CRA Table 8.9 claim code 1 BPA and TC differ"
            )
        return {"bpa": "CAD"}, {"bpa": upper}
    definitions: dict[str, tuple[str, list[str], str, dict[str, tuple[int, str]]]] = {
        "cpp-total": (
            "Table 8.3 Canada Pension Plan / Quebec Pension Plan 2026 contribution rates and amounts",
            [
                "CPP/QPP", "Year’s Maximum Pensionable Earnings (YMPE)",
                "Basic Exemption", "Year’s Maximum Contributory Earnings",
                "Employee  and Employer Total Contribution Rate",
                "Maximum Employee and Employer Total Contribution*",
                "YMPE Before Rounding",
            ],
            "CPP (Canada except QC)",
            {"ympe": (1, "CAD"), "exempt": (2, "CAD"), "rate": (4, "decimal rate")},
        ),
        "cpp-base": (
            "Table 8.4 Base Canada Pension Plan / Quebec Pension Plan 2026 rates and amounts",
            [
                "CPP/QPP", "Year’s Maximum Pensionable Earnings (YMPE)",
                "Base Employee and Employer Contribution Rate",
                "Maximum Base Employee and Employer Contribution*",
            ],
            "CPP (Canada except QC)",
            {"baseRate": (2, "decimal rate")},
        ),
        "cpp-first": (
            "Table 8.5 First additional Canada Pension Plan / Quebec Pension Plan 2026 rates and amounts",
            [
                "CPP/QPP", "Year’s Maximum Pensionable Earnings (YMPE)",
                "First Additional Employee and Employer Contribution Rate",
                "Maximum First Additional Employee and Employer Contribution*",
            ],
            "CPP (Canada except QC)",
            {"additionalRate": (2, "decimal rate")},
        ),
        "cpp-second": (
            "Table 8.6 Second additional Canada Pension Plan / Quebec Pension Plan 2026 rates and amounts",
            [
                "CPP/QPP", "Year’s Maximum Pensionable Earnings (YMPE)",
                "Year’s Additional Maximum Pensionable Earnings (YAMPE)",
                "Pensionable earnings subject to Second Additional Contribution",
                "Second Additional Employee and Employer Contribution Rate",
                "Maximum Second Additional Employee and Employer Contribution*",
            ],
            "CPP (Canada except QC)",
            {
                "cpp2Min": (1, "CAD"), "cpp2Max": (2, "CAD"),
                "cpp2Rate": (4, "decimal rate"),
            },
        ),
        "ei": (
            "Table 8.7 Employment Insurance 2026 rates and amounts",
            [
                "EI", "Maximum Annual Insurable Earnings",
                "Employee Contribution Rate", "Employer Contribution Rate",
                "Maximum Annual Employee Premium", "Maximum Annual Employer Premium",
            ],
            "Canada except QC",
            {"maxInsurable": (1, "CAD"), "rate": (2, "decimal rate")},
        ),
    }
    title, headers, label, selected = definitions[table]
    if rows[0] != [title] + [""] * (len(headers) - 1):
        raise ChangedExtraction(f"CRA {title.split()[1]} title/year row changed")
    if table == "cpp-total":
        if len(rows) < 4 or rows[2] != ["", "", "", "(YMCE)", "", "", ""]:
            raise ChangedExtraction("CRA Table 8.3 secondary header changed")
    if rows[1] != headers:
        raise ChangedExtraction("CRA contribution table header changed")
    _index, row = _one_csv_row(
        rows,
        lambda item: len(item) == len(headers) and item[0] == label,
        f"CRA contribution row {label}",
    )
    for position, cell in enumerate(row[1:], 1):
        _csv_number(cell, f"{label}[{position}]")
    value = {
        key: _csv_number(row[position], key)
        for key, (position, _unit) in selected.items()
    }
    unit = {key: unit_name for key, (_position, unit_name) in selected.items()}
    return unit, value


def _extract_cra_t4127_csv(
    body: bytes, params: dict[str, Any]
) -> tuple[Any, Any]:
    rows = _reviewed_csv_rows(body, params["encoding"])
    spec = CRA_T4127_CSV_SPECS[params["cohort"]]
    if spec["table"].startswith("rates"):
        return _extract_cra_rates_csv(rows, spec)
    if spec["table"].startswith("amounts"):
        return _extract_cra_amounts_csv(rows, spec)
    return _extract_cra_contribution_csv(rows, spec)


def _extract_cra_t4127_bc_annual_rate(
    body: bytes, params: dict[str, Any]
) -> tuple[Any, Any]:
    parser = _parse_html(body)
    annual_pattern = re.compile(
        r"On February 17, 2026, the Government of British Columbia "
        r"announced a change to the lowest personal income tax rate and "
        r"the BC tax reduction\. For 2026 and subsequent years, the lowest "
        r"personal tax rate is increased from 5\.06% to 5\.60%\."
    )
    prorated_pattern = re.compile(
        r"Since the employers have used a lower tax rate for the first six "
        r"months of the year, a prorated lowest personal income tax rate of "
        r"6\.14% will apply for the remaining six months commencing with "
        r"the first payroll in July\. The tax rates and brackets are as follows:"
    )
    option_pattern = re.compile(
        r"See Table 8\.1 for rates, income thresholds, and constants and "
        r"Table 8\.2 for other rates and amounts\. The Option 2 rates will "
        r"not be prorated\."
    )
    groups = [
        [block for block in parser.block_texts if pattern.fullmatch(block)]
        for pattern in (annual_pattern, prorated_pattern, option_pattern)
    ]
    if [len(group) for group in groups] != [1, 1, 1]:
        raise ChangedExtraction(
            "CRA BC annual/prorated/Option 2 evidence cardinality changed"
        )
    return {"rate": "decimal rate"}, {"rate": 0.056}


CRA_T4032_ON_HEALTH_BLOCKS = (
    "when taxable income is less than or equal to $20,000, the premium is $0",
    "when taxable income is greater than $20,000 and less than or equal to "
    "$36,000, the premium is equal to the lesser of (i) $300 and (ii) 6% "
    "of taxable income greater than $20,000",
    "when taxable income is greater than $36,000 and less than or equal to "
    "$48,000, the premium is equal to the lesser of (i) $450 and (ii) $300 "
    "plus 6% of taxable income greater than $36,000",
    "when taxable income is greater than $48,000 and less than or equal to "
    "$72,000, the premium is equal to the lesser of (i) $600 and (ii) $450 "
    "plus 25% of taxable income greater than $48,000",
    "when taxable income is greater than $72,000 and less than or equal to "
    "$200,000, the premium is equal to the lesser of (i) $750 and (ii) $600 "
    "plus 25% of taxable income greater than $72,000",
    "when taxable income is greater than $200,000, the premium is equal to "
    "the lesser of (i) $900 and (ii) $750 plus 25% of taxable income greater "
    "than $200,000",
)
CRA_T4032_ON_REVISION = "T4032-ON(E) Rev. 26"
CRA_T4032_ON_EFFECTIVE_HEADING = "What's new as of January 1, 2026"
CRA_T4032_ON_HEALTH_LEAD = "For 2026, the Ontario health premium is:"
CRA_T4032_ON_REDUCTION_LEAD = (
    "For 2026, Ontario's tax reduction amounts are:"
)
CRA_T4032_ON_REDUCTION_SENTENCE = (
    "The reduction is equal to twice the individual's personal amounts minus "
    "the provincial tax payable before reduction. The reduction cannot be "
    "more than the provincial tax payable before reduction. The reduction is "
    "nil when the provincial tax payable before reduction is more than twice "
    "the personal amounts. Because of the way the reduction for dependants "
    "with disabilities is determined, we include only the basic personal "
    "amount in the provincial tax tables."
)


def _extract_cra_t4032_on(
    body: bytes, params: dict[str, Any]
) -> tuple[Any, Any]:
    parser = _parse_html(body)
    h1 = "Payroll Deductions Tables - CPP, EI, and income tax deductions - Ontario"
    if parser.heading_records.count((1, h1)) != 1:
        raise ChangedExtraction("CRA T4032ON exact H1 cardinality changed")
    if parser.block_texts.count(CRA_T4032_ON_REVISION) != 1:
        raise ChangedExtraction("CRA T4032ON Rev. 26 evidence changed")
    if parser.headings.count(CRA_T4032_ON_EFFECTIVE_HEADING) != 1:
        raise ChangedExtraction(
            "CRA T4032ON January 1, 2026 heading cardinality changed"
        )
    if parser.block_texts.count(CRA_T4032_ON_HEALTH_LEAD) != 1:
        raise ChangedExtraction(
            "CRA T4032ON 2026 health lead cardinality changed"
        )
    if parser.block_texts.count(CRA_T4032_ON_REDUCTION_LEAD) != 1:
        raise ChangedExtraction(
            "CRA T4032ON 2026 tax-reduction lead cardinality changed"
        )
    if parser.headings.count("Ontario health premium") != 1:
        raise ChangedExtraction("CRA T4032ON health section cardinality changed")
    health_items = [
        block
        for heading, block in parser.list_items
        if heading == "Ontario health premium"
    ]
    if health_items != list(CRA_T4032_ON_HEALTH_BLOCKS):
        raise ChangedExtraction(
            "CRA T4032ON health bullets are missing, reordered, duplicated, or changed"
        )
    if parser.headings.count("Tax reduction") != 1:
        raise ChangedExtraction("CRA T4032ON tax reduction section changed")
    reduction_blocks = [
        block
        for heading, tag, block in parser.heading_blocks
        if heading == "Tax reduction" and tag == "p"
    ]
    basic_matches = [
        block for block in reduction_blocks
        if re.fullmatch(r"Basic personal amount\.{3,} \$300", block)
    ]
    sentence_matches = [
        block for block in reduction_blocks
        if block == CRA_T4032_ON_REDUCTION_SENTENCE
    ]
    if len(basic_matches) != 1 or len(sentence_matches) != 1:
        raise ChangedExtraction(
            "CRA T4032ON $300/twice-personal-amount evidence changed"
        )
    health = {
        "zeroTo": 20000,
        "tiers": [
            {"to": 36000, "base": 0, "offset": 20000, "rate": 0.06, "cap": 300},
            {"to": 48000, "base": 300, "offset": 36000, "rate": 0.06, "cap": 450},
            {"to": 72000, "base": 450, "offset": 48000, "rate": 0.25, "cap": 600},
            {"to": 200000, "base": 600, "offset": 72000, "rate": 0.25, "cap": 750},
        ],
        "above": {"base": 750, "offset": 200000, "rate": 0.25, "cap": 900},
    }
    return (
        {"taxReduction": "CAD", "health": "CAD/rate"},
        {"taxReduction": 600, "health": health},
    )


def _pdf_literal_at(text: str, index: int) -> tuple[str, int]:
    if index >= len(text) or text[index] != "(":
        raise ChangedExtraction("PDF literal does not start with '('")
    index += 1
    depth = 1
    chars: list[str] = []
    while index < len(text) and depth:
        char = text[index]
        index += 1
        if char == "\\":
            if index >= len(text):
                raise ChangedExtraction("unterminated PDF string escape")
            escaped = text[index]
            index += 1
            chars.append(
                {
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    "b": "\b",
                    "f": "\f",
                }.get(escaped, escaped)
            )
        elif char == "(":
            depth += 1
            if depth > 32:
                raise UnsupportedExtraction(
                    "PDF literal nesting exceeds safe depth"
                )
            chars.append(char)
        elif char == ")":
            depth -= 1
            if depth:
                chars.append(char)
        else:
            chars.append(char)
    if depth:
        raise ChangedExtraction("unterminated PDF literal string")
    return "".join(chars), index


def _pdf_operator_at(text: str, index: int, operator: str) -> bool:
    end = index + len(operator)
    return (
        text.startswith(operator, index)
        and (index == 0 or not text[index - 1].isalpha())
        and (end == len(text) or not text[end].isalpha())
    )


def _pdf_literal_lines_from_bytes(content: bytes) -> list[str]:
    text = content.decode("latin-1")
    tokens = list(re.finditer(r"(?<![A-Za-z])(?:BT|ET)(?![A-Za-z])", text))
    regions: list[tuple[int, int]] = []
    start: int | None = None
    for token in tokens:
        if token.group(0) == "BT":
            if start is not None:
                raise ChangedExtraction("PDF text objects may not nest")
            start = token.end()
        else:
            if start is None:
                raise ChangedExtraction("PDF ET has no matching BT")
            regions.append((start, token.start()))
            start = None
    if start is not None:
        raise ChangedExtraction("PDF BT has no matching ET")
    for outside_match in re.finditer(
        r"(?:\)|\]|>)\s*(?:Tj|TJ)(?![A-Za-z])", text
    ):
        operator_position = outside_match.end() - 2
        if not any(
            region_start <= operator_position < region_end
            for region_start, region_end in regions
        ):
            raise ChangedExtraction(
                "PDF text operator appears outside a balanced BT/ET object"
            )

    lines: list[str] = []
    number_token = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)")
    for region_start, region_end in regions:
        region = text[region_start:region_end]
        index = 0
        while index < len(region):
            if region[index] == "(":
                literal, after = _pdf_literal_at(region, index)
                probe = after
                while probe < len(region) and region[probe].isspace():
                    probe += 1
                if _pdf_operator_at(region, probe, "Tj"):
                    normalized = _normalize_text(literal)
                    if normalized:
                        lines.append(normalized)
                    index = probe + 2
                    continue
                index = after
                continue
            if region[index] == "[":
                close = region.find("]", index + 1)
                if close < 0:
                    raise ChangedExtraction("unterminated PDF TJ array")
                if "[" in region[index + 1 : close]:
                    raise UnsupportedExtraction("nested PDF TJ arrays are unsupported")
                probe = close + 1
                while probe < len(region) and region[probe].isspace():
                    probe += 1
                if not _pdf_operator_at(region, probe, "TJ"):
                    index = close + 1
                    continue
                cursor = index + 1
                pieces: list[str] = []
                token_count = 0
                while cursor < close:
                    while cursor < close and region[cursor].isspace():
                        cursor += 1
                    if cursor >= close:
                        break
                    token_count += 1
                    if token_count > 256:
                        raise UnsupportedExtraction(
                            "PDF TJ array exceeds safe token count"
                        )
                    if region[cursor] == "(":
                        literal, cursor = _pdf_literal_at(region, cursor)
                        if cursor > close:
                            raise ChangedExtraction(
                                "PDF TJ literal crosses array boundary"
                            )
                        pieces.append(literal)
                        continue
                    if region[cursor] == "<":
                        raise UnsupportedExtraction(
                            "hex-string PDF TJ text is unsupported"
                        )
                    number = number_token.match(region, cursor)
                    if number is None or number.end() > close:
                        raise ChangedExtraction(
                            "PDF TJ array contains a non-literal/non-number token"
                        )
                    cursor = number.end()
                if not pieces:
                    raise ChangedExtraction("PDF TJ array has no literal text")
                normalized = _normalize_text("".join(pieces))
                if normalized:
                    lines.append(normalized)
                index = probe + 2
                continue
            if region[index] == "<":
                hex_match = re.match(r"<[0-9A-Fa-f\s]*>\s*Tj\b", region[index:])
                if hex_match:
                    raise UnsupportedExtraction(
                        "hex-string PDF Tj text is unsupported"
                    )
            index += 1
    return lines


def _pdf_classic_xref_is_valid(body: bytes) -> bool:
    matches = list(re.finditer(rb"startxref\s+([0-9]+)\s+%%EOF\s*$", body))
    if len(matches) != 1:
        return False
    offset = int(matches[0].group(1))
    return 0 <= offset < len(body) and body[offset : offset + 4] == b"xref"


def _bounded_flate(data: bytes) -> bytes:
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(
            data, MAX_PDF_DECOMPRESSED_BYTES + 1
        )
        if len(output) <= MAX_PDF_DECOMPRESSED_BYTES:
            output += decompressor.flush(
                MAX_PDF_DECOMPRESSED_BYTES + 1 - len(output)
            )
    except zlib.error as exc:
        raise ChangedExtraction(f"invalid PDF Flate stream: {exc}") from exc
    if not decompressor.eof or decompressor.unused_data:
        raise ChangedExtraction("PDF Flate stream is truncated or has trailing data")
    if len(output) > MAX_PDF_DECOMPRESSED_BYTES:
        raise UnsupportedExtraction("PDF decompressed stream exceeds safe limit")
    if len(data) == 0 or len(output) > len(data) * MAX_PDF_COMPRESSION_RATIO:
        raise UnsupportedExtraction("PDF Flate compression ratio exceeds safe limit")
    return output


def _pdf_literal_lines(body: bytes) -> list[str]:
    if not body.startswith(b"%PDF-"):
        raise UnsupportedExtraction("body is not a PDF")
    if len(body) > MAX_BODY_BYTES:
        raise UnsupportedExtraction("PDF body exceeds safe limit")
    if not body.rstrip().endswith(b"%%EOF"):
        raise ChangedExtraction("PDF is truncated before %%EOF")
    for marker in (b"/Encrypt", b"/ObjStm", b"/ToUnicode", b"/DecodeParms"):
        if marker in body:
            raise UnsupportedExtraction(
                f"PDF feature {marker.decode('ascii')} is not safely supported"
            )
    if re.search(rb"/Type\s*/XRef\b", body):
        raise UnsupportedExtraction("PDF xref streams are unsupported")
    if re.search(rb"/Subtype\s*/(?:Type0|CIDFontType[02]|Type3)\b", body):
        raise UnsupportedExtraction("PDF uses an unsupported font encoding")
    if not _pdf_classic_xref_is_valid(body):
        raise ChangedExtraction(
            "PDF requires exactly one valid classic xref/startxref"
        )
    object_matches = list(
        re.finditer(
            rb"(?ms)([1-9][0-9]*)\s+([0-9]+)\s+obj\b(.*?)\bendobj\b",
            body,
        )
    )
    if len(object_matches) > MAX_PDF_OBJECTS:
        raise UnsupportedExtraction("PDF object count exceeds safe limit")
    if any(len(match.group(3)) > MAX_PDF_OBJECT_BYTES for match in object_matches):
        raise UnsupportedExtraction("PDF object exceeds safe size limit")

    contents: list[bytes] = []
    total_content_bytes = 0
    stream_count = 0
    for match in object_matches:
        object_body = match.group(3)
        stream_match = re.fullmatch(
            rb"(?s)(.*?)\bstream\r?\n(.*?)\r?\nendstream\s*",
            object_body.strip(),
        )
        if stream_match is None:
            continue
        stream_count += 1
        if stream_count > MAX_PDF_STREAMS:
            raise UnsupportedExtraction("PDF stream count exceeds safe limit")
        dictionary = stream_match.group(1)
        stream = stream_match.group(2)
        filters = re.findall(rb"/Filter\s*/([A-Za-z0-9]+)", dictionary)
        array_filter = re.search(rb"/Filter\s*\[", dictionary)
        if array_filter or len(filters) > 1:
            raise UnsupportedExtraction("PDF filter chains are unsupported")
        if filters:
            if filters[0] != b"FlateDecode":
                raise UnsupportedExtraction(
                    "PDF stream filter is not safely supported"
                )
            content = _bounded_flate(stream)
        else:
            content = stream
        total_content_bytes += len(content)
        if total_content_bytes > MAX_PDF_DECOMPRESSED_BYTES:
            raise UnsupportedExtraction(
                "PDF aggregate text stream bytes exceed safe limit"
            )
        contents.append(content)
    if b"stream" in body and stream_count == 0:
        raise ChangedExtraction("PDF stream/object boundaries are malformed")
    if not contents:
        if len(body) > MAX_PDF_DECOMPRESSED_BYTES:
            raise UnsupportedExtraction(
                "PDF aggregate literal content exceeds safe limit"
            )
        contents = [body]
    lines: list[str] = []
    for content in contents:
        lines.extend(_pdf_literal_lines_from_bytes(content))
    if not lines:
        raise UnsupportedExtraction("PDF has no supported literal text operators")
    return lines


def _extract_pdf_table(
    body: bytes, params: dict[str, Any]
) -> tuple[str, Any]:
    lines = _pdf_literal_lines(body)
    if lines.count(params["anchor"]) != 1:
        raise ChangedExtraction(
            f"PDF anchor {params['anchor']!r} matched "
            f"{lines.count(params['anchor'])} times"
        )
    start = lines.index(params["anchor"]) + 1
    delimiter = params["delimiter"]
    rows = [
        [part.strip() for part in line.split(delimiter)]
        for line in lines[start:]
        if delimiter in line
    ]
    return _extract_table_rows(
        rows,
        params["headers"],
        params["unitLabel"],
        params["valueTypes"],
        params["nullToken"],
    )


def _extract_json_record(
    body: bytes, params: dict[str, Any]
) -> tuple[Any, Any]:
    try:
        data = _json_loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ChangedExtraction(f"invalid JSON source: {exc}") from exc
    try:
        record = _resolve_pointer(data, params["pointer"])
    except RegistryError as exc:
        raise ChangedExtraction(str(exc)) from exc
    if (
        not isinstance(record, dict)
        or set(record) != {"unit", "value"}
        or not _valid_unit_tree(record["unit"])
        or not _unit_tree_aligned(record["unit"], record["value"])
        or not _finite_json(record["value"])
    ):
        raise ChangedExtraction(
            "JSON pointer must resolve to exact {unit,value} finite record"
        )
    return record["unit"], record["value"]


def _extract_api_json_record(
    body: bytes, params: dict[str, Any]
) -> tuple[str, Any]:
    try:
        data = _json_loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ChangedExtraction(f"invalid API JSON source: {exc}") from exc
    try:
        records = _resolve_pointer(data, params["arrayPointer"])
    except RegistryError as exc:
        raise ChangedExtraction(str(exc)) from exc
    if not isinstance(records, list):
        raise ChangedExtraction("arrayPointer did not resolve to an array")
    match_fields = params["match"]
    matches = [
        record
        for record in records
        if isinstance(record, dict)
        and all(record.get(key) == value for key, value in match_fields.items())
    ]
    if len(matches) != 1:
        raise ChangedExtraction(
            f"exact record selector matched {len(matches)} rows"
        )
    try:
        value = _resolve_pointer(matches[0], params["valuePointer"])
    except RegistryError as exc:
        raise ChangedExtraction(str(exc)) from exc
    transform = params.get("transform", "identity")
    if transform == "currency-to-number":
        if not isinstance(value, str):
            raise ChangedExtraction("currency transform requires a string")
        normalized = _normalize_text(value)
        match = re.fullmatch(
            r"(AUD|CAD|NZD)\s*\$?\s*([0-9][0-9,]*(?:\.\d+)?)",
            normalized,
        )
        if not match:
            raise ChangedExtraction(
                f"{value!r} lacks an exact supported ISO currency prefix"
            )
        unit = match.group(1)
        value = _finite_number(match.group(2))
        return unit, value
    if (
        not isinstance(value, dict)
        or set(value) != {"unit", "value"}
        or not isinstance(value["unit"], str)
        or not value["unit"]
        or not _finite_json(value["value"])
    ):
        raise ChangedExtraction(
            "identity API value must be an exact finite {unit,value} record"
        )
    return value["unit"], value["value"]


EXTRACTORS: dict[
    str, Callable[[bytes, dict[str, Any]], tuple[Any, Any]]
] = {
    "html-table": _extract_html_table,
    "html-definition": _extract_html_definition,
    "html-table-record": _extract_html_table_record,
    "html-labelled-values": _extract_html_labelled_values,
    "html-text-anchor": _extract_html_text_anchor,
    "html-section-text": _extract_html_section_text,
    "pdf-table": _extract_pdf_table,
    "json-pointer": _extract_json_record,
    "api-json-pointer": _extract_json_record,
    "api-json-record": _extract_api_json_record,
    "ato-lito": _extract_ato_lito,
    "ato-law-lito": _extract_ato_law_lito,
    "ato-law-resident-brackets": _extract_ato_law_resident_brackets,
    "ato-tax-free-band": _extract_ato_tax_free_band,
    "cra-t4127-version": _extract_cra_t4127_version,
    "cra-t4127-csv": _extract_cra_t4127_csv,
    "cra-t4127-bc-annual-rate": _extract_cra_t4127_bc_annual_rate,
    "cra-t4032-on": _extract_cra_t4032_on,
}


def _expected_media(mode: str, media_type: str) -> bool:
    normalized = _media_type(media_type)
    if (
        mode.startswith("html-")
        or mode.startswith("ato-")
        or mode in {
            "cra-t4127-version",
            "cra-t4127-bc-annual-rate",
            "cra-t4032-on",
        }
    ):
        return normalized in HTML_MEDIA_TYPES
    if mode == "cra-t4127-csv":
        return normalized in CSV_MEDIA_TYPES
    if mode == "pdf-table":
        return normalized in PDF_MEDIA_TYPES
    return normalized in JSON_MEDIA_TYPES or normalized.endswith("+json")


def _blocked_body(media_type: str, body: bytes) -> bool:
    if _media_type(media_type) not in HTML_MEDIA_TYPES:
        return False
    text = body[:200_000].decode("utf-8", errors="ignore").lower()
    if "verify you are human" in text or "cf-chl-" in text:
        return True
    if re.search(
        r"<title[^>]*>\s*just a moment(?:\.\.\.)?\s*</title>", text
    ):
        return True
    return (
        "<form" in text
        and ("type=\"password\"" in text or "type='password'" in text)
        and ("sign in" in text or "log in" in text or "login" in text)
    )


def _evaluate_response(
    attestation: dict[str, Any],
    response: SourceResponse,
    *,
    offline: bool,
    root: Path,
) -> AttestationResult:
    attestation_id = attestation["id"]
    source = attestation["sourceUrl"]
    request_url = _request_url(attestation)
    target_parts = [
        f"{item['targetId']}{item['reviewedPath']}"
        for item in attestation.get("targets", [])
    ]
    target_parts.extend(
        f"claim:{item['claimId']}@{item.get('expectedPath', '/')}"
        for item in attestation.get("claims", [])
    )
    target_path = ",".join(target_parts)
    expected = attestation["expected"]
    context = response.body
    if response.error is not None:
        return _result(
            attestation_id,
            source,
            target_path,
            "transient",
            response.error,
            expected,
            "Retry the live audit; investigate DNS/TLS/timeout if it persists.",
            context=context,
            request_url=request_url,
        )
    try:
        _validate_official_url(response.final_url, attestation["jurisdiction"])
        relation = attestation.get("_sourceRelation")
        if relation in {"citation", "same-host"} and (
            _canonical_hostname(response.final_url)
            != _canonical_hostname(attestation["sourceUrl"])
        ):
            raise RegistryError(
                "candidate redirect left its citation canonical hostname"
            )
    except RegistryError as exc:
        return _result(
            attestation_id,
            source,
            target_path,
            "unsupported",
            {"finalUrl": response.final_url, "error": str(exc)},
            source,
            "Restore an allowlisted official redirect target.",
            context=context,
            request_url=request_url,
        )
    status = response.status or 0
    if status in {401, 403} or _blocked_body(
        response.media_type, response.body
    ):
        return _result(
            attestation_id,
            source,
            target_path,
            "blocked",
            {"httpStatus": status, "finalUrl": response.final_url},
            expected,
            "Review the source manually or arrange approved machine access; never mark blocked as matched.",
            context=context,
            request_url=request_url,
        )
    if status == 429 or 500 <= status <= 599:
        return _result(
            attestation_id,
            source,
            target_path,
            "transient",
            {"httpStatus": status, "finalUrl": response.final_url},
            expected,
            "Retry after the official service recovers; do not update expected values.",
            context=context,
            request_url=request_url,
        )
    if response.too_large:
        return _result(
            attestation_id,
            source,
            target_path,
            "unsupported",
            f"body exceeds {MAX_BODY_BYTES} bytes",
            expected,
            "Use a smaller official endpoint or add a reviewed bounded extractor.",
            context=context,
            request_url=request_url,
        )
    if status < 200 or status >= 300:
        return _result(
            attestation_id,
            source,
            target_path,
            "changed",
            {"httpStatus": status, "finalUrl": response.final_url},
            expected,
            "Confirm whether the official source moved, then review the canonical URL.",
            context=context,
            request_url=request_url,
        )
    if not response.body.strip():
        return _result(
            attestation_id,
            source,
            target_path,
            "changed",
            "empty response body",
            expected,
            "Inspect the official response and refresh the reviewed fixture only after evidence review.",
            context=context,
            request_url=request_url,
        )
    mode = attestation["extractor"]["mode"]
    candidate_media = attestation.get("_candidateMediaType")
    if (
        candidate_media is not None
        and _media_type(response.media_type) != candidate_media
    ):
        return _result(
            attestation_id,
            source,
            target_path,
            "unsupported",
            response.media_type,
            candidate_media,
            "Restore the candidate's reviewed exact response media type.",
            context=context,
            request_url=request_url,
        )
    if not _expected_media(mode, response.media_type):
        return _result(
            attestation_id,
            source,
            target_path,
            "unsupported",
            response.media_type,
            f"media compatible with {mode}",
            "Use the correct official representation or a reviewed extractor enum.",
            context=context,
            request_url=request_url,
        )
    if offline:
        actual_fingerprint = _fingerprint_bytes(response.body)
        expected_fingerprint = attestation["fixture"]["sha256"]
        if actual_fingerprint != expected_fingerprint:
            return _result(
                attestation_id,
                source,
                target_path,
                "changed",
                actual_fingerprint,
                expected_fingerprint,
                "Review the fixture diff and update its fingerprint only with official evidence.",
                context=context,
                request_url=request_url,
            )
    extractor = EXTRACTORS[mode]
    try:
        actual_unit, actual_value = extractor(
            response.body, attestation["extractor"]["params"]
        )
    except UnsupportedExtraction as exc:
        return _result(
            attestation_id,
            source,
            target_path,
            "unsupported",
            str(exc),
            expected,
            "Use a supported official representation or add a reviewed bounded extractor.",
            context=context,
            request_url=request_url,
        )
    except ChangedExtraction as exc:
        return _result(
            attestation_id,
            source,
            target_path,
            "changed",
            str(exc),
            expected,
            "Review the source layout and values; update extractor parameters only after evidence review.",
            context=context,
            request_url=request_url,
        )
    actual = {"type": _value_type(actual_value), "unit": actual_unit, "value": actual_value}
    if actual != expected:
        return _result(
            attestation_id,
            source,
            target_path,
            "changed",
            actual,
            expected,
            "Review the official value/unit drift and update the boundary manifest through factual review.",
            context={"body": _fingerprint_bytes(context), "actual": actual},
            request_url=request_url,
        )
    return _result(
        attestation_id,
        source,
        target_path,
        "match",
        actual,
        expected,
        "No action required.",
        context={"body": _fingerprint_bytes(context), "actual": actual},
        request_url=request_url,
    )


def _offline_response(root: Path, attestation: dict[str, Any]) -> SourceResponse:
    fixture = attestation["fixture"]
    body = _safe_path(root, fixture["path"]).read_bytes()
    return SourceResponse(
        fixture["httpStatus"],
        fixture["finalUrl"],
        fixture["mediaType"],
        body,
        too_large=len(body) > MAX_BODY_BYTES,
    )


def _ssl_context() -> ssl.SSLContext:
    paths = ssl.get_default_verify_paths()
    if paths.cafile or paths.capath:
        return ssl.create_default_context()
    fallback = Path("/etc/ssl/cert.pem")
    if fallback.is_file():
        return ssl.create_default_context(cafile=str(fallback))
    return ssl.create_default_context()


def _transport_error_message(exc: Exception) -> str:
    reason = exc.reason if isinstance(exc, urllib_error.URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError) or (
        "CERTIFICATE_VERIFY_FAILED" in str(reason).upper()
    ):
        return f"TLS certificate verification failed: {reason}"
    return f"{type(exc).__name__}: {exc}"


def _live_request_headers(url: str) -> dict[str, str]:
    headers = dict(DEFAULT_LIVE_REQUEST_HEADERS)
    if _canonical_hostname(url) in CANADA_CURL_COMPAT_HOSTS:
        headers["User-Agent"] = CANADA_CURL_COMPAT_USER_AGENT
        headers["Accept-Encoding"] = "identity"
    return headers


def _latency_bucket(seconds: float) -> str:
    if not isinstance(seconds, (int, float)) or not math.isfinite(seconds):
        raise ValueError("latency must be finite")
    milliseconds = max(0.0, float(seconds) * 1_000)
    if milliseconds < 250:
        return "lt250ms"
    if milliseconds < 1_000:
        return "250ms-999ms"
    if milliseconds < 5_000:
        return "1s-4.999s"
    if milliseconds < 15_000:
        return "5s-14.999s"
    return "15s-plus"


def _classify_request_response(
    attestation: dict[str, Any], response: SourceResponse
) -> str:
    if response.error is not None:
        return "transient"
    try:
        _validate_official_url(
            response.final_url, attestation["jurisdiction"]
        )
        relation = attestation.get("_sourceRelation")
        if relation in {"citation", "same-host"} and (
            _canonical_hostname(response.final_url)
            != _canonical_hostname(attestation["sourceUrl"])
        ):
            raise RegistryError("candidate redirect host changed")
    except RegistryError:
        return "unsupported"
    status = response.status or 0
    if status == 429 or 500 <= status <= 599:
        return "transient"
    if status in {401, 403}:
        return "blocked"
    if status < 200 or status >= 300 or not response.body.strip():
        return "changed"
    if _blocked_body(response.media_type, response.body):
        return "blocked"
    if response.too_large:
        return "unsupported"
    return "ready"


def _validate_execution_settings(
    mode: str,
    *,
    max_attempts: int,
    retry_backoff_ms: int,
    timeout: float,
    request_budget_seconds: float = DEFAULT_REQUEST_BUDGET_SECONDS,
    attestation_budget_seconds: float = DEFAULT_ATTESTATION_BUDGET_SECONDS,
    observation_id: str | None = None,
) -> str | None:
    if (
        not isinstance(max_attempts, int)
        or isinstance(max_attempts, bool)
        or not 1 <= max_attempts <= MAX_RETRY_ATTEMPTS
    ):
        raise ValueError(
            f"maxAttempts must be an integer 1-{MAX_RETRY_ATTEMPTS}"
        )
    if (
        not isinstance(retry_backoff_ms, int)
        or isinstance(retry_backoff_ms, bool)
        or not 1 <= retry_backoff_ms <= MAX_RETRY_BACKOFF_MS
    ):
        raise ValueError(
            "backoffMs must be an integer "
            f"1-{MAX_RETRY_BACKOFF_MS}"
        )
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > 60
    ):
        raise ValueError("timeoutSeconds must be finite, >0, and <=60")
    if (
        isinstance(request_budget_seconds, bool)
        or not isinstance(request_budget_seconds, (int, float))
        or not math.isfinite(request_budget_seconds)
        or request_budget_seconds <= 0
        or request_budget_seconds > MAX_REQUEST_BUDGET_SECONDS
    ):
        raise ValueError(
            "requestBudgetSeconds must be finite, >0, and <=60"
        )
    if (
        isinstance(attestation_budget_seconds, bool)
        or not isinstance(attestation_budget_seconds, (int, float))
        or not math.isfinite(attestation_budget_seconds)
        or attestation_budget_seconds <= 0
        or attestation_budget_seconds > MAX_ATTESTATION_BUDGET_SECONDS
        or attestation_budget_seconds < request_budget_seconds
    ):
        raise ValueError(
            "attestationBudgetSeconds must be finite, >= request budget, "
            "and <=120"
        )
    if mode == "offline" and max_attempts != 1:
        raise ValueError("offline mode requires maxAttempts=1")
    resolved = observation_id or ("offline" if mode == "offline" else None)
    if resolved is not None and (
        not isinstance(resolved, str)
        or not OBSERVATION_ID_PATTERN.fullmatch(resolved)
    ):
        raise ValueError(
            "observationId must match [A-Za-z0-9._:-]{1,128}"
        )
    return resolved


def _live_response(
    attestation: dict[str, Any],
    timeout: float,
    *,
    urlopen: Callable[..., Any] = urllib_request.urlopen,
) -> SourceResponse:
    request_spec = attestation["request"]
    url = _request_url(attestation)
    data = None
    headers = _live_request_headers(url)
    if request_spec["method"] == "POST":
        data = json.dumps(
            request_spec["jsonBody"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib_request.Request(
        url,
        data=data,
        method=request_spec["method"],
        headers=headers,
    )
    try:
        with urlopen(
            request, timeout=timeout, context=_ssl_context()
        ) as response:
            body = response.read(MAX_BODY_BYTES + 1)
            media_type = response.headers.get(
                "Content-Type", "application/octet-stream"
            )
            return SourceResponse(
                getattr(response, "status", None) or response.getcode(),
                response.geturl(),
                media_type,
                body[:MAX_BODY_BYTES],
                too_large=len(body) > MAX_BODY_BYTES,
            )
    except urllib_error.HTTPError as exc:
        try:
            body = exc.read(MAX_BODY_BYTES + 1)
        except Exception:
            body = b""
        headers = getattr(exc, "headers", None)
        media_type = (
            headers.get("Content-Type", "application/octet-stream")
            if headers is not None
            else "application/octet-stream"
        )
        return SourceResponse(
            exc.code,
            exc.geturl() or url,
            media_type,
            body[:MAX_BODY_BYTES],
            too_large=len(body) > MAX_BODY_BYTES,
        )
    except Exception as exc:
        return SourceResponse(
            None,
            url,
            "application/octet-stream",
            b"",
            error=_transport_error_message(exc),
        )


def _offline_execution(
    root: Path, attestation: dict[str, Any]
) -> RequestExecution:
    response = _offline_response(root, attestation)
    status = _classify_request_response(attestation, response)
    return RequestExecution(
        _public_request_key(attestation),
        _request_url(attestation),
        attestation["request"]["method"],
        (AttemptAudit(1, status, "offline"),),
        status,
        "offline",
        response,
    )


def _live_execution(
    attestation: dict[str, Any],
    *,
    max_attempts: int,
    retry_backoff_ms: int,
    timeout: float,
    urlopen: Callable[..., Any],
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
    request_budget_seconds: float = DEFAULT_REQUEST_BUDGET_SECONDS,
) -> RequestExecution:
    attempts: list[AttemptAudit] = []
    response: SourceResponse | None = None
    final_status = "transient"
    total_latency = 0.0
    budget_exhausted = False
    for number in range(1, max_attempts + 1):
        remaining = request_budget_seconds - total_latency
        if remaining <= 0:
            budget_exhausted = True
            break
        started = clock()
        response = _live_response(
            attestation, min(timeout, remaining), urlopen=urlopen
        )
        elapsed = max(0.0, clock() - started)
        total_latency += elapsed
        if total_latency > request_budget_seconds + 0.001:
            budget_exhausted = True
            transport_error = (
                f"{response.error}; " if response.error is not None else ""
            )
            response = SourceResponse(
                None,
                _request_url(attestation),
                "application/octet-stream",
                b"",
                error=transport_error + "request time budget exhausted",
            )
            final_status = "transient"
        else:
            final_status = _classify_request_response(attestation, response)
        attempts.append(
            AttemptAudit(number, final_status, _latency_bucket(elapsed))
        )
        if final_status != "transient" or number == max_attempts:
            break
        delay_seconds = retry_backoff_ms * (2 ** (number - 1)) / 1_000
        if total_latency + delay_seconds >= request_budget_seconds:
            budget_exhausted = True
            break
        sleeper(delay_seconds)
        total_latency += delay_seconds
    if response is None:
        raise AssertionError("live execution produced no response")
    return RequestExecution(
        _public_request_key(attestation),
        _request_url(attestation),
        attestation["request"]["method"],
        tuple(attempts),
        final_status,
        _latency_bucket(total_latency),
        response,
        request_budget_seconds,
        budget_exhausted,
        total_latency,
    )


def _attach_request_execution(
    result: AttestationResult, execution: RequestExecution
) -> AttestationResult:
    return replace(
        result,
        requestKey=execution.requestKey,
        attemptCount=execution.attemptCount,
        requestFinalStatus=execution.finalStatus,
        latencyBucket=execution.latencyBucket,
    )


def _candidate_chain_item(
    candidate_id: str,
    execution: RequestExecution,
    outcome: str,
    reason: Any,
) -> dict[str, Any]:
    return {
        "candidateId": candidate_id,
        "requestKey": execution.requestKey,
        "requestUrl": execution.requestUrl,
        "method": execution.method,
        "outcome": outcome,
        "reason": reason,
        "attemptCount": execution.attemptCount,
        "budgetSeconds": execution.budgetSeconds,
        "budgetExhausted": execution.budgetExhausted,
        "latencyBucket": execution.latencyBucket,
        "attempts": [asdict(attempt) for attempt in execution.attempts],
    }


def _with_candidate_chain(
    result: AttestationResult,
    *,
    selected: str | None,
    policy: str,
    chain: list[dict[str, Any]],
) -> AttestationResult:
    return replace(
        result,
        selectedCandidate=selected,
        candidatePolicy=policy,
        candidateChain=tuple(chain),
    )


def verify_source_attestations(
    root: Path | str,
    *,
    attestations_path: Path | str,
    boundary_manifest_path: Path | str | None = None,
    claims_path: Path | str = "data/claims.json",
    mode: str = "offline",
    today: date | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    retry_backoff_ms: int = DEFAULT_RETRY_BACKOFF_MS,
    request_budget_seconds: float = DEFAULT_REQUEST_BUDGET_SECONDS,
    attestation_budget_seconds: float = DEFAULT_ATTESTATION_BUDGET_SECONDS,
    observation_id: str | None = None,
    urlopen: Callable[..., Any] = urllib_request.urlopen,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> AttestationReport:
    if mode not in {"offline", "live"}:
        raise ValueError("mode must be offline or live")
    resolved_observation_id = _validate_execution_settings(
        mode,
        max_attempts=max_attempts,
        retry_backoff_ms=retry_backoff_ms,
        timeout=timeout,
        request_budget_seconds=request_budget_seconds,
        attestation_budget_seconds=attestation_budget_seconds,
        observation_id=observation_id,
    )
    root_path = Path(root).resolve()
    generated_at = datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    report = AttestationReport(
        mode,
        generated_at,
        resolved_observation_id,
        {
            "maxAttempts": max_attempts,
            "backoffMs": retry_backoff_ms,
            "timeoutSeconds": timeout,
            "requestBudgetSeconds": request_budget_seconds,
            "attestationBudgetSeconds": attestation_budget_seconds,
        },
    )
    today_value = today or datetime.now(timezone.utc).date()
    try:
        registry_file = Path(attestations_path)
        if not registry_file.is_absolute():
            registry_file = _safe_path(root_path, str(registry_file))
        registry = _load_json(registry_file)
        if boundary_manifest_path is not None:
            manifest_name = boundary_manifest_path
        elif isinstance(registry, dict):
            manifest_name = registry.get("boundaryManifest")
        else:
            raise RegistryError("attestation registry root must be an object")
        manifest_file = Path(manifest_name)
        if not manifest_file.is_absolute():
            manifest_file = _safe_path(root_path, str(manifest_file))
        boundary_data = _load_json(manifest_file)
        claims_file = Path(claims_path)
        if not claims_file.is_absolute():
            claims_file = _safe_path(root_path, str(claims_file))
        claims_data = _load_json(claims_file)
    except (RegistryError, TypeError) as exc:
        report.results.append(
            _result(
                "<registry>",
                "<none>",
                "/",
                "unsupported",
                str(exc),
                "readable strict registry and boundary manifest",
                "Repair the registry paths and JSON.",
            )
        )
        return report

    try:
        valid = _validate_registry(
            root_path,
            registry,
            boundary_data,
            claims_data,
            today_value,
            report,
        )
    except RegistryError as exc:
        report.results.append(
            _result(
                "<registry>",
                "<none>",
                "/schema",
                "unsupported",
                str(exc),
                "valid strict attestation registry",
                "Repair the registry before running source extraction.",
                context=registry,
            )
        )
        return report

    cache: dict[str, RequestExecution] = {}
    for attestation in valid:
        reserved_attestation_budget = 0.0
        policy = _live_policy(attestation)
        manual_review = _manual_review_status(attestation, today_value)
        candidate_policy = _candidate_policy(attestation)
        candidate_contexts = _candidate_contexts(attestation)
        emit_candidate_telemetry = "requestCandidates" in attestation
        if mode == "live" and policy["mode"] == "fixture-only":
            primary_id, primary_context, _media = candidate_contexts[0]
            report.results.append(
                replace(
                    _result(
                        attestation["id"],
                        attestation["sourceUrl"],
                        "/livePolicy",
                        "unsupported",
                        {
                            "mode": "fixture-only",
                            "reason": policy["reason"],
                            "manualReviewDays": policy[
                                "manualReviewDays"
                            ],
                            "verifiedAt": manual_review["verifiedAt"],
                            "dueDate": manual_review["dueDate"],
                            "daysOverdue": manual_review["daysOverdue"],
                            "evidenceFingerprint": manual_review[
                                "evidenceFingerprint"
                            ],
                        },
                        "reviewed live extraction",
                        (
                            "Perform manual official-source review within "
                            f"{policy['manualReviewDays']} day(s); retain "
                            "fixture-only until a bounded extractor can verify "
                            "the live representation."
                        ),
                        context=policy,
                        request_url=_request_url(primary_context),
                    ),
                    requestKey=_public_request_key(primary_context),
                    attemptCount=0,
                    requestFinalStatus="unsupported",
                    latencyBucket="offline",
                    selectedCandidate=None,
                    candidatePolicy=candidate_policy,
                    candidateChain=((
                        {
                            "candidateId": primary_id,
                            "requestKey": _public_request_key(primary_context),
                            "requestUrl": _request_url(primary_context),
                            "method": primary_context["request"]["method"],
                            "outcome": "unsupported",
                            "reason": policy["reason"],
                            "attemptCount": 0,
                            "latencyBucket": "offline",
                            "attempts": [],
                        },
                    ) if emit_candidate_telemetry else ()),
                    manualReview=manual_review,
                )
            )
            continue
        chain: list[dict[str, Any]] = []
        selected: str | None = None
        final_result: AttestationResult | None = None
        first_result: AttestationResult | None = None
        first_match_result: AttestationResult | None = None
        for candidate_id, candidate, _media in candidate_contexts:
            request_key = _request_key(candidate)
            if request_key not in cache:
                if (
                    mode == "live"
                    and reserved_attestation_budget
                    + request_budget_seconds
                    > attestation_budget_seconds
                ):
                    budget_actual = {
                        "reason": "attestation time budget exhausted",
                        "requestBudgetSeconds": request_budget_seconds,
                        "attestationBudgetSeconds": attestation_budget_seconds,
                        "reservedSeconds": reserved_attestation_budget,
                    }
                    candidate_result = replace(
                        _result(
                            attestation["id"],
                            attestation["sourceUrl"],
                            "/requestCandidates/budget",
                            "transient",
                            budget_actual,
                            "a candidate evaluated within the reviewed budget",
                            "Reduce retry/candidate cost or explicitly review a larger bounded budget.",
                            context=budget_actual,
                            request_url=_request_url(candidate),
                        ),
                        requestKey=_public_request_key(candidate),
                        attemptCount=0,
                        requestFinalStatus="transient",
                        latencyBucket="offline",
                    )
                    if first_result is None:
                        first_result = candidate_result
                    chain.append({
                        "candidateId": candidate_id,
                        "requestKey": _public_request_key(candidate),
                        "requestUrl": _request_url(candidate),
                        "method": candidate["request"]["method"],
                        "outcome": "transient",
                        "reason": budget_actual,
                        "attemptCount": 0,
                        "budgetSeconds": request_budget_seconds,
                        "budgetExhausted": True,
                        "latencyBucket": "offline",
                        "attempts": [],
                    })
                    final_result = candidate_result
                    continue
                if mode == "offline":
                    cache[request_key] = _offline_execution(
                        root_path, candidate
                    )
                else:
                    reserved_attestation_budget += request_budget_seconds
                    cache[request_key] = _live_execution(
                        candidate,
                        max_attempts=max_attempts,
                        retry_backoff_ms=retry_backoff_ms,
                        timeout=timeout,
                        request_budget_seconds=request_budget_seconds,
                        urlopen=urlopen,
                        clock=clock,
                        sleeper=sleeper,
                    )
            execution = cache[request_key]
            candidate_result = _attach_request_execution(
                _evaluate_response(
                    candidate,
                    execution.response,
                    offline=mode == "offline",
                    root=root_path,
                ),
                execution,
            )
            if first_result is None:
                first_result = candidate_result
            chain.append(
                _candidate_chain_item(
                    candidate_id,
                    execution,
                    candidate_result.status,
                    candidate_result.actual,
                )
            )
            final_result = candidate_result
            if candidate_result.status == "changed":
                final_result = candidate_result
                break
            if candidate_policy == "first-match":
                if candidate_result.status == "match":
                    selected = candidate_id
                    break
                continue
            if candidate_result.status == "match" and selected is None:
                selected = candidate_id
                first_match_result = candidate_result
        if final_result is None:
            raise AssertionError("candidate chain produced no result")
        if candidate_policy == "available-parity" and final_result.status != "changed":
            if first_match_result is not None:
                final_result = first_match_result
            elif first_result is not None:
                final_result = first_result
        if (
            candidate_policy == "available-parity"
            and len(chain) == len(candidate_contexts)
            and all(item["outcome"] == "match" for item in chain)
        ):
            final_result = replace(
                final_result,
                fix="All reviewed candidate representations match.",
            )
        elif final_result.status == "match" and selected is None:
            selected = chain[-1]["candidateId"]
        final_result = _with_candidate_chain(
            final_result,
            selected=selected if emit_candidate_telemetry else None,
            policy=candidate_policy,
            chain=chain if emit_candidate_telemetry else [],
        )
        if manual_review is not None:
            final_result = replace(
                final_result, manualReview=manual_review
            )
            if (
                mode == "offline"
                and final_result.status == "match"
                and manual_review["daysOverdue"] > 0
            ):
                final_result = replace(
                    final_result,
                    status="unsupported",
                    actual=manual_review,
                    expected={
                        "manualReviewDueOnOrAfter": today_value.isoformat()
                    },
                    fix=(
                        "Re-review the official evidence, update verifiedAt "
                        "and the raw fixture SHA, then rerun offline verification."
                    ),
                )
        report.results.append(final_result)
    report.fetchedUrls = len(cache)
    report.requests = sorted(
        cache.values(), key=lambda item: item.requestKey
    )
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify boundary reviewed constants against official source attestations."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    parser.add_argument(
        "--attestations",
        default="data/source-attestations.json",
        help="attestation registry path",
    )
    parser.add_argument(
        "--boundary-manifest",
        default=None,
        help="override boundary manifest path",
    )
    parser.add_argument(
        "--claims",
        default="data/claims.json",
        help="claim registry path",
    )
    parser.add_argument(
        "--mode",
        choices=("offline", "live"),
        default="offline",
    )
    parser.add_argument("--today", default=None, help="ISO date override")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help=f"total attempts per transient request (1-{MAX_RETRY_ATTEMPTS})",
    )
    parser.add_argument(
        "--retry-backoff-ms",
        type=int,
        default=DEFAULT_RETRY_BACKOFF_MS,
        help=(
            "base deterministic exponential retry delay in milliseconds "
            f"(1-{MAX_RETRY_BACKOFF_MS})"
        ),
    )
    parser.add_argument(
        "--request-budget-seconds",
        type=float,
        default=DEFAULT_REQUEST_BUDGET_SECONDS,
        help="total retry+backoff budget per canonical request (0,60]",
    )
    parser.add_argument(
        "--attestation-budget-seconds",
        type=float,
        default=DEFAULT_ATTESTATION_BUDGET_SECONDS,
        help="reserved fresh-request budget per attestation (0,120]",
    )
    parser.add_argument(
        "--observation-id",
        default=None,
        help="stable workflow observation id for trend replay protection",
    )
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="emit non-match results without a nonzero exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        today = _parse_date(args.today, "--today") if args.today else None
    except RegistryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        _validate_execution_settings(
            args.mode,
            max_attempts=args.max_attempts,
            retry_backoff_ms=args.retry_backoff_ms,
            timeout=args.timeout,
            request_budget_seconds=args.request_budget_seconds,
            attestation_budget_seconds=args.attestation_budget_seconds,
            observation_id=args.observation_id,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    report = verify_source_attestations(
        args.root,
        attestations_path=args.attestations,
        boundary_manifest_path=args.boundary_manifest,
        claims_path=args.claims,
        mode=args.mode,
        today=today,
        timeout=args.timeout,
        max_attempts=args.max_attempts,
        retry_backoff_ms=args.retry_backoff_ms,
        request_budget_seconds=args.request_budget_seconds,
        attestation_budget_seconds=args.attestation_budget_seconds,
        observation_id=args.observation_id,
    )
    payload = report.to_json()
    if args.output is not None:
        args.output.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    non_matches = [
        result for result in report.results if result.status != "match"
    ]
    if non_matches:
        print(
            f"Source attestation verification found "
            f"{len(non_matches)} non-match result(s):",
            file=sys.stderr,
        )
        for result in non_matches:
            print(result.render(), file=sys.stderr)
    summary = payload["summary"]
    print(
        "Source attestation verification "
        f"{'passed' if not non_matches else 'completed'}: "
        f"{len(report.results)} attestation result(s), "
        f"{report.fetchedUrls} URL fetch(es), "
        f"{payload['requestAudit']['totalAttemptCount']} total attempt(s), "
        f"audit={json.dumps(report.audit, sort_keys=True, separators=(',', ':'))}, "
        + ", ".join(
            f"{status}={summary[status]}"
            for status in (
                "match",
                "changed",
                "blocked",
                "transient",
                "unsupported",
            )
        )
        + "."
    )
    if non_matches and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
