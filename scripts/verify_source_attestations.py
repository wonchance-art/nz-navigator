#!/usr/bin/env python3
"""Verify reviewed boundary constants against fingerprinted official sources."""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import json
import math
import re
import ssl
import sys
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


SCHEMA_VERSION = 1
MAX_BODY_BYTES = 2_000_000
DEFAULT_TIMEOUT = 12.0
MAX_ATTESTATIONS = 256
MAX_TARGETS_PER_ATTESTATION = 16
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
        "pdf-table",
        "json-pointer",
        "api-json-pointer",
        "api-json-record",
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
OPTIONAL_ROOT_FIELDS = frozenset({"claimScope"})
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
    {"effectiveTo", "targets", "claims"}
)
TARGET_FIELDS = frozenset({"targetId", "reviewedPath"})
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
REQUEST_POST_FIELDS = frozenset({"method", "url", "jsonBody"})
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
        "final-inclusive-range",
    }
)
HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})
PDF_MEDIA_TYPES = frozenset({"application/pdf"})
JSON_MEDIA_TYPES = frozenset(
    {"application/json", "application/problem+json"}
)
class RegistryError(ValueError):
    pass


class ChangedExtraction(ValueError):
    pass


class UnsupportedExtraction(ValueError):
    pass


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
    results: list[AttestationResult] = field(default_factory=list)
    fetchedUrls: int = 0
    audit: dict[str, int] = field(
        default_factory=lambda: {
            "attestationCount": 0,
            "claimCount": 0,
            "reviewedLeafCount": 0,
            "liveCapableCount": 0,
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
        return {
            "schemaVersion": SCHEMA_VERSION,
            "mode": self.mode,
            "generatedAt": self.generatedAt,
            "summary": summary,
            "fetchedUrls": self.fetchedUrls,
            "audit": self.audit,
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
    value: Any, source_url: str, jurisdiction: str
) -> None:
    if not isinstance(value, dict) or value.get("method") not in {
        "GET",
        "POST",
    }:
        raise RegistryError("request.method must be GET or POST")
    if value["method"] == "GET":
        if set(value) != REQUEST_GET_FIELDS:
            raise RegistryError("GET request may contain only method")
        return
    if set(value) != REQUEST_POST_FIELDS:
        raise RegistryError(
            "POST request requires exactly method, url, and jsonBody"
        )
    request_url = value["url"]
    if not isinstance(request_url, str) or len(request_url) > 2048:
        raise RegistryError("POST request.url must be at most 2048 characters")
    _validate_official_url(request_url, jurisdiction)
    source_host = urllib_parse.urlsplit(source_url).hostname
    request_host = urllib_parse.urlsplit(request_url).hostname
    if (
        source_host is None
        or request_host is None
        or source_host.encode("idna").decode("ascii").lower().rstrip(".")
        != request_host.encode("idna").decode("ascii").lower().rstrip(".")
    ):
        raise RegistryError(
            "POST request.url host must exactly match citation sourceUrl host"
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
            _validate_text(field_spec["unit"], "field.unit")
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


def _request_url(attestation: dict[str, Any]) -> str:
    request = attestation["request"]
    return (
        request["url"]
        if request["method"] == "POST"
        else attestation["sourceUrl"]
    )


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
            fixture_key = (
                raw["fixture"]["path"],
                raw["fixture"]["mediaType"],
                raw["fixture"]["sha256"],
                raw["fixture"]["httpStatus"],
                raw["fixture"]["finalUrl"],
            )
            request_key = _request_key(raw)
            previous_fixture = source_fixtures.setdefault(
                request_key, fixture_key
            )
            if previous_fixture != fixture_key:
                raise RegistryError(
                    "one source request must use one deterministic fixture response"
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
                if not _exact_fields(mapping, TARGET_FIELDS):
                    raise RegistryError(
                        "target mapping must contain targetId and reviewedPath"
                    )
                target_id = mapping["targetId"]
                reviewed_path = mapping["reviewedPath"]
                if target_id not in targets:
                    raise RegistryError(f"unknown boundary target {target_id!r}")
                _pointer_parts(reviewed_path)
                resolved = _resolve_pointer(
                    targets[target_id]["reviewed"], reviewed_path
                )
                pair = (target_id, reviewed_path)
                if pair in seen_local_targets:
                    raise RegistryError("duplicate target mapping in attestation")
                seen_local_targets.add(pair)
                if resolved != expected["value"]:
                    raise RegistryError(
                        f"{target_id}{reviewed_path} differs from expected.value"
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
    }
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
        self.definitions: list[tuple[str, str, str]] = []
        self.block_texts: list[str] = []
        self.labelled_values: list[tuple[str, str, str]] = []
        self._recent_anchors: list[str] = []
        self._table: dict[str, Any] | None = None
        self._row: list[str] | None = None
        self._cell_parts: list[str] | None = None
        self._caption_parts: list[str] | None = None
        self._heading_parts: list[str] | None = None
        self._heading_level = 0
        self._current_heading = ""
        self._outer_heading = ""
        self._pending_label: tuple[str, str] | None = None
        self._block_stack: list[dict[str, Any]] = []
        self._dt_parts: list[str] | None = None
        self._dd_parts: list[str] | None = None
        self._pending_dt: str | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        lowered = tag.lower()
        if lowered == "table":
            self._table = {
                "caption": "",
                "rows": [],
                "anchors": list(self._recent_anchors),
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

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
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
                self._remember_anchor(block)
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

    def handle_data(self, data: str) -> None:
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
    if transform in {"duration-months", "duration-weeks"}:
        word = "months?" if transform == "duration-months" else "weeks?"
        match = _single_numeric_match(
            normalized,
            rf"(?<![A-Za-z0-9])([0-9][0-9,]*(?:\.[0-9]+)?)\s+{word}\b",
            transform,
        )
        return _finite_number(match.group(1))
    if transform == "inclusive-range":
        matches = list(
            re.finditer(
                r"(?<![A-Za-z0-9])([0-9][0-9,]*(?:\.[0-9]+)?)"
                r"\s*(?:[\-\u2013\u2014]|\bto\b)\s*"
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
    data_rows = table["rows"][header_index + 1 :]
    if not data_rows:
        raise ChangedExtraction("matched table has no data rows")
    header_positions = {label: index for index, label in enumerate(headers)}
    extracted: dict[str, Any] = {}
    units: dict[str, str] = {}
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
        text for text in parser.block_texts + parser.headings
        if text == params["anchor"]
    ]
    if len(matches) != 1:
        raise ChangedExtraction(
            f"text anchor {params['anchor']!r} matched {len(matches)} blocks"
        )
    return params["unit"], _transform_html_value(
        matches[0], params["transform"]
    )


def _pdf_literal_lines(body: bytes) -> list[str]:
    if not body.startswith(b"%PDF-"):
        raise UnsupportedExtraction("body is not a PDF")
    for marker in (b"/Encrypt", b"/FlateDecode", b"/ObjStm"):
        if marker in body:
            raise UnsupportedExtraction(
                f"PDF feature {marker.decode('ascii')} is not safely supported"
            )
    text = body.decode("latin-1")
    lines: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "(":
            index += 1
            continue
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
                chars.append(char)
            elif char == ")":
                depth -= 1
                if depth:
                    chars.append(char)
            else:
                chars.append(char)
        if depth:
            raise ChangedExtraction("unterminated PDF literal string")
        probe = index
        while probe < len(text) and text[probe].isspace():
            probe += 1
        if text.startswith("Tj", probe):
            lines.append(_normalize_text("".join(chars)))
        index = probe
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
    str, Callable[[bytes, dict[str, Any]], tuple[str, Any]]
] = {
    "html-table": _extract_html_table,
    "html-definition": _extract_html_definition,
    "html-table-record": _extract_html_table_record,
    "html-labelled-values": _extract_html_labelled_values,
    "html-text-anchor": _extract_html_text_anchor,
    "pdf-table": _extract_pdf_table,
    "json-pointer": _extract_json_record,
    "api-json-pointer": _extract_json_record,
    "api-json-record": _extract_api_json_record,
}


def _expected_media(mode: str, media_type: str) -> bool:
    normalized = _media_type(media_type)
    if mode.startswith("html-"):
        return normalized in HTML_MEDIA_TYPES
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


def _live_response(
    attestation: dict[str, Any],
    timeout: float,
    *,
    urlopen: Callable[..., Any] = urllib_request.urlopen,
) -> SourceResponse:
    request_spec = attestation["request"]
    url = _request_url(attestation)
    data = None
    headers = {
        "User-Agent": "nz-navigator-source-attestation/1.0",
        "Accept": (
            "text/html,application/xhtml+xml,application/pdf,"
            "application/json;q=0.9,*/*;q=0.1"
        ),
        "Connection": "close",
    }
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
            error=f"{type(exc).__name__}: {exc}",
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
    urlopen: Callable[..., Any] = urllib_request.urlopen,
) -> AttestationReport:
    if mode not in {"offline", "live"}:
        raise ValueError("mode must be offline or live")
    root_path = Path(root).resolve()
    generated_at = datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    report = AttestationReport(mode, generated_at)
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

    cache: dict[str, SourceResponse] = {}
    for attestation in valid:
        request_key = _request_key(attestation)
        if request_key not in cache:
            if mode == "offline":
                cache[request_key] = _offline_response(root_path, attestation)
            else:
                cache[request_key] = _live_response(
                    attestation, timeout, urlopen=urlopen
                )
        report.results.append(
            _evaluate_response(
                attestation,
                cache[request_key],
                offline=mode == "offline",
                root=root_path,
            )
        )
    report.fetchedUrls = len(cache)
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
    if args.timeout <= 0 or args.timeout > 60:
        print("ERROR: --timeout must be >0 and <=60 seconds", file=sys.stderr)
        return 2
    report = verify_source_attestations(
        args.root,
        attestations_path=args.attestations,
        boundary_manifest_path=args.boundary_manifest,
        claims_path=args.claims,
        mode=args.mode,
        today=today,
        timeout=args.timeout,
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
