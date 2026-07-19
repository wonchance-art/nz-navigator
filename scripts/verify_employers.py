#!/usr/bin/env python3
"""Fail-closed verifier for the NZ Navigator employer directory."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
import json
import math
from pathlib import Path
import re
import socket
import ssl
import sys
import unicodedata
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


ROOT_FIELDS = frozenset({"schemaVersion", "generatedAt", "audit", "employers"})
AUDIT_FIELDS = frozenset({
    "employerCount",
    "countryCounts",
    "statusCounts",
    "contactableCount",
    "expiredCount",
    "nearDuplicateCandidateCount",
    "linkUrlCount",
})
ENTRY_FIELDS = frozenset({
    "id",
    "country",
    "name",
    "location",
    "workTypes",
    "source",
    "contact",
    "status",
    "nextReviewAt",
    "vacancyStatus",
    "eligibility",
})
LOCATION_REQUIRED_FIELDS = frozenset({
    "label", "region", "lat", "lng", "precision"
})
LOCATION_OPTIONAL_FIELDS = frozenset({"address", "state", "postcode"})
SOURCE_REQUIRED_FIELDS = frozenset({"kind", "url", "checkedAt"})
SOURCE_OPTIONAL_FIELDS = frozenset({"effectiveTo"})
CONTACT_REQUIRED_FIELDS = frozenset({"kind"})
CONTACT_OPTIONAL_FIELDS = frozenset({"url"})
ELIGIBILITY_FIELDS = frozenset({
    "scheme",
    "classification",
    "requiresRoleCheck",
    "requiresLocationCheck",
})

COUNTRIES = frozenset({"NZ", "AU"})
PRECISIONS = frozenset({"exact", "postcode", "town", "region"})
SOURCE_KINDS = frozenset({
    "government-register",
    "government-job-gateway",
    "industry-association",
    "employer-official",
    "verified-local-producer",
    "unverified",
})
CONTACT_KINDS = frozenset({"recruitment", "company", "email", "none"})
STATUSES = frozenset({"active", "uncertain", "expired"})
VACANCY_STATUSES = frozenset({"directory-only"})
SCHEMES = frozenset({"nz-whv-extension", "au-417-specified-work", "none"})
CLASSIFICATIONS = frozenset({"conditional", "not-applicable"})
WORK_TYPES = frozenset({
    "construction",
    "farm-packing",
    "farm-processing",
    "food-processing",
    "grain-processing",
    "horticulture",
    "job-gateway",
    "labour-contracting",
    "livestock-processing",
    "meat-processing",
    "mining",
    "nursery",
    "orchard-contracting",
    "packhouse",
    "packhouse-orchard",
    "packhouse-processing",
    "quality-lab",
    "viticulture-contracting",
    "viticulture-winery",
    "winery-processing",
})
AU_STATES = frozenset({"ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"})
AU_POSTCODE_RANGES = {
    "ACT": ((200, 299), (2600, 2618), (2900, 2920)),
    "NSW": ((1000, 2599), (2619, 2899), (2921, 2999)),
    "NT": ((800, 899), (900, 999)),
    "QLD": ((4000, 4999), (9000, 9999)),
    "SA": ((5000, 5799), (5800, 5999)),
    "TAS": ((7000, 7799), (7800, 7999)),
    "VIC": ((3000, 3999), (8000, 8999)),
    "WA": ((6000, 6797), (6800, 6999)),
}
BOUNDING_BOXES = {
    "NZ": (-47.5, -33.0, 165.0, 179.5),
    "AU": (-44.5, -10.0, 112.0, 154.5),
}
INDUSTRY_HOSTS = frozenset({
    "nzkgi.org.nz",
    "freshproduce.org.au",
    "ntfarmers.org.au",
})
PUBLIC_SUFFIXES = (
    "govt.nz", "co.nz", "org.nz", "gov.au", "com.au", "org.au", "net.au"
)
ID_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
VACANCY_PATTERN = re.compile(
    r"\b(?:currently hiring|hiring now|vacanc(?:y|ies)(?: available| open)?|"
    r"jobs? available|apply now|open positions?)\b",
    flags=re.IGNORECASE,
)
MAX_TEXT = 500
MAX_BODY_BYTES = 512 * 1024
USER_AGENT = "NZ-Navigator-Employer-Link-Verifier/1.0"


@dataclass(frozen=True)
class Problem:
    employer_id: str
    field: str
    actual: Any
    expected: Any
    fix: str

    def render(self) -> str:
        return (
            f"ERROR id={self.employer_id} field={self.field} "
            f"actual={_json(self.actual)} expected={_json(self.expected)}\n"
            f"  Fix: {self.fix}"
        )


@dataclass
class Verification:
    problems: list[Problem]
    employers: list[dict[str, Any]]
    audit: dict[str, Any]
    duplicate_candidates: list[dict[str, Any]]

    @property
    def ok(self) -> bool:
        return not self.problems


def _json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _problem(
    problems: list[Problem],
    employer_id: str,
    field: str,
    actual: Any,
    expected: Any,
    fix: str,
) -> None:
    problems.append(Problem(employer_id, field, actual, expected, fix))


def _iso_date(
    value: Any,
    employer_id: str,
    field: str,
    problems: list[Problem],
) -> date | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        _problem(
            problems, employer_id, field, value, "real ISO date YYYY-MM-DD",
            "Use a real calendar date in YYYY-MM-DD form.",
        )
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        _problem(
            problems, employer_id, field, value, "real ISO date YYYY-MM-DD",
            "Correct the impossible calendar date.",
        )
        return None
    if parsed.isoformat() != value:
        _problem(
            problems, employer_id, field, value, parsed.isoformat(),
            "Use the canonical zero-padded ISO date.",
        )
        return None
    return parsed


def _safe_text(
    value: Any,
    employer_id: str,
    field: str,
    problems: list[Problem],
    *,
    max_length: int = MAX_TEXT,
) -> str | None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > max_length
        or any(ord(char) < 32 for char in value)
    ):
        _problem(
            problems, employer_id, field, value,
            f"trimmed non-empty text up to {max_length} characters",
            "Provide bounded, normalized display text without control characters.",
        )
        return None
    return value


def _https_url(
    value: Any,
    employer_id: str,
    field: str,
    problems: list[Problem],
) -> urllib_parse.SplitResult | None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        _problem(
            problems, employer_id, field, value, "bounded HTTPS URL",
            "Provide the reviewed HTTPS evidence URL.",
        )
        return None
    parsed = urllib_parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.hostname != parsed.hostname.lower()
    ):
        _problem(
            problems, employer_id, field, value,
            "HTTPS URL without userinfo or fragment and with lowercase host",
            "Use the canonical public HTTPS URL; remove credentials/fragments.",
        )
        return None
    return parsed


def _mailto_url(
    value: Any,
    employer_id: str,
    field: str,
    problems: list[Problem],
) -> str | None:
    if not isinstance(value, str) or len(value) > 320:
        valid = False
    else:
        parsed = urllib_parse.urlsplit(value)
        address = parsed.path
        valid = (
            parsed.scheme == "mailto"
            and not parsed.netloc
            and not parsed.query
            and not parsed.fragment
            and re.fullmatch(
                r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
                r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",
                address,
            )
            is not None
            and ".." not in address
        )
    if not valid:
        _problem(
            problems, employer_id, field, value, "one exact mailto: address",
            "Use mailto:user@example.org without query, fragment, or display text.",
        )
        return None
    return value


def _host_matches(host: str, reviewed: str) -> bool:
    return host == reviewed or host.endswith("." + reviewed)


def _is_government_host(country: str, host: str) -> bool:
    suffix = "govt.nz" if country == "NZ" else "gov.au"
    return _host_matches(host, suffix)


def _is_industry_host(host: str) -> bool:
    return any(_host_matches(host, item) for item in INDUSTRY_HOSTS)


def _registrable_host(host: str) -> str:
    labels = host.split(".")
    for suffix in PUBLIC_SUFFIXES:
        suffix_labels = suffix.split(".")
        if host == suffix:
            return host
        if host.endswith("." + suffix) and len(labels) > len(suffix_labels):
            return ".".join(labels[-len(suffix_labels) - 1 :])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().replace("&", " and ")
    return " ".join(re.sub(r"[^\w]+", " ", normalized).split())


def _canonical_contact(contact: dict[str, Any]) -> str:
    if contact["kind"] == "none":
        return ""
    value = contact["url"]
    if value.startswith("mailto:"):
        return value.casefold()
    parsed = urllib_parse.urlsplit(value)
    return urllib_parse.urlunsplit((
        "https",
        parsed.hostname or "",
        parsed.path.rstrip("/") or "/",
        parsed.query,
        "",
    ))


def _location_key(location: dict[str, Any]) -> str:
    return "|".join(
        _normalize(str(location.get(key, "")))
        for key in ("label", "address", "region", "state", "postcode")
    )


def _distance_meters(first: dict[str, Any], second: dict[str, Any]) -> float:
    first_lat = math.radians(first["location"]["lat"])
    second_lat = math.radians(second["location"]["lat"])
    lat_delta = second_lat - first_lat
    lng_delta = math.radians(
        second["location"]["lng"] - first["location"]["lng"]
    )
    haversine = (
        math.sin(lat_delta / 2) ** 2
        + math.cos(first_lat)
        * math.cos(second_lat)
        * math.sin(lng_delta / 2) ** 2
    )
    return 2 * 6_371_000 * math.asin(math.sqrt(haversine))


def _validate_location(
    raw: Any,
    employer_id: str,
    country: str,
    problems: list[Problem],
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        _problem(
            problems, employer_id, "location", raw, "location object",
            "Provide the reviewed location object.",
        )
        return None
    keys = set(raw)
    allowed = LOCATION_REQUIRED_FIELDS | LOCATION_OPTIONAL_FIELDS
    if not LOCATION_REQUIRED_FIELDS <= keys or not keys <= allowed:
        _problem(
            problems, employer_id, "location.keys", sorted(keys),
            {
                "required": sorted(LOCATION_REQUIRED_FIELDS),
                "optional": sorted(LOCATION_OPTIONAL_FIELDS),
            },
            "Remove unknown keys and add every required location field.",
        )
        return None
    for field in ("label", "region"):
        _safe_text(raw[field], employer_id, f"location.{field}", problems)
    for field in ("address", "state", "postcode"):
        if field in raw:
            _safe_text(raw[field], employer_id, f"location.{field}", problems)
    precision = raw["precision"]
    if precision not in PRECISIONS:
        _problem(
            problems, employer_id, "location.precision", precision,
            sorted(PRECISIONS), "Use one reviewed coordinate precision enum.",
        )
    for field in ("lat", "lng"):
        value = raw[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            _problem(
                problems, employer_id, f"location.{field}", value,
                "finite number", "Provide a finite reviewed coordinate.",
            )
    if all(
        isinstance(raw[field], (int, float))
        and not isinstance(raw[field], bool)
        and math.isfinite(raw[field])
        for field in ("lat", "lng")
    ):
        min_lat, max_lat, min_lng, max_lng = BOUNDING_BOXES[country]
        if not (
            min_lat <= raw["lat"] <= max_lat
            and min_lng <= raw["lng"] <= max_lng
        ):
            _problem(
                problems, employer_id, "location.lat/lng",
                [raw["lat"], raw["lng"]],
                {
                    "country": country,
                    "lat": [min_lat, max_lat],
                    "lng": [min_lng, max_lng],
                },
                "Correct the coordinate or country; do not retain an out-of-country point.",
            )
    if precision == "exact" and "address" not in raw:
        _problem(
            problems, employer_id, "location.address", None,
            "required when precision=exact",
            "Add the reviewed street address or lower the declared precision.",
        )
    if precision == "postcode" and "postcode" not in raw:
        _problem(
            problems, employer_id, "location.postcode", None,
            "required when precision=postcode",
            "Add the reviewed postcode or lower the declared precision.",
        )
    postcode = raw.get("postcode")
    state = raw.get("state")
    if country == "NZ":
        if state is not None:
            _problem(
                problems, employer_id, "location.state", state, "absent for NZ",
                "Use region for New Zealand rows and remove state.",
            )
        if postcode is not None and re.fullmatch(r"\d{4}", postcode) is None:
            _problem(
                problems, employer_id, "location.postcode", postcode,
                "four ASCII digits", "Use the canonical four-digit NZ postcode.",
            )
    else:
        if state not in AU_STATES:
            _problem(
                problems, employer_id, "location.state", state,
                sorted(AU_STATES), "Add the reviewed AU state or territory.",
            )
        if not isinstance(postcode, str) or re.fullmatch(r"\d{4}", postcode) is None:
            _problem(
                problems, employer_id, "location.postcode", postcode,
                "four ASCII digits", "Use the zero-padded four-digit AU postcode.",
            )
        elif state in AU_POSTCODE_RANGES:
            numeric = int(postcode)
            if not any(
                lower <= numeric <= upper
                for lower, upper in AU_POSTCODE_RANGES[state]
            ):
                _problem(
                    problems, employer_id, "location.state/postcode",
                    {"state": state, "postcode": postcode},
                    {"state": state, "ranges": AU_POSTCODE_RANGES[state]},
                    "Correct the state or postcode using the reviewed postal boundaries.",
                )
    return raw


def _validate_contact(
    raw: Any,
    employer_id: str,
    problems: list[Problem],
) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or not CONTACT_REQUIRED_FIELDS <= set(raw) or not set(raw) <= (
        CONTACT_REQUIRED_FIELDS | CONTACT_OPTIONAL_FIELDS
    ):
        _problem(
            problems, employer_id, "contact.keys",
            sorted(raw) if isinstance(raw, dict) else raw,
            {"required": ["kind"], "optional": ["url"]},
            "Use the exact contact object contract.",
        )
        return None
    kind = raw["kind"]
    if kind not in CONTACT_KINDS:
        _problem(
            problems, employer_id, "contact.kind", kind, sorted(CONTACT_KINDS),
            "Use one reviewed contact-kind enum.",
        )
        return raw
    has_url = "url" in raw
    if kind == "none" and has_url:
        _problem(
            problems, employer_id, "contact.url", raw["url"],
            "absent when contact.kind=none",
            "Remove the URL or choose its truthful contact kind.",
        )
    elif kind != "none" and not has_url:
        _problem(
            problems, employer_id, "contact.url", None,
            f"required when contact.kind={kind}",
            "Add the reviewed contact URL.",
        )
    elif has_url and kind == "email":
        _mailto_url(raw["url"], employer_id, "contact.url", problems)
    elif has_url and kind in {"company", "recruitment"}:
        _https_url(raw["url"], employer_id, "contact.url", problems)
    return raw


def _validate_source(
    raw: Any,
    employer_id: str,
    country: str,
    contact: dict[str, Any] | None,
    problems: list[Problem],
) -> tuple[dict[str, Any] | None, date | None, date | None]:
    if not isinstance(raw, dict) or not SOURCE_REQUIRED_FIELDS <= set(raw) or not set(raw) <= (
        SOURCE_REQUIRED_FIELDS | SOURCE_OPTIONAL_FIELDS
    ):
        _problem(
            problems, employer_id, "source.keys",
            sorted(raw) if isinstance(raw, dict) else raw,
            {
                "required": sorted(SOURCE_REQUIRED_FIELDS),
                "optional": sorted(SOURCE_OPTIONAL_FIELDS),
            },
            "Provide one exact source object; source evidence is mandatory.",
        )
        return None, None, None
    kind = raw["kind"]
    if kind not in SOURCE_KINDS:
        _problem(
            problems, employer_id, "source.kind", kind, sorted(SOURCE_KINDS),
            "Use one reviewed source-kind enum without promoting the evidence.",
        )
    parsed = _https_url(raw["url"], employer_id, "source.url", problems)
    checked = _iso_date(raw["checkedAt"], employer_id, "source.checkedAt", problems)
    effective_to = (
        _iso_date(
            raw["effectiveTo"], employer_id, "source.effectiveTo", problems
        )
        if "effectiveTo" in raw
        else None
    )
    if parsed is not None and kind in SOURCE_KINDS:
        host = parsed.hostname or ""
        if kind in {"government-register", "government-job-gateway"}:
            if not _is_government_host(country, host):
                _problem(
                    problems, employer_id, "source.url", raw["url"],
                    f"{country} government host for {kind}",
                    "Downgrade source.kind or use the actual government evidence URL.",
                )
        elif kind == "industry-association":
            if not _is_industry_host(host):
                _problem(
                    problems, employer_id, "source.url", raw["url"],
                    sorted(INDUSTRY_HOSTS),
                    "Use a reviewed association host or downgrade source.kind.",
                )
        elif kind == "verified-local-producer":
            if not (_is_industry_host(host) or _is_government_host(country, host)):
                _problem(
                    problems, employer_id, "source.url", raw["url"],
                    "reviewed association or government host",
                    "Keep local-producer evidence third-party and reviewed.",
                )
        elif kind == "employer-official":
            if _is_industry_host(host) or _is_government_host(country, host):
                _problem(
                    problems, employer_id, "source.url", raw["url"],
                    "non-government, non-association employer host",
                    "Use the truthful third-party source kind instead of employer-official.",
                )
            if contact and contact.get("kind") in {"company", "email"}:
                contact_value = contact.get("url", "")
                contact_host = (
                    contact_value.rsplit("@", 1)[-1]
                    if contact["kind"] == "email"
                    else (urllib_parse.urlsplit(contact_value).hostname or "")
                )
                if (
                    contact_host
                    and _registrable_host(host)
                    != _registrable_host(contact_host.lower())
                ):
                    _problem(
                        problems, employer_id, "source.url/contact.url",
                        {"source": host, "contact": contact_host},
                        "same registrable employer host",
                        "Correct the contact/source relation or use recruitment contact kind.",
                    )
    return raw, checked, effective_to


def _validate_eligibility(
    raw: Any,
    employer_id: str,
    country: str,
    problems: list[Problem],
) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or set(raw) != ELIGIBILITY_FIELDS:
        _problem(
            problems, employer_id, "eligibility.keys",
            sorted(raw) if isinstance(raw, dict) else raw,
            sorted(ELIGIBILITY_FIELDS),
            "Use the exact conditional eligibility object.",
        )
        return None
    scheme = raw["scheme"]
    classification = raw["classification"]
    if scheme not in SCHEMES:
        _problem(
            problems, employer_id, "eligibility.scheme", scheme,
            sorted(SCHEMES), "Use one reviewed scheme enum.",
        )
    if classification not in CLASSIFICATIONS:
        _problem(
            problems, employer_id, "eligibility.classification", classification,
            sorted(CLASSIFICATIONS),
            "Never encode an employer row as automatically eligible.",
        )
    if raw["requiresRoleCheck"] is not True:
        _problem(
            problems, employer_id, "eligibility.requiresRoleCheck",
            raw["requiresRoleCheck"], True,
            "Every directory row requires a role-level eligibility check.",
        )
    if not isinstance(raw["requiresLocationCheck"], bool):
        _problem(
            problems, employer_id, "eligibility.requiresLocationCheck",
            raw["requiresLocationCheck"], "boolean",
            "Use an explicit reviewed location-check boolean.",
        )
    expected = {
        "NZ": ("nz-whv-extension", "conditional", False),
        "AU": ("au-417-specified-work", "conditional", True),
    }
    if scheme == "none":
        wanted = (
            "none",
            "not-applicable",
            True,
            raw["requiresLocationCheck"],
        )
    else:
        expected_scheme, expected_classification, expected_location = expected[country]
        wanted = (
            expected_scheme,
            expected_classification,
            True,
            expected_location,
        )
    actual = (
        scheme,
        classification,
        raw["requiresRoleCheck"],
        raw["requiresLocationCheck"],
    )
    if actual != wanted:
        _problem(
            problems, employer_id, "eligibility", raw,
            {
                "scheme": wanted[0],
                "classification": wanted[1],
                "requiresRoleCheck": wanted[2],
                "requiresLocationCheck": wanted[3],
            },
            "Use conditional country-specific eligibility, or explicit none/not-applicable.",
        )
    return raw


def _validate_entry(
    raw: Any,
    index: int,
    today: date,
    problems: list[Problem],
) -> dict[str, Any] | None:
    problem_start = len(problems)
    provisional_id = (
        raw.get("id", f"<row:{index}>") if isinstance(raw, dict) else f"<row:{index}>"
    )
    if not isinstance(raw, dict) or set(raw) != ENTRY_FIELDS:
        _problem(
            problems, str(provisional_id), "entry.keys",
            sorted(raw) if isinstance(raw, dict) else raw,
            sorted(ENTRY_FIELDS),
            "Use exactly the schema-v1 employer entry fields.",
        )
        return None
    employer_id = str(raw["id"])
    if (
        not isinstance(raw["id"], str)
        or len(raw["id"]) > 100
        or ID_PATTERN.fullmatch(raw["id"]) is None
    ):
        _problem(
            problems, employer_id, "id", raw["id"],
            "unique lowercase kebab-case stable ID",
            "Use a stable lowercase ID; add a location suffix for another branch.",
        )
    country = raw["country"]
    if country not in COUNTRIES:
        _problem(
            problems, employer_id, "country", country, sorted(COUNTRIES),
            "Use NZ or AU.",
        )
        return None
    name = _safe_text(raw["name"], employer_id, "name", problems)
    location = _validate_location(
        raw["location"], employer_id, country, problems
    )
    contact = _validate_contact(raw["contact"], employer_id, problems)
    source, checked_at, effective_to = _validate_source(
        raw["source"], employer_id, country, contact, problems
    )
    status = raw["status"]
    if status not in STATUSES:
        _problem(
            problems, employer_id, "status", status, sorted(STATUSES),
            "Use the evidence-aware directory status.",
        )
    next_review = _iso_date(
        raw["nextReviewAt"], employer_id, "nextReviewAt", problems
    )
    if checked_at and checked_at > today:
        _problem(
            problems, employer_id, "source.checkedAt", checked_at.isoformat(),
            f"on or before {today.isoformat()}",
            "Do not publish a future evidence check.",
        )
    if next_review and checked_at and next_review < checked_at:
        _problem(
            problems, employer_id, "nextReviewAt", next_review.isoformat(),
            f"on or after checkedAt {checked_at.isoformat()}",
            "Correct the review schedule.",
        )
    if status in {"active", "uncertain"} and next_review and next_review < today:
        _problem(
            problems, employer_id, "nextReviewAt", next_review.isoformat(),
            f"on or after {today.isoformat()}",
            "Recheck the row or mark it expired before the review deadline passes.",
        )
    if effective_to and effective_to < today and status != "expired":
        _problem(
            problems, employer_id, "status", status, "expired",
            "An elapsed source effectiveTo cannot remain active or uncertain.",
        )
    if status == "expired" and (
        effective_to is None or effective_to >= today
    ):
        _problem(
            problems, employer_id, "source.effectiveTo",
            raw["source"].get("effectiveTo"), f"date before {today.isoformat()}",
            "Expired rows require an elapsed official effectiveTo date.",
        )
    if (
        source
        and source.get("kind") == "unverified"
        and status != "uncertain"
    ):
        _problem(
            problems, employer_id, "status", status, "uncertain",
            "Unverified evidence cannot be promoted to active.",
        )
    work_types = raw["workTypes"]
    if (
        not isinstance(work_types, list)
        or not 1 <= len(work_types) <= 8
        or not all(isinstance(item, str) for item in work_types)
        or len(set(work_types)) != len(work_types)
        or any(item not in WORK_TYPES for item in work_types)
    ):
        _problem(
            problems, employer_id, "workTypes", work_types,
            {"unique": True, "min": 1, "max": 8, "enum": sorted(WORK_TYPES)},
            "Map every work type to the fixed reviewed enum.",
        )
    if raw["vacancyStatus"] not in VACANCY_STATUSES:
        _problem(
            problems, employer_id, "vacancyStatus", raw["vacancyStatus"],
            "directory-only",
            "The directory may not claim a current vacancy.",
        )
    phrase_values = [raw["name"]]
    if isinstance(raw["location"], dict):
        phrase_values.extend(
            raw["location"].get(key, "") for key in ("label", "address")
        )
    for value in phrase_values:
        if isinstance(value, str) and VACANCY_PATTERN.search(value):
            _problem(
                problems, employer_id, "vacancyStatus/text", value,
                "directory wording without current-vacancy claims",
                "Remove current hiring/vacancy language; link users to the reviewed contact.",
            )
    _validate_eligibility(
        raw["eligibility"], employer_id, country, problems
    )
    if (
        name is None
        or location is None
        or contact is None
        or source is None
        or len(problems) != problem_start
    ):
        return None
    return raw


def _duplicates(
    employers: list[dict[str, Any]],
    problems: list[Problem],
) -> list[dict[str, Any]]:
    exact: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for employer in employers:
        key = "|".join((
            _normalize(employer["name"]),
            _location_key(employer["location"]),
            employer["contact"]["kind"],
            _canonical_contact(employer["contact"]),
        ))
        exact[key].append(employer)
    for group in exact.values():
        if len(group) > 1:
            ids = sorted(item["id"] for item in group)
            for item in group:
                _problem(
                    problems, item["id"], "duplicate", ids,
                    "one row per business branch",
                    "Merge the duplicate or give a genuinely distinct branch its own location ID.",
                )

    candidates: list[dict[str, Any]] = []
    for first_index, first in enumerate(employers):
        for second in employers[first_index + 1 :]:
            same_name = _normalize(first["name"]) == _normalize(second["name"])
            first_contact = _canonical_contact(first["contact"])
            second_contact = _canonical_contact(second["contact"])
            same_contact = (
                bool(first_contact)
                and first_contact == second_contact
            )
            if not (same_name or same_contact):
                continue
            distance = _distance_meters(first, second)
            if distance <= 200:
                candidates.append({
                    "firstId": min(first["id"], second["id"]),
                    "secondId": max(first["id"], second["id"]),
                    "distanceMeters": round(distance, 1),
                    "reason": (
                        "same-name-and-contact"
                        if same_name and same_contact
                        else "same-name"
                        if same_name
                        else "same-contact"
                    ),
                })
    return sorted(
        candidates,
        key=lambda item: (
            item["firstId"], item["secondId"], item["distanceMeters"]
        ),
    )


def _web_urls(employers: list[dict[str, Any]]) -> dict[str, dict[str, set[str]]]:
    urls: dict[str, dict[str, set[str]]] = {}
    for employer in employers:
        values = [("source", employer["source"]["url"])]
        if (
            employer["contact"]["kind"] in {"company", "recruitment"}
            and "url" in employer["contact"]
        ):
            values.append(("contact", employer["contact"]["url"]))
        for role, url in values:
            item = urls.setdefault(
                url, {"ownerIds": set(), "roles": set()}
            )
            item["ownerIds"].add(employer["id"])
            item["roles"].add(role)
    return urls


def _link_locator_count(employers: list[dict[str, Any]]) -> int:
    values = {item["source"]["url"] for item in employers}
    values.update(
        item["contact"]["url"]
        for item in employers
        if "url" in item["contact"]
    )
    return len(values)


def _audit(
    employers: list[dict[str, Any]],
    duplicate_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    countries = Counter(item["country"] for item in employers)
    statuses = Counter(item["status"] for item in employers)
    return {
        "employerCount": len(employers),
        "countryCounts": {"NZ": countries["NZ"], "AU": countries["AU"]},
        "statusCounts": {
            "active": statuses["active"],
            "uncertain": statuses["uncertain"],
            "expired": statuses["expired"],
        },
        "contactableCount": sum(
            item["contact"]["kind"] != "none" for item in employers
        ),
        "expiredCount": statuses["expired"],
        "nearDuplicateCandidateCount": len(duplicate_candidates),
        "linkUrlCount": _link_locator_count(employers),
    }


def verify_registry(path: Path, today: date) -> Verification:
    problems: list[Problem] = []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _problem(
            problems, "<root>", "json", str(exc), "valid UTF-8 JSON",
            "Correct the registry file before verification.",
        )
        return Verification(problems, [], {}, [])
    if not isinstance(raw, dict) or set(raw) != ROOT_FIELDS:
        _problem(
            problems, "<root>", "root.keys",
            sorted(raw) if isinstance(raw, dict) else type(raw).__name__,
            sorted(ROOT_FIELDS),
            "Use the exact schema-v1 root object.",
        )
        return Verification(problems, [], {}, [])
    if raw["schemaVersion"] != 1:
        _problem(
            problems, "<root>", "schemaVersion", raw["schemaVersion"], 1,
            "Migrate the registry to the supported schema version.",
        )
    generated = _iso_date(
        raw["generatedAt"], "<root>", "generatedAt", problems
    )
    if generated and generated > today:
        _problem(
            problems, "<root>", "generatedAt", generated.isoformat(),
            f"on or before {today.isoformat()}",
            "Do not publish a future registry generation date.",
        )
    if not isinstance(raw["employers"], list) or not raw["employers"]:
        _problem(
            problems, "<root>", "employers", raw["employers"],
            "non-empty array", "Add at least one reviewed employer row.",
        )
        employers_raw: list[Any] = []
    else:
        employers_raw = raw["employers"]
    employers: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(employers_raw):
        entry = _validate_entry(item, index, today, problems)
        if entry is None:
            continue
        if entry["id"] in seen_ids:
            _problem(
                problems, entry["id"], "id", entry["id"], "unique ID",
                "Give each branch one stable unique ID.",
            )
        seen_ids.add(entry["id"])
        employers.append(entry)
    duplicate_candidates = _duplicates(employers, problems)
    audit = _audit(employers, duplicate_candidates)
    declared_audit = raw["audit"]
    if (
        not isinstance(declared_audit, dict)
        or set(declared_audit) != AUDIT_FIELDS
        or declared_audit != audit
    ):
        _problem(
            problems, "<root>", "audit", declared_audit, audit,
            "Publish the exact deterministic audit emitted by the verifier.",
        )
    return Verification(problems, employers, audit, duplicate_candidates)


def _redirect_allowed(original: str, final: str) -> bool:
    original_parts = urllib_parse.urlsplit(original)
    final_parts = urllib_parse.urlsplit(final)
    return (
        final_parts.scheme == "https"
        and final_parts.hostname is not None
        and final_parts.username is None
        and final_parts.password is None
        and _registrable_host(original_parts.hostname or "")
        == _registrable_host(final_parts.hostname)
    )


def _link_result(
    url: str,
    context: dict[str, set[str]],
    status: str,
    *,
    http_status: int | None = None,
    final_url: str | None = None,
    actual: str,
    fix: str,
) -> dict[str, Any]:
    return {
        "url": url,
        "ownerIds": sorted(context["ownerIds"]),
        "roles": sorted(context["roles"]),
        "status": status,
        "httpStatus": http_status,
        "finalUrl": final_url,
        "actual": actual,
        "expected": "reachable reviewed HTTPS representation",
        "fix": fix,
    }


def check_links(
    employers: list[dict[str, Any]],
    *,
    timeout: float = 10.0,
    urlopen: Callable[..., Any] = urllib_request.urlopen,
    generated_at: str | None = None,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    urls = _web_urls(employers)
    for url in sorted(urls):
        context = urls[url]
        request = urllib_request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        try:
            with urlopen(
                request, timeout=timeout, context=ssl.create_default_context()
            ) as response:
                status_code = int(getattr(response, "status", 200))
                final_url = response.geturl()
                body = response.read(MAX_BODY_BYTES)
            if not _redirect_allowed(url, final_url):
                result = _link_result(
                    url, context, "unsupported",
                    http_status=status_code, final_url=final_url,
                    actual="redirect crossed the reviewed registrable HTTPS host",
                    fix="Review the redirect and update the registry only after official confirmation.",
                )
            elif status_code in {401, 403}:
                result = _link_result(
                    url, context, "blocked",
                    http_status=status_code, final_url=final_url,
                    actual=f"HTTP {status_code}",
                    fix="Review manually; access blocking does not prove link drift.",
                )
            elif status_code == 429 or status_code >= 500:
                result = _link_result(
                    url, context, "transient",
                    http_status=status_code, final_url=final_url,
                    actual=f"HTTP {status_code}",
                    fix="Retry the link audit after the transient service failure.",
                )
            elif status_code < 200 or status_code >= 300:
                result = _link_result(
                    url, context, "changed",
                    http_status=status_code, final_url=final_url,
                    actual=f"HTTP {status_code}",
                    fix="Replace or re-review the changed official/contact link.",
                )
            elif not body.strip():
                result = _link_result(
                    url, context, "changed",
                    http_status=status_code, final_url=final_url,
                    actual="empty HTTP 2xx response",
                    fix="Confirm the representation and update the reviewed URL.",
                )
            else:
                lower = body[:64_000].lower()
                blocked = (
                    b"verify you are human" in lower
                    or (
                        b"<input" in lower
                        and b"type=\"password\"" in lower
                    )
                )
                result = _link_result(
                    url, context, "blocked" if blocked else "match",
                    http_status=status_code, final_url=final_url,
                    actual=(
                        "HTTP 2xx access challenge"
                        if blocked
                        else f"HTTP {status_code} non-empty response"
                    ),
                    fix=(
                        "Review manually; access blocking does not prove link drift."
                        if blocked
                        else "No action required."
                    ),
                )
        except urllib_error.HTTPError as exc:
            code = int(exc.code)
            status = (
                "blocked" if code in {401, 403}
                else "transient" if code == 429 or code >= 500
                else "changed"
            )
            result = _link_result(
                url, context, status, http_status=code, final_url=exc.geturl(),
                actual=f"HTTP {code}",
                fix=(
                    "Review manually; access blocking does not prove link drift."
                    if status == "blocked"
                    else "Retry after the transient failure."
                    if status == "transient"
                    else "Replace or re-review the changed link."
                ),
            )
            exc.close()
        except (
            urllib_error.URLError,
            TimeoutError,
            socket.timeout,
            ssl.SSLError,
        ) as exc:
            result = _link_result(
                url, context, "transient",
                actual=f"{type(exc).__name__}: {exc}",
                fix="Retry the link audit; investigate DNS, TLS, or timeout if persistent.",
            )
        results.append(result)
    counts = Counter(item["status"] for item in results)
    return {
        "schemaVersion": 1,
        "generatedAt": generated_at or date.today().isoformat(),
        "audit": {
            "urlCount": len(results),
            "match": counts["match"],
            "changed": counts["changed"],
            "blocked": counts["blocked"],
            "transient": counts["transient"],
            "unsupported": counts["unsupported"],
        },
        "results": results,
    }


def _parse_today(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("today must be a real ISO date") from exc
    if parsed.isoformat() != value:
        raise argparse.ArgumentTypeError("today must be canonical YYYY-MM-DD")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the schema-v1 employer directory."
    )
    parser.add_argument(
        "registry", nargs="?", default="data/employers.json",
        help="employer registry JSON path",
    )
    parser.add_argument("--today", type=_parse_today, default=date.today())
    parser.add_argument("--dump-duplicates", action="store_true")
    parser.add_argument("--check-links", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--output")
    parser.add_argument(
        "--no-fail", action="store_true",
        help="write a non-match link report without returning exit 1",
    )
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 30:
        parser.error("--timeout must be within (0, 30]")
    verification = verify_registry(Path(args.registry), args.today)
    if verification.problems:
        print(
            f"Employer verification failed with "
            f"{len(verification.problems)} error(s):",
            file=sys.stderr,
        )
        for problem in verification.problems:
            print(problem.render(), file=sys.stderr)
        return 1
    if args.dump_duplicates:
        print(
            "Near-duplicate candidates: "
            + _json(verification.duplicate_candidates)
        )
    print(
        "Employer verification passed: "
        f"{verification.audit['employerCount']} employer(s), "
        f"audit={_json(verification.audit)}."
    )
    if not args.check_links:
        if args.output:
            Path(args.output).write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "generatedAt": args.today.isoformat(),
                        "audit": verification.audit,
                        "duplicateCandidates": verification.duplicate_candidates,
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
        return 0
    report = check_links(
        verification.employers,
        timeout=args.timeout,
        generated_at=args.today.isoformat(),
    )
    if args.output:
        Path(args.output).write_text(
            json.dumps(
                report, ensure_ascii=False, indent=2, sort_keys=True
            ) + "\n",
            encoding="utf-8",
        )
    print("Employer link audit: " + _json(report["audit"]))
    nonmatch = report["audit"]["urlCount"] - report["audit"]["match"]
    return 0 if nonmatch == 0 or args.no_fail else 1


if __name__ == "__main__":
    raise SystemExit(main())
