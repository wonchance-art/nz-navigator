#!/usr/bin/env python3
"""Validate the factual-claim registry without third-party dependencies."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import ssl
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request


SUPPORTED_SCHEMA_VERSION = 1
VALID_STATUSES = frozenset({"official", "derived", "estimated", "unverified"})
VALID_SEVERITIES = frozenset({"critical", "medium", "minor"})
PARITY_STATUSES = frozenset({"official", "derived"})
STALE_AFTER_DAYS = {"critical": 45, "medium": 90, "minor": 90}

COUNTRY_OFFICIAL_DOMAINS = {
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

# Cross-country claims may use only these explicitly reviewed intergovernmental
# sources. Additions should be code-reviewed rather than accepting arbitrary
# .org or government-looking domains.
COMMON_OFFICIAL_DOMAINS = (
    "oecd.org",
    "worldbank.org",
    "ilo.org",
    "un.org",
)

REQUIRED_ROOT_FIELDS = ("schemaVersion", "generatedAt", "claims")
REQUIRED_CLAIM_FIELDS = (
    "id",
    "country",
    "locale",
    "category",
    "label",
    "value",
    "status",
    "verifiedAt",
    "effectiveFrom",
    "sourceUrl",
    "pages",
    "severity",
)
STRING_FIELDS = (
    "id",
    "country",
    "locale",
    "category",
    "label",
    "status",
    "verifiedAt",
    "effectiveFrom",
    "sourceUrl",
    "severity",
)
OPTIONAL_STRING_FIELDS = (
    "unit",
    "effectiveTo",
    "parityKey",
    "notes",
    "parityExemptReason",
)


@dataclass(frozen=True)
class Issue:
    """One actionable validation failure."""

    claim_id: str
    field: str
    message: str
    fix: str

    def render(self) -> str:
        return (
            f"ERROR [{self.claim_id}] {self.field}: {self.message}\n"
            f"  Fix: {self.fix}"
        )


@dataclass
class ValidationReport:
    """Validation outcome and useful success counters."""

    issues: list[Issue] = field(default_factory=list)
    claim_count: int = 0
    checked_pages: set[str] = field(default_factory=set)
    checked_links: int = 0

    @property
    def ok(self) -> bool:
        return not self.issues


class ClaimMarkerParser(HTMLParser):
    """Collect data-claim-id attributes with HTML entity decoding."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.claim_ids: set[str] = set()

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self._collect(attrs)

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self._collect(attrs)

    def _collect(self, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() == "data-claim-id" and value is not None:
                self.claim_ids.add(value)


def _reject_non_json_number(value: str) -> None:
    raise ValueError(f"{value} is not valid JSON")


def _parse_iso_date(value: str) -> date | None:
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.isoformat() == value else None


def _parse_generated_at(value: str) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_json_scalar(value: Any) -> bool:
    if value is None or isinstance(value, (list, dict)):
        return False
    if isinstance(value, float):
        return math.isfinite(value)
    return isinstance(value, (str, int, float, bool))


def _hostname_allowed(hostname: str, domains: Iterable[str]) -> bool:
    host = hostname.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def _allowed_domains_for(country: str) -> tuple[str, ...] | None:
    if country == "COMMON":
        return COMMON_OFFICIAL_DOMAINS
    country_domains = COUNTRY_OFFICIAL_DOMAINS.get(country)
    if country_domains is None:
        return None
    return country_domains + COMMON_OFFICIAL_DOMAINS


def _validate_source_url(
    claim_id: str,
    country: str,
    source_url: str,
    issues: list[Issue],
) -> bool:
    try:
        parsed = urllib_parse.urlsplit(source_url)
        hostname = parsed.hostname
    except ValueError:
        hostname = None
        parsed = None

    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        issues.append(
            Issue(
                claim_id,
                "sourceUrl",
                "must be an absolute HTTP(S) URL without embedded credentials",
                "Use the canonical public source URL, for example "
                "https://www.immigration.govt.nz/...",
            )
        )
        return False

    allowed = _allowed_domains_for(country)
    if allowed is None:
        issues.append(
            Issue(
                claim_id,
                "country",
                f"{country!r} has no official-domain policy",
                "Use NZ, CA, AU, or COMMON, or add a reviewed country allowlist.",
            )
        )
        return False

    if not _hostname_allowed(hostname, allowed):
        issues.append(
            Issue(
                claim_id,
                "sourceUrl",
                f"host {hostname!r} is not allowlisted for {country}",
                "Replace it with an approved official source or explicitly "
                "review and extend the allowlist in scripts/verify_claims.py.",
            )
        )
        return False
    return True


def _safe_page_path(
    root: Path,
    page: str,
    claim_id: str,
    field_name: str,
    issues: list[Issue],
) -> Path | None:
    raw_path = Path(page)
    if raw_path.is_absolute():
        issues.append(
            Issue(
                claim_id,
                field_name,
                f"{page!r} is absolute",
                "Use a repository-relative page path such as nz/index.html.",
            )
        )
        return None

    root_resolved = root.resolve()
    candidate = (root_resolved / raw_path).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        issues.append(
            Issue(
                claim_id,
                field_name,
                f"{page!r} escapes the repository root",
                "Remove '..' segments and use a repository-relative HTML path.",
            )
        )
        return None
    return candidate


def _page_claim_ids(
    page_path: Path,
    page_label: str,
    claim_id: str,
    field_name: str,
    issues: list[Issue],
    cache: dict[Path, set[str]],
) -> set[str] | None:
    if page_path in cache:
        return cache[page_path]

    if not page_path.is_file():
        issues.append(
            Issue(
                claim_id,
                field_name,
                f"page {page_label!r} does not exist",
                "Create the page or correct the repository-relative path.",
            )
        )
        return None

    try:
        content = page_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        issues.append(
            Issue(
                claim_id,
                field_name,
                f"cannot read {page_label!r} as UTF-8: {exc}",
                "Make the page readable UTF-8 HTML.",
            )
        )
        return None

    parser = ClaimMarkerParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception as exc:  # HTMLParser errors are rare but should be actionable.
        issues.append(
            Issue(
                claim_id,
                field_name,
                f"cannot parse claim markers in {page_label!r}: {exc}",
                "Repair the HTML around data-claim-id attributes.",
            )
        )
        return None

    cache[page_path] = parser.claim_ids
    return parser.claim_ids


def _validate_parity(claims: list[dict[str, Any]], issues: list[Issue]) -> None:
    groups: dict[str, list[dict[str, Any]]] = {}
    for claim in claims:
        if (
            claim.get("status") in PARITY_STATUSES
            and _is_nonempty_string(claim.get("parityKey"))
        ):
            groups.setdefault(claim["parityKey"], []).append(claim)

    for parity_key, group in groups.items():
        comparable = [
            claim
            for claim in group
            if not _is_nonempty_string(claim.get("parityExemptReason"))
            and _is_nonempty_string(claim.get("id"))
            and _is_json_scalar(claim.get("value"))
        ]
        if len(comparable) < 2:
            continue

        baseline = comparable[0]
        baseline_pair = (baseline.get("value"), baseline.get("unit"))
        for claim in comparable[1:]:
            pair = (claim.get("value"), claim.get("unit"))
            if pair == baseline_pair:
                continue
            issues.append(
                Issue(
                    claim["id"],
                    "parityKey",
                    f"{parity_key!r} value/unit {pair!r} differs from "
                    f"{baseline['id']!r} {baseline_pair!r}",
                    "Align value and unit across official/derived translations, "
                    "or add a non-empty parityExemptReason explaining the exception.",
                )
            )


def _ssl_context() -> ssl.SSLContext:
    """Use Python's CA store, with the macOS system bundle as a fallback."""

    paths = ssl.get_default_verify_paths()
    if paths.cafile or paths.capath:
        return ssl.create_default_context()
    system_bundle = Path("/etc/ssl/cert.pem")
    if system_bundle.is_file():
        return ssl.create_default_context(cafile=str(system_bundle))
    return ssl.create_default_context()


def _request_link(url: str, method: str, timeout: float) -> None:
    request = urllib_request.Request(
        url,
        method=method,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 Safari/537.36 "
                "nz-navigator-claim-verifier/1.0"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Connection": "close",
        },
    )
    try:
        with urllib_request.urlopen(
            request, timeout=timeout, context=_ssl_context()
        ) as response:
            status = getattr(response, "status", None) or response.getcode()
            if not 200 <= status < 400:
                raise RuntimeError(f"HTTP {status}")
            if method == "GET":
                response.read(1)
    except urllib_error.HTTPError as exc:
        # Authentication, bot protection, rate limiting, and unsupported HEAD
        # prove that the official host and path exist. 404/410 and transport
        # failures still fail the dead-link check.
        if exc.code in {401, 403, 405, 429}:
            return
        raise


def _check_source_links(
    url_claims: dict[str, set[str]],
    timeout: float,
    issues: list[Issue],
) -> int:
    def check_one(url: str) -> tuple[str, list[str]]:
        failures: list[str] = []
        for method in ("HEAD", "GET"):
            try:
                _request_link(url, method, timeout)
                return url, []
            except Exception as exc:  # Network stacks expose several exception types.
                failures.append(f"{method}: {exc}")
        return url, failures

    urls = sorted(url_claims)
    # Government sites can take the full timeout or block HEAD requests.
    # Bounded concurrency keeps the opt-in audit practical without creating
    # an unbounded request burst.
    with ThreadPoolExecutor(max_workers=min(8, len(urls) or 1)) as executor:
        results = executor.map(check_one, urls)
        for url, failures in results:
            if not failures:
                continue
            detail = "; ".join(failures)
            for claim_id in sorted(url_claims[url]):
                issues.append(
                    Issue(
                        claim_id,
                        "sourceUrl",
                        f"link check failed for {url}: {detail}",
                        "Confirm the official URL is live or replace it with the "
                        "current canonical source. Re-run with --check-links.",
                    )
                )
    return len(urls)


def _load_registry(registry_path: Path, report: ValidationReport) -> Any:
    if not registry_path.is_file():
        report.issues.append(
            Issue(
                "<registry>",
                "file",
                f"{registry_path} does not exist",
                "Create data/claims.json or pass the correct registry path.",
            )
        )
        return None
    try:
        with registry_path.open(encoding="utf-8") as handle:
            return json.load(handle, parse_constant=_reject_non_json_number)
    except json.JSONDecodeError as exc:
        report.issues.append(
            Issue(
                "<registry>",
                "json",
                f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
                "Repair the JSON syntax and re-run the verifier.",
            )
        )
    except (OSError, UnicodeError, ValueError) as exc:
        report.issues.append(
            Issue(
                "<registry>",
                "json",
                f"cannot load strict UTF-8 JSON: {exc}",
                "Use valid UTF-8 JSON with finite numeric values.",
            )
        )
    return None


def validate_registry(
    registry_path: Path | str,
    root: Path | str,
    *,
    today: date | None = None,
    check_links: bool = False,
    timeout: float = 10.0,
) -> ValidationReport:
    """Validate a registry and its page markers.

    ``today`` is injectable so unit tests can exercise age boundaries without
    changing the production CLI clock.
    """

    report = ValidationReport()
    root_path = Path(root).resolve()
    registry = Path(registry_path)
    if not registry.is_absolute():
        registry = root_path / registry

    data = _load_registry(registry, report)
    if data is None:
        return report
    if not isinstance(data, dict):
        report.issues.append(
            Issue(
                "<registry>",
                "root",
                "JSON root must be an object",
                "Wrap schemaVersion, generatedAt, and claims in one JSON object.",
            )
        )
        return report

    for field_name in REQUIRED_ROOT_FIELDS:
        if field_name not in data:
            report.issues.append(
                Issue(
                    "<registry>",
                    field_name,
                    "required root field is missing",
                    f"Add the {field_name!r} field to the registry root.",
                )
            )

    schema_version = data.get("schemaVersion")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != SUPPORTED_SCHEMA_VERSION
    ):
        report.issues.append(
            Issue(
                "<registry>",
                "schemaVersion",
                f"must be integer {SUPPORTED_SCHEMA_VERSION}",
                f"Set schemaVersion to {SUPPORTED_SCHEMA_VERSION}.",
            )
        )

    if _parse_generated_at(data.get("generatedAt")) is None:
        report.issues.append(
            Issue(
                "<registry>",
                "generatedAt",
                "must be an ISO 8601 timestamp with a timezone",
                "Use a value such as 2026-07-19T00:00:00Z.",
            )
        )

    claims_value = data.get("claims")
    if not isinstance(claims_value, list):
        report.issues.append(
            Issue(
                "<registry>",
                "claims",
                "must be an array",
                "Set claims to a JSON array of claim objects.",
            )
        )
        return report

    report.claim_count = len(claims_value)
    today_value = today or datetime.now(timezone.utc).date()
    seen_ids: dict[str, int] = {}
    valid_claims: list[dict[str, Any]] = []
    page_cache: dict[Path, set[str]] = {}
    url_claims: dict[str, set[str]] = {}

    for index, claim in enumerate(claims_value):
        fallback_id = f"<claim #{index + 1}>"
        if not isinstance(claim, dict):
            report.issues.append(
                Issue(
                    fallback_id,
                    "claim",
                    "claim must be an object",
                    "Replace the array item with an object containing all required fields.",
                )
            )
            continue

        raw_id = claim.get("id")
        claim_id = raw_id if _is_nonempty_string(raw_id) else fallback_id
        valid_claims.append(claim)

        for field_name in REQUIRED_CLAIM_FIELDS:
            if field_name not in claim:
                report.issues.append(
                    Issue(
                        claim_id,
                        field_name,
                        "required field is missing",
                        f"Add {field_name!r} to this claim.",
                    )
                )

        for field_name in STRING_FIELDS:
            if field_name in claim and not _is_nonempty_string(claim[field_name]):
                report.issues.append(
                    Issue(
                        claim_id,
                        field_name,
                        "must be a non-empty string",
                        f"Set {field_name!r} to a non-empty JSON string.",
                    )
                )

        for field_name in OPTIONAL_STRING_FIELDS:
            if field_name in claim and not _is_nonempty_string(claim[field_name]):
                report.issues.append(
                    Issue(
                        claim_id,
                        field_name,
                        "must be a non-empty string when present",
                        f"Remove {field_name!r} or set it to a non-empty string.",
                    )
                )

        if "value" in claim and not _is_json_scalar(claim["value"]):
            report.issues.append(
                Issue(
                    claim_id,
                    "value",
                    "must be a finite JSON scalar (string, number, or boolean)",
                    "Store a scalar display/comparison value; move explanation to notes.",
                )
            )

        if _is_nonempty_string(raw_id):
            if raw_id in seen_ids:
                report.issues.append(
                    Issue(
                        raw_id,
                        "id",
                        f"duplicates claim #{seen_ids[raw_id] + 1}",
                        "Give every claim a stable, globally unique id.",
                    )
                )
            else:
                seen_ids[raw_id] = index

        status = claim.get("status")
        if _is_nonempty_string(status) and status not in VALID_STATUSES:
            report.issues.append(
                Issue(
                    claim_id,
                    "status",
                    f"{status!r} is not one of {sorted(VALID_STATUSES)}",
                    "Use official, derived, estimated, or unverified.",
                )
            )

        severity = claim.get("severity")
        if _is_nonempty_string(severity) and severity not in VALID_SEVERITIES:
            report.issues.append(
                Issue(
                    claim_id,
                    "severity",
                    f"{severity!r} is not one of {sorted(VALID_SEVERITIES)}",
                    "Use critical, medium, or minor.",
                )
            )

        verified_date: date | None = None
        verified_at = claim.get("verifiedAt")
        if _is_nonempty_string(verified_at):
            verified_date = _parse_iso_date(verified_at)
            if verified_date is None:
                report.issues.append(
                    Issue(
                        claim_id,
                        "verifiedAt",
                        "must be an ISO date in YYYY-MM-DD form",
                        "Use a real calendar date such as 2026-07-19.",
                    )
                )
            elif verified_date > today_value:
                report.issues.append(
                    Issue(
                        claim_id,
                        "verifiedAt",
                        f"{verified_at} is in the future relative to {today_value}",
                        "Use the date the official source was actually checked.",
                    )
                )
            elif severity in STALE_AFTER_DAYS:
                age = (today_value - verified_date).days
                limit = STALE_AFTER_DAYS[severity]
                if age > limit:
                    report.issues.append(
                        Issue(
                            claim_id,
                            "verifiedAt",
                            f"claim is stale ({age} days old; limit is {limit})",
                            "Re-check the official source and update verifiedAt "
                            "(and value/effective dates if needed).",
                        )
                    )

        effective_from_date: date | None = None
        effective_from = claim.get("effectiveFrom")
        if _is_nonempty_string(effective_from):
            effective_from_date = _parse_iso_date(effective_from)
            if effective_from_date is None:
                report.issues.append(
                    Issue(
                        claim_id,
                        "effectiveFrom",
                        "must be an ISO date in YYYY-MM-DD form",
                        "Use a real calendar date such as 2026-04-01.",
                    )
                )

        effective_to_date: date | None = None
        effective_to = claim.get("effectiveTo")
        if _is_nonempty_string(effective_to):
            effective_to_date = _parse_iso_date(effective_to)
            if effective_to_date is None:
                report.issues.append(
                    Issue(
                        claim_id,
                        "effectiveTo",
                        "must be an ISO date in YYYY-MM-DD form",
                        "Use a real calendar date or remove effectiveTo.",
                    )
                )

        if (
            effective_from_date is not None
            and effective_to_date is not None
            and effective_from_date > effective_to_date
        ):
            report.issues.append(
                Issue(
                    claim_id,
                    "effectiveTo",
                    "is earlier than effectiveFrom",
                    "Correct the effective date range so effectiveFrom <= effectiveTo.",
                )
            )

        country = claim.get("country")
        source_url = claim.get("sourceUrl")
        source_valid = False
        country_supported = False
        if _is_nonempty_string(country):
            country_supported = _allowed_domains_for(country) is not None
            if not country_supported:
                report.issues.append(
                    Issue(
                        claim_id,
                        "country",
                        f"{country!r} has no official-domain policy",
                        "Use NZ, CA, AU, or COMMON, or add a reviewed country allowlist.",
                    )
                )
        if country_supported and _is_nonempty_string(source_url):
            source_valid = _validate_source_url(
                claim_id, country, source_url, report.issues
            )
        if source_valid:
            url_claims.setdefault(source_url, set()).add(claim_id)

        pages = claim.get("pages")
        if "pages" in claim:
            if not isinstance(pages, list) or not pages:
                report.issues.append(
                    Issue(
                        claim_id,
                        "pages",
                        "must be a non-empty array",
                        "List every repository-relative HTML page that shows this claim.",
                    )
                )
            else:
                for page_index, page in enumerate(pages):
                    page_field = f"pages[{page_index}]"
                    if not _is_nonempty_string(page):
                        report.issues.append(
                            Issue(
                                claim_id,
                                page_field,
                                "must be a non-empty page path string",
                                "Use a path such as nz/index.html.",
                            )
                        )
                        continue
                    page_path = _safe_page_path(
                        root_path, page, claim_id, page_field, report.issues
                    )
                    if page_path is None:
                        continue
                    markers = _page_claim_ids(
                        page_path,
                        page,
                        claim_id,
                        page_field,
                        report.issues,
                        page_cache,
                    )
                    if markers is None:
                        continue
                    report.checked_pages.add(page)
                    if _is_nonempty_string(raw_id) and raw_id not in markers:
                        report.issues.append(
                            Issue(
                                claim_id,
                                page_field,
                                f"{page!r} has no data-claim-id={raw_id!r} marker",
                                f'Add data-claim-id="{raw_id}" to the element that '
                                "renders this claim, or remove the page from pages.",
                            )
                        )

        if _is_nonempty_string(claim.get("parityExemptReason")) and not _is_nonempty_string(
            claim.get("parityKey")
        ):
            report.issues.append(
                Issue(
                    claim_id,
                    "parityExemptReason",
                    "has no parityKey to exempt",
                    "Add the relevant parityKey or remove parityExemptReason.",
                )
            )

    _validate_parity(valid_claims, report.issues)

    if check_links:
        report.checked_links = _check_source_links(
            url_claims, timeout, report.issues
        )

    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate data/claims.json and its HTML claim markers."
    )
    parser.add_argument(
        "registry",
        nargs="?",
        default="data/claims.json",
        help="registry path, relative to --root (default: data/claims.json)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root (default: parent of this script's directory)",
    )
    parser.add_argument(
        "--check-links",
        action="store_true",
        help="also make HTTP HEAD/GET requests for sourceUrl values",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="per-request link timeout in seconds (default: 10)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.timeout <= 0:
        print("ERROR [<arguments>] timeout: must be greater than zero", file=sys.stderr)
        print("  Fix: Pass a positive --timeout value.", file=sys.stderr)
        return 1

    root = args.root or Path(__file__).resolve().parents[1]
    report = validate_registry(
        args.registry,
        root,
        check_links=args.check_links,
        timeout=args.timeout,
    )
    if not report.ok:
        print(
            f"Claim verification failed with {len(report.issues)} error(s):",
            file=sys.stderr,
        )
        for issue in report.issues:
            print(issue.render(), file=sys.stderr)
        return 1

    suffix = (
        f", {report.checked_links} unique source link(s)"
        if args.check_links
        else ""
    )
    print(
        f"Claim verification passed: {report.claim_count} claim(s), "
        f"{len(report.checked_pages)} page(s){suffix}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
