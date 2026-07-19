#!/usr/bin/env python3
"""Pure, deterministic reducer for the single employer-link drift issue."""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
from urllib import parse as urllib_parse


ISSUE_TITLE = "Employer directory link drift"
MARKER_PREFIX = "employer-link-report:v1:"
MARKER_PATTERN = re.compile(
    r"<!-- employer-link-report:v1:([0-9a-f]{64}) -->"
)
STATUSES = frozenset({
    "match", "changed", "blocked", "transient", "unsupported"
})
REPORT_FIELDS = frozenset({"schemaVersion", "generatedAt", "audit", "results"})
AUDIT_FIELDS = frozenset({
    "urlCount", "match", "changed", "blocked", "transient", "unsupported"
})
RESULT_FIELDS = frozenset({
    "url",
    "ownerIds",
    "roles",
    "status",
    "httpStatus",
    "finalUrl",
    "actual",
    "expected",
    "fix",
})


class ReducerError(ValueError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _escape(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("`", "\\`")
    )


def _validate_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        raise ReducerError("report root does not match schema v1")
    if report["schemaVersion"] != 1:
        raise ReducerError("report schemaVersion must be 1")
    if (
        not isinstance(report["generatedAt"], str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}", report["generatedAt"]) is None
    ):
        raise ReducerError("report generatedAt must be a canonical ISO date")
    try:
        generated_at = date.fromisoformat(report["generatedAt"])
    except ValueError as exc:
        raise ReducerError("report generatedAt must be a real ISO date") from exc
    if generated_at.isoformat() != report["generatedAt"]:
        raise ReducerError("report generatedAt must be a canonical ISO date")
    if not isinstance(report["results"], list):
        raise ReducerError("report results must be an array")
    if (
        not isinstance(report["audit"], dict)
        or set(report["audit"]) != AUDIT_FIELDS
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in report["audit"].values()
        )
    ):
        raise ReducerError("report audit must contain exact non-negative counts")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, result in enumerate(report["results"]):
        if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
            raise ReducerError(f"result {index} has unsupported fields")
        if (
            not isinstance(result["status"], str)
            or result["status"] not in STATUSES
        ):
            raise ReducerError(f"result {index} has unknown status")
        if (
            not isinstance(result["url"], str)
            or not result["url"].startswith("https://")
            or result["url"] in seen
        ):
            raise ReducerError(f"result {index} URL is invalid or duplicated")
        seen.add(result["url"])
        if (
            not isinstance(result["ownerIds"], list)
            or not result["ownerIds"]
            or not all(isinstance(item, str) and item for item in result["ownerIds"])
            or len(set(result["ownerIds"])) != len(result["ownerIds"])
        ):
            raise ReducerError(f"result {index} ownerIds are invalid")
        if (
            not isinstance(result["roles"], list)
            or not result["roles"]
            or not all(isinstance(item, str) for item in result["roles"])
            or not set(result["roles"]) <= {"source", "contact"}
        ):
            raise ReducerError(f"result {index} roles are invalid")
        if (
            result["httpStatus"] is not None
            and (
                isinstance(result["httpStatus"], bool)
                or not isinstance(result["httpStatus"], int)
                or not 100 <= result["httpStatus"] <= 599
            )
        ):
            raise ReducerError(f"result {index} httpStatus is invalid")
        if result["finalUrl"] is not None:
            if (
                not isinstance(result["finalUrl"], str)
                or len(result["finalUrl"]) > 2048
            ):
                raise ReducerError(f"result {index} finalUrl is invalid")
            final = urllib_parse.urlsplit(result["finalUrl"])
            if (
                final.scheme != "https"
                or not final.hostname
                or final.username is not None
                or final.password is not None
            ):
                raise ReducerError(f"result {index} finalUrl is invalid")
        for field in ("actual", "expected", "fix"):
            if (
                not isinstance(result[field], str)
                or not result[field]
                or len(result[field]) > 2000
            ):
                raise ReducerError(f"result {index} {field} is invalid")
        normalized.append({
            "url": result["url"],
            "ownerIds": sorted(result["ownerIds"]),
            "roles": sorted(result["roles"]),
            "status": result["status"],
            "httpStatus": result["httpStatus"],
            "finalUrl": result["finalUrl"],
            "actual": result["actual"],
            "expected": result["expected"],
            "fix": result["fix"],
        })
    normalized.sort(key=lambda item: item["url"])
    observed = {status: 0 for status in STATUSES}
    for item in normalized:
        observed[item["status"]] += 1
    if (
        report["audit"]["urlCount"] != len(normalized)
        or any(report["audit"][status] != observed[status] for status in STATUSES)
    ):
        raise ReducerError("report audit does not match deterministic results")
    return {**report, "results": normalized}


def body_fingerprint(report: dict[str, Any]) -> str:
    normalized = _validate_report(report)
    substantive = [
        item for item in normalized["results"] if item["status"] != "match"
    ]
    payload = {
        "audit": {
            key: normalized["audit"].get(key)
            for key in (
                "urlCount", "match", "changed", "blocked",
                "transient", "unsupported",
            )
        },
        "findings": substantive,
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def render_issue_body(report: dict[str, Any]) -> dict[str, str]:
    normalized = _validate_report(report)
    fingerprint = body_fingerprint(normalized)
    findings = [
        item for item in normalized["results"] if item["status"] != "match"
    ]
    audit = normalized["audit"]
    lines = [
        "## Employer directory link drift",
        "",
        f"Generated: `{_escape(normalized['generatedAt'])}`",
        "",
        (
            "Audit: "
            f"{audit.get('urlCount', 0)} URLs; "
            f"{audit.get('match', 0)} match; "
            f"{audit.get('changed', 0)} changed; "
            f"{audit.get('blocked', 0)} blocked; "
            f"{audit.get('transient', 0)} transient; "
            f"{audit.get('unsupported', 0)} unsupported."
        ),
        "",
    ]
    if findings:
        lines.extend([
            "| Status | URL | Rows | Actual | Fix |",
            "|---|---|---|---|---|",
        ])
        for item in findings:
            lines.append(
                "| "
                + " | ".join((
                    _escape(item["status"]),
                    f"[official/contact link]({_escape(item['url'])})",
                    _escape(", ".join(item["ownerIds"])),
                    _escape(item["actual"]),
                    _escape(item["fix"]),
                ))
                + " |"
            )
    else:
        lines.append("All reviewed employer source/contact links matched.")
    lines.extend([
        "",
        "No response body, email content, token, or user data is stored here.",
        "",
        f"<!-- {MARKER_PREFIX}{fingerprint} -->",
    ])
    return {
        "body": "\n".join(lines) + "\n",
        "bodyFingerprint": fingerprint,
    }


def _existing_fingerprint(body: Any) -> str:
    if not isinstance(body, str) or len(body) > 200_000:
        raise ReducerError("existing issue body is missing or oversized")
    matches = MARKER_PATTERN.findall(body)
    if len(matches) != 1:
        raise ReducerError("existing exact-title issue needs one valid v1 marker")
    return matches[0]


def reduce_issue(
    report: dict[str, Any],
    issues: Any,
) -> dict[str, Any]:
    normalized = _validate_report(report)
    if not isinstance(issues, list):
        raise ReducerError("issues input must be a JSON array")
    exact = [
        item for item in issues
        if isinstance(item, dict) and item.get("title") == ISSUE_TITLE
    ]
    if len(exact) > 1:
        raise ReducerError("multiple exact-title employer drift issues exist")
    current = exact[0] if exact else None
    if current is not None and (
        not isinstance(current.get("number"), int)
        or current.get("state") not in {"OPEN", "CLOSED", "open", "closed"}
    ):
        raise ReducerError("existing exact-title issue shape is invalid")
    rendered = render_issue_body(normalized)
    findings = any(
        item["status"] != "match" for item in normalized["results"]
    )
    issue_number = current["number"] if current else None
    current_state = str(current.get("state", "")).lower() if current else ""
    old_fingerprint = (
        _existing_fingerprint(current.get("body")) if current else None
    )
    if not findings:
        action = "close" if current and current_state == "open" else "noop"
    elif current is None:
        action = "create"
    else:
        if current_state == "closed":
            action = "reopen"
        elif old_fingerprint == rendered["bodyFingerprint"]:
            action = "noop"
        else:
            action = "update"
    return {
        "schemaVersion": 1,
        "action": action,
        "issueNumber": issue_number,
        "title": ISSUE_TITLE,
        "body": rendered["body"],
        "bodyFingerprint": rendered["bodyFingerprint"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reduce one employer link report into one issue action."
    )
    parser.add_argument("--report", required=True)
    parser.add_argument("--issues", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        issues = json.loads(Path(args.issues).read_text(encoding="utf-8"))
        payload = reduce_issue(report, issues)
    except (OSError, UnicodeError, json.JSONDecodeError, ReducerError) as exc:
        print(f"Employer issue reducer failed: {exc}", file=sys.stderr)
        return 1
    serialized = json.dumps(
        payload, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    if args.output:
        Path(args.output).write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
