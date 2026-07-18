#!/usr/bin/env python3
"""Render and reduce the single idempotent source-drift issue payload."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ISSUE_TITLE = "Source attestation drift"
NON_MATCH_STATUSES = ("changed", "blocked", "transient", "unsupported")


class IssueContractError(ValueError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _display(value: Any) -> str:
    try:
        return _canonical(value)
    except (TypeError, ValueError):
        return repr(value)


def report_body_fingerprint(report: dict[str, Any]) -> str:
    results = report.get("results")
    if not isinstance(results, list):
        raise IssueContractError("report.results must be an array")
    normalized_results = []
    fields = (
        "status",
        "id",
        "source",
        "requestUrl",
        "path",
        "actual",
        "expected",
        "fix",
        "contextFingerprint",
    )
    for result in results:
        if not isinstance(result, dict):
            raise IssueContractError("every report result must be an object")
        normalized_results.append(
            {field: result.get(field) for field in fields}
        )
    normalized_results.sort(
        key=lambda item: (
            str(item["status"]),
            str(item["id"]),
            str(item["source"]),
            str(item["requestUrl"]),
            str(item["path"]),
            _display(item["actual"]),
            _display(item["expected"]),
        )
    )
    substantive = {
        "audit": report.get("audit", {}),
        "results": normalized_results,
    }
    return hashlib.sha256(_canonical(substantive).encode("utf-8")).hexdigest()


def render_issue_body(report: dict[str, Any]) -> str:
    results = report.get("results")
    if not isinstance(results, list):
        raise IssueContractError("report.results must be an array")
    grouped = {status: [] for status in NON_MATCH_STATUSES}
    for result in results:
        if not isinstance(result, dict):
            raise IssueContractError("every report result must be an object")
        status = result.get("status")
        if status in grouped:
            grouped[status].append(result)
        elif status != "match":
            raise IssueContractError(f"unknown result status {status!r}")
    audit = report.get("audit", {})
    lines = [
        "# Source attestation drift",
        "",
        f"Generated: `{report.get('generatedAt', '<unknown>')}`",
        f"Mode: `{report.get('mode', '<unknown>')}`",
        f"Audit: `{_display(audit)}`",
    ]
    descriptions = {
        "changed": (
            "Changed — the official response value, unit, structure, or "
            "cardinality differs from the reviewed expectation."
        ),
        "blocked": (
            "Blocked — authentication, bot protection, or access control "
            "prevented verification; this does not assert a policy value change."
        ),
        "transient": (
            "Transient — rate limiting, server failure, timeout, DNS, or TLS "
            "prevented verification; retry before factual review."
        ),
        "unsupported": (
            "Unsupported — the safe extractor or media boundary cannot verify "
            "this response; this does not assert a policy value change."
        ),
    }
    for status in NON_MATCH_STATUSES:
        items = sorted(
            grouped[status],
            key=lambda item: (
                str(item.get("id", "")),
                str(item.get("path", "")),
            ),
        )
        if not items:
            continue
        lines.extend(["", f"## {descriptions[status]}", ""])
        for item in items:
            lines.extend(
                [
                    f"- `{item.get('id', '<unknown>')}` "
                    f"source `{item.get('source', '<none>')}`; "
                    f"request `{item.get('requestUrl', item.get('source', '<none>'))}`; "
                    f"path `{item.get('path', '/')}`",
                    f"  - Actual: `{_display(item.get('actual'))}`",
                    f"  - Expected: `{_display(item.get('expected'))}`",
                    f"  - Context: `{item.get('contextFingerprint', '<none>')}`",
                    f"  - Fix: {item.get('fix', 'Review the source.')}",
                ]
            )
    if not any(grouped.values()):
        lines.extend(
            [
                "",
                "All reviewed source attestations match. The scheduled drift "
                "issue can be closed.",
            ]
        )
    unsigned = "\n".join(lines).rstrip() + "\n"
    fingerprint = report_body_fingerprint(report)
    return unsigned + f"\n<!-- source-attestation-report:{fingerprint} -->\n"


def _body_fingerprint(body: Any) -> str | None:
    if not isinstance(body, str):
        return None
    matches = re.findall(
        r"<!-- source-attestation-report:([0-9a-f]{64}) -->", body
    )
    return matches[0] if len(matches) == 1 else None


def reduce_issue(
    report: dict[str, Any], existing_issues: list[dict[str, Any]]
) -> dict[str, Any]:
    if not isinstance(existing_issues, list):
        raise IssueContractError("existing issues must be an array")
    exact = [
        issue for issue in existing_issues
        if isinstance(issue, dict) and issue.get("title") == ISSUE_TITLE
    ]
    if len(exact) > 1:
        raise IssueContractError("multiple exact-title drift issues exist")
    body = render_issue_body(report)
    body_fingerprint = report_body_fingerprint(report)
    has_non_match = any(
        isinstance(result, dict)
        and result.get("status") in NON_MATCH_STATUSES
        for result in report.get("results", [])
    )
    issue = exact[0] if exact else None
    if has_non_match:
        if issue is None:
            action = "create"
        elif issue.get("state") == "closed":
            action = "reopen"
        elif _body_fingerprint(issue.get("body")) == body_fingerprint:
            action = "noop"
        else:
            action = "update"
    elif issue is not None and issue.get("state") == "open":
        action = "close"
    else:
        action = "noop"
    return {
        "schemaVersion": 1,
        "title": ISSUE_TITLE,
        "action": action,
        "issueNumber": issue.get("number") if issue is not None else None,
        "body": body,
        "bodyFingerprint": body_fingerprint,
    }


def _load(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise IssueContractError(f"{path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render the idempotent source-attestation drift issue payload."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--existing", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = _load(args.report)
        existing = _load(args.existing) if args.existing else []
        payload = reduce_issue(report, existing)
    except IssueContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
