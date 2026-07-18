#!/usr/bin/env python3
"""Render and reduce the single idempotent source-drift issue payload."""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime
import hashlib
import html
import json
from pathlib import Path
import re
import sys
from typing import Any


ISSUE_TITLE = "Source attestation drift"
NON_MATCH_STATUSES = ("changed", "blocked", "transient", "unsupported")
REQUEST_STATUSES = frozenset(
    {"ready", "transient", "blocked", "changed", "unsupported"}
)
LATENCY_BUCKETS = frozenset(
    {
        "offline",
        "lt250ms",
        "250ms-999ms",
        "1s-4.999s",
        "5s-14.999s",
        "15s-plus",
    }
)
TREND_VERSION = 1
TREND_PREFIX = "<!-- source-attestation-trend:v1:"
TREND_SUFFIX = " -->"
MAX_TREND_REQUESTS = 128
MAX_TREND_EVENTS = 8
MAX_TREND_DECODED_BYTES = 48 * 1024
MAX_TREND_ENCODED_CHARS = 64 * 1024
REQUEST_KEY_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
OBSERVATION_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z"
)
TREND_ROOT_FIELDS = frozenset({"version", "requests"})
TREND_REQUEST_FIELDS = frozenset(
    {
        "consecutiveTransient",
        "firstSeen",
        "lastSeen",
        "recoveredAt",
        "lastStatus",
        "lastObservationId",
        "events",
    }
)
TREND_EVENT_FIELDS = frozenset(
    {"observationId", "status", "observedAt"}
)


class IssueContractError(ValueError):
    pass


def _empty_trend_state() -> dict[str, Any]:
    return {"version": TREND_VERSION, "requests": {}}


def _timestamp(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 40
        or not TIMESTAMP_PATTERN.fullmatch(value)
    ):
        raise IssueContractError(f"{field} must be a bounded UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise IssueContractError(f"{field} is not an ISO timestamp") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise IssueContractError(f"{field} must be UTC")
    return value


def _timestamp_value(value: Any, field: str) -> datetime:
    validated = _timestamp(value, field)
    return datetime.fromisoformat(validated[:-1] + "+00:00")


def _observation_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not OBSERVATION_ID_PATTERN.fullmatch(value):
        raise IssueContractError(
            f"{field} must match [A-Za-z0-9._:-]{{1,128}}"
        )
    return value


def _validate_trend_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict) or set(state) != TREND_ROOT_FIELDS:
        raise IssueContractError("trend marker root has unsupported fields")
    if state["version"] != TREND_VERSION:
        raise IssueContractError("trend marker version is unsupported")
    requests = state["requests"]
    if not isinstance(requests, dict) or len(requests) > MAX_TREND_REQUESTS:
        raise IssueContractError("trend request state is not a bounded object")
    for request_key, item in requests.items():
        if (
            not isinstance(request_key, str)
            or not REQUEST_KEY_PATTERN.fullmatch(request_key)
            or not isinstance(item, dict)
            or set(item) != TREND_REQUEST_FIELDS
        ):
            raise IssueContractError("trend request entry is malformed")
        streak = item["consecutiveTransient"]
        if (
            not isinstance(streak, int)
            or isinstance(streak, bool)
            or not 0 <= streak <= 1_000_000
        ):
            raise IssueContractError("transient streak is out of bounds")
        first_seen = _timestamp_value(item["firstSeen"], "firstSeen")
        last_seen = _timestamp_value(item["lastSeen"], "lastSeen")
        if first_seen > last_seen:
            raise IssueContractError("trend firstSeen exceeds lastSeen")
        recovered_at = None
        if item["recoveredAt"] is not None:
            recovered_at = _timestamp_value(
                item["recoveredAt"], "recoveredAt"
            )
        if item["lastStatus"] not in REQUEST_STATUSES:
            raise IssueContractError("trend lastStatus is unsupported")
        _observation_id(item["lastObservationId"], "lastObservationId")
        events = item["events"]
        if not isinstance(events, list) or not 1 <= len(events) <= MAX_TREND_EVENTS:
            raise IssueContractError("trend events are not bounded")
        previous_event_at: datetime | None = None
        seen_observations: set[str] = set()
        for event in events:
            if not isinstance(event, dict) or set(event) != TREND_EVENT_FIELDS:
                raise IssueContractError("trend event is malformed")
            _observation_id(event["observationId"], "event observationId")
            if event["observationId"] in seen_observations:
                raise IssueContractError(
                    "trend event observationId is duplicated"
                )
            seen_observations.add(event["observationId"])
            if event["status"] not in REQUEST_STATUSES:
                raise IssueContractError("trend event status is unsupported")
            event_at = _timestamp_value(
                event["observedAt"], "event observedAt"
            )
            if previous_event_at is not None and event_at < previous_event_at:
                raise IssueContractError(
                    "trend events are not chronological"
                )
            previous_event_at = event_at
        if events[-1]["observationId"] != item["lastObservationId"]:
            raise IssueContractError("trend last observation and event differ")
        if events[-1]["status"] != item["lastStatus"]:
            raise IssueContractError("trend last status and event differ")
        if previous_event_at != last_seen:
            raise IssueContractError(
                "trend last event timestamp differs from lastSeen"
            )
        if streak > 0 and item["lastStatus"] != "transient":
            raise IssueContractError("active transient streak has non-transient status")
        if streak > 0 and recovered_at is not None:
            raise IssueContractError("active transient trend has recoveredAt")
        if streak == 0:
            if recovered_at is None:
                raise IssueContractError("recovered trend entry lacks recoveredAt")
            if item["lastStatus"] == "transient":
                raise IssueContractError(
                    "recovered trend has transient lastStatus"
                )
            if recovered_at != last_seen:
                raise IssueContractError(
                    "trend recoveredAt differs from lastSeen"
                )
    canonical = _canonical(state).encode("utf-8")
    if len(canonical) > MAX_TREND_DECODED_BYTES:
        raise IssueContractError("trend state exceeds decoded size limit")
    return state


def _encode_trend_state(state: dict[str, Any]) -> str:
    _validate_trend_state(state)
    raw = _canonical(state).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if len(encoded) > MAX_TREND_ENCODED_CHARS:
        raise IssueContractError("trend marker exceeds encoded size limit")
    return f"{TREND_PREFIX}{encoded}{TREND_SUFFIX}"


def _decode_trend_marker(body: Any) -> dict[str, Any]:
    if not isinstance(body, str):
        return _empty_trend_state()
    prefix_count = body.count("<!-- source-attestation-trend:")
    pattern = re.compile(
        r"<!-- source-attestation-trend:v1:([A-Za-z0-9_-]+) -->"
    )
    matches = pattern.findall(body)
    if prefix_count == 0:
        return _empty_trend_state()
    if prefix_count != 1 or len(matches) != 1:
        raise IssueContractError("trend marker is malformed or duplicated")
    encoded = matches[0]
    if len(encoded) > MAX_TREND_ENCODED_CHARS:
        raise IssueContractError("trend marker exceeds encoded size limit")
    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded + padding)
    except Exception as exc:
        raise IssueContractError("trend marker is not valid base64url") from exc
    if len(raw) > MAX_TREND_DECODED_BYTES:
        raise IssueContractError("trend marker exceeds decoded size limit")
    try:
        state = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise IssueContractError("trend marker JSON is invalid") from exc
    return _validate_trend_state(state)


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


def _markdown_code(value: Any) -> str:
    escaped = html.escape(str(value), quote=True)
    escaped = escaped.replace("|", "&#124;").replace("`", "&#96;")
    escaped = escaped.replace("\r", " ").replace("\n", " ")
    return f"<code>{escaped}</code>"


def _normalized_request_audit(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    request_audit = report.get("requestAudit")
    if request_audit is None:
        return []
    expected_root = {
        "schemaVersion",
        "requestCount",
        "totalAttemptCount",
        "retriedRequestCount",
        "requests",
    }
    if not isinstance(request_audit, dict) or set(request_audit) != expected_root:
        raise IssueContractError("requestAudit root is malformed")
    if request_audit["schemaVersion"] != 1:
        raise IssueContractError("requestAudit version is unsupported")
    requests = request_audit["requests"]
    if not isinstance(requests, list) or len(requests) > MAX_TREND_REQUESTS:
        raise IssueContractError("requestAudit requests are not bounded")
    if (
        not isinstance(request_audit["requestCount"], int)
        or isinstance(request_audit["requestCount"], bool)
        or request_audit["requestCount"] != len(requests)
    ):
        raise IssueContractError("requestAudit requestCount mismatch")
    expected_fields = {
        "requestKey",
        "requestUrl",
        "method",
        "attemptCount",
        "finalStatus",
        "latencyBucket",
        "attempts",
    }
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    total_attempts = 0
    retried = 0
    for item in requests:
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise IssueContractError("requestAudit entry is malformed")
        request_key = item["requestKey"]
        if (
            not isinstance(request_key, str)
            or not REQUEST_KEY_PATTERN.fullmatch(request_key)
            or request_key in seen
        ):
            raise IssueContractError("requestAudit key is invalid or duplicated")
        seen.add(request_key)
        if item["finalStatus"] not in REQUEST_STATUSES:
            raise IssueContractError("requestAudit finalStatus is unsupported")
        if (
            not isinstance(item["requestUrl"], str)
            or not 1 <= len(item["requestUrl"]) <= 2048
            or item["method"] not in {"GET", "POST"}
            or item["latencyBucket"] not in LATENCY_BUCKETS
        ):
            raise IssueContractError("requestAudit transport fields are malformed")
        attempts = item["attempts"]
        attempt_count = item["attemptCount"]
        if (
            not isinstance(attempt_count, int)
            or isinstance(attempt_count, bool)
            or not 1 <= attempt_count <= 4
            or not isinstance(attempts, list)
            or len(attempts) != attempt_count
        ):
            raise IssueContractError("requestAudit attempts are inconsistent")
        for index, attempt in enumerate(attempts, 1):
            if (
                not isinstance(attempt, dict)
                or set(attempt)
                != {"number", "status", "latencyBucket"}
                or attempt["number"] != index
                or attempt["status"] not in REQUEST_STATUSES
                or attempt["latencyBucket"] not in LATENCY_BUCKETS
            ):
                raise IssueContractError(
                    "requestAudit attempt history is malformed"
                )
        if attempts[-1]["status"] != item["finalStatus"]:
            raise IssueContractError(
                "requestAudit finalStatus differs from the last attempt"
            )
        total_attempts += attempt_count
        retried += attempt_count > 1
        normalized.append(
            {
                "requestKey": request_key,
                "requestUrl": item["requestUrl"],
                "method": item["method"],
                "finalStatus": item["finalStatus"],
                "attemptCount": attempt_count,
                "latencyBucket": item["latencyBucket"],
                "attempts": attempts,
            }
        )
    if (
        not isinstance(request_audit["totalAttemptCount"], int)
        or isinstance(request_audit["totalAttemptCount"], bool)
        or not isinstance(request_audit["retriedRequestCount"], int)
        or isinstance(request_audit["retriedRequestCount"], bool)
        or request_audit["totalAttemptCount"] != total_attempts
        or request_audit["retriedRequestCount"] != retried
    ):
        raise IssueContractError("requestAudit aggregate counts mismatch")
    return sorted(normalized, key=lambda item: item["requestKey"])


def _request_observations(
    report: dict[str, Any],
) -> tuple[str | None, str, list[dict[str, Any]]]:
    observations = _normalized_request_audit(report)
    if report.get("requestAudit") is None:
        return None, _timestamp(
            report.get("generatedAt"), "report generatedAt"
        ), []
    observation = report.get("observationId")
    if observation is None:
        observation = report_body_fingerprint(report)
    observation = _observation_id(observation, "report observationId")
    observed_at = _timestamp(report.get("generatedAt"), "report generatedAt")
    return observation, observed_at, observations


def _advance_trend_state(
    report: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    state = deepcopy(_validate_trend_state(previous))
    observation_id, observed_at, observations = _request_observations(report)
    if observation_id is None:
        return state
    requests = state["requests"]
    for observation in observations:
        request_key = observation["requestKey"]
        status = observation["finalStatus"]
        prior = requests.get(request_key)
        if (
            prior is not None
            and any(
                event["observationId"] == observation_id
                for event in prior["events"]
            )
        ):
            continue
        event = {
            "observationId": observation_id,
            "status": status,
            "observedAt": observed_at,
        }
        if status == "transient":
            if prior is not None and prior["lastStatus"] == "transient":
                streak = prior["consecutiveTransient"] + 1
                first_seen = prior["firstSeen"]
                events = prior["events"] + [event]
            else:
                streak = 1
                first_seen = observed_at
                events = [event]
            requests[request_key] = {
                "consecutiveTransient": streak,
                "firstSeen": first_seen,
                "lastSeen": observed_at,
                "recoveredAt": None,
                "lastStatus": "transient",
                "lastObservationId": observation_id,
                "events": events[-MAX_TREND_EVENTS:],
            }
        elif prior is not None and prior["lastStatus"] == "transient":
            requests[request_key] = {
                "consecutiveTransient": 0,
                "firstSeen": prior["firstSeen"],
                "lastSeen": observed_at,
                "recoveredAt": observed_at,
                "lastStatus": status,
                "lastObservationId": observation_id,
                "events": (prior["events"] + [event])[-MAX_TREND_EVENTS:],
            }
    if len(requests) > MAX_TREND_REQUESTS:
        raise IssueContractError("trend state exceeds request limit")
    return _validate_trend_state(state)


def report_body_fingerprint(
    report: dict[str, Any],
    trend_state: dict[str, Any] | None = None,
) -> str:
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
        "requests": [
            {
                "requestKey": item["requestKey"],
                "finalStatus": item["finalStatus"],
                "attemptCount": item["attemptCount"],
                "attemptStatuses": [
                    attempt["status"] for attempt in item["attempts"]
                ],
            }
            for item in _normalized_request_audit(report)
        ],
    }
    substantive["trend"] = _validate_trend_state(
        trend_state if trend_state is not None else _empty_trend_state()
    )
    return hashlib.sha256(_canonical(substantive).encode("utf-8")).hexdigest()


def render_issue_body(
    report: dict[str, Any],
    trend_state: dict[str, Any] | None = None,
) -> str:
    trend = _validate_trend_state(
        trend_state if trend_state is not None else _empty_trend_state()
    )
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
            "cardinality differs from the reviewed expectation. SLA: factual "
            "review starts immediately."
        ),
        "blocked": (
            "Blocked — authentication, bot protection, or access control "
            "prevented verification; this does not assert a policy value "
            "change. SLA: access review starts immediately."
        ),
        "transient": (
            "Transient — rate limiting, server failure, timeout, DNS, or TLS "
            "prevented verification; retry before factual review. SLA: one "
            "observation waits for the next schedule, two trigger endpoint "
            "investigation, and three or more require manual source review."
        ),
        "unsupported": (
            "Unsupported — the safe extractor or media boundary cannot verify "
            "this response; this does not assert a policy value change. SLA: "
            "extractor review starts immediately."
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
    _observation, _observed_at, current_requests = _request_observations(
        report
    )
    if current_requests:
        lines.extend(
            [
                "",
                "## Current request telemetry",
                "",
                "| Request | Endpoint | Final | Attempts | Latency | Attempt statuses |",
                "| --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for item in current_requests:
            statuses = " → ".join(
                str(attempt.get("status", "?"))
                for attempt in item["attempts"]
            )
            lines.append(
                f"| `{item['requestKey'][:19]}…` | "
                f"{_markdown_code(item['method'] + ' ' + item['requestUrl'])} | "
                f"{item['finalStatus']} | "
                f"{item['attemptCount']} | {item['latencyBucket']} | "
                f"{statuses} |"
            )
    current_by_key = {
        item["requestKey"]: item for item in current_requests
    }

    def endpoint_suffix(request_key: str) -> str:
        current = current_by_key.get(request_key)
        if current is None:
            return ""
        return (
            "; endpoint="
            + _markdown_code(
                current["method"] + " " + current["requestUrl"]
            )
        )

    active = [
        (key, item)
        for key, item in trend["requests"].items()
        if item["consecutiveTransient"] > 0
    ]
    recovered = [
        (key, item)
        for key, item in trend["requests"].items()
        if item["consecutiveTransient"] == 0
    ]
    if active:
        lines.extend(["", "## Transient trend", ""])
        for request_key, item in sorted(active):
            streak = item["consecutiveTransient"]
            if streak == 1:
                sla = "observe until the next scheduled run"
            elif streak == 2:
                sla = "investigate the endpoint and network path"
            else:
                sla = "perform manual official-source review"
            lines.append(
                f"- `{request_key[:19]}…`: consecutive={streak}, "
                f"firstSeen=`{item['firstSeen']}`, "
                f"lastSeen=`{item['lastSeen']}`"
                f"{endpoint_suffix(request_key)}; SLA: {sla}."
            )
    if recovered:
        lines.extend(["", "## Recovered request transport", ""])
        for request_key, item in sorted(recovered):
            lines.append(
                f"- `{request_key[:19]}…`: recoveredAt="
                f"`{item['recoveredAt']}`, final={item['lastStatus']}"
                f"{endpoint_suffix(request_key)}."
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
    fingerprint = report_body_fingerprint(report, trend)
    return (
        unsigned
        + f"\n<!-- source-attestation-report:{fingerprint} -->\n"
        + _encode_trend_state(trend)
        + "\n"
    )


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
    issue = exact[0] if exact else None
    previous_trend = _decode_trend_marker(
        issue.get("body") if issue is not None else ""
    )
    trend_state = _advance_trend_state(report, previous_trend)
    body = render_issue_body(report, trend_state)
    body_fingerprint = report_body_fingerprint(report, trend_state)
    has_non_match = any(
        isinstance(result, dict)
        and result.get("status") in NON_MATCH_STATUSES
        for result in report.get("results", [])
    )
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
        "trendState": trend_state,
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
