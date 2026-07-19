from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import render_employer_issue as reducer  # noqa: E402


def result(
    url: str,
    status: str,
    *,
    actual: str | None = None,
) -> dict[str, object]:
    return {
        "url": url,
        "ownerIds": ["au-reviewed-employer"],
        "roles": ["source"],
        "status": status,
        "httpStatus": 200 if status == "match" else 503,
        "finalUrl": url,
        "actual": actual or (
            "HTTP 200 non-empty response" if status == "match" else "HTTP 503"
        ),
        "expected": "reachable reviewed HTTPS representation",
        "fix": (
            "No action required."
            if status == "match"
            else "Retry or review the official link."
        ),
    }


def report(
    results: list[dict[str, object]],
    *,
    generated_at: str = "2026-07-19",
) -> dict[str, object]:
    counts = {status: 0 for status in reducer.STATUSES}
    for item in results:
        counts[str(item["status"])] += 1
    return {
        "schemaVersion": 1,
        "generatedAt": generated_at,
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


class EmployerIssueReducerTests(unittest.TestCase):
    def issue(
        self,
        source_report: dict[str, object],
        *,
        number: int = 10,
        state: str = "OPEN",
    ) -> dict[str, object]:
        rendered = reducer.render_issue_body(source_report)
        return {
            "number": number,
            "title": reducer.ISSUE_TITLE,
            "state": state,
            "body": rendered["body"],
        }

    def test_create_update_reopen_close_and_noop(self) -> None:
        changed = report([
            result("https://example.gov.au/source", "changed")
        ])
        created = reducer.reduce_issue(changed, [])
        self.assertEqual(created["action"], "create")
        current = self.issue(changed)
        self.assertEqual(
            reducer.reduce_issue(changed, [current])["action"], "noop"
        )

        updated_report = report([
            result("https://example.gov.au/source", "blocked")
        ])
        self.assertEqual(
            reducer.reduce_issue(updated_report, [current])["action"],
            "update",
        )
        closed = self.issue(changed, state="CLOSED")
        self.assertEqual(
            reducer.reduce_issue(updated_report, [closed])["action"],
            "reopen",
        )

        green = report([
            result("https://example.gov.au/source", "match")
        ])
        self.assertEqual(
            reducer.reduce_issue(green, [current])["action"], "close"
        )
        self.assertEqual(
            reducer.reduce_issue(green, [])["action"], "noop"
        )

    def test_order_and_generated_time_are_idempotent(self) -> None:
        first = report([
            result("https://example.gov.au/b", "transient"),
            result("https://example.gov.au/a", "blocked"),
        ])
        second = report(
            list(reversed(first["results"])),  # type: ignore[arg-type]
            generated_at="2026-07-20",
        )
        self.assertEqual(
            reducer.body_fingerprint(first),
            reducer.body_fingerprint(second),
        )
        existing = self.issue(first)
        self.assertEqual(
            reducer.reduce_issue(second, [existing])["action"], "noop"
        )

    def test_statuses_are_distinct_and_markdown_is_escaped(self) -> None:
        values = [
            result(
                f"https://example.gov.au/{status}",
                status,
                actual=f"{status} | value `safe`",
            )
            for status in ("changed", "blocked", "transient", "unsupported")
        ]
        body = reducer.render_issue_body(report(values))["body"]
        for status in ("changed", "blocked", "transient", "unsupported"):
            self.assertIn(status, body)
        self.assertIn(r"\|", body)
        self.assertIn(r"\`safe\`", body)
        self.assertIn("No response body", body)

    def test_duplicate_issue_and_malformed_marker_fail_closed(self) -> None:
        drift = report([
            result("https://example.gov.au/source", "changed")
        ])
        current = self.issue(drift)
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(drift, [current, deepcopy(current)])

        malformed = deepcopy(current)
        malformed["body"] = "missing marker"
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(drift, [malformed])
        green = report([
            result("https://example.gov.au/source", "match")
        ])
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(green, [malformed])

        duplicated_marker = deepcopy(current)
        duplicated_marker["body"] += current["body"]
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(drift, [duplicated_marker])

    def test_malformed_or_duplicate_report_fails_closed(self) -> None:
        drift = report([
            result("https://example.gov.au/source", "changed")
        ])
        drift["audit"]["changed"] = 0  # type: ignore[index]
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(drift, [])

        duplicated = report([
            result("https://example.gov.au/source", "changed"),
            result("https://example.gov.au/source", "changed"),
        ])
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(duplicated, [])

        malformed = report([
            result("https://example.gov.au/source", "changed")
        ])
        malformed["results"][0]["ownerIds"] = [{"nested": True}]  # type: ignore[index]
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(malformed, [])

        malformed = report([
            result("https://example.gov.au/source", "changed")
        ])
        malformed["results"][0]["status"] = {"nested": True}  # type: ignore[index]
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(malformed, [])

        malformed = report([
            result("https://example.gov.au/source", "changed")
        ])
        malformed["results"][0]["httpStatus"] = "503"  # type: ignore[index]
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(malformed, [])

        malformed = report([
            result("https://example.gov.au/source", "changed")
        ])
        malformed["generatedAt"] = "2026-02-30"
        with self.assertRaises(reducer.ReducerError):
            reducer.reduce_issue(malformed, [])

    def test_payload_contains_only_bounded_public_link_metadata(self) -> None:
        drift = report([
            result("https://example.gov.au/source", "transient")
        ])
        payload = reducer.reduce_issue(drift, [])
        serialized = json.dumps(payload)
        self.assertIn("https://example.gov.au/source", serialized)
        self.assertNotIn("responseBody", serialized)
        self.assertNotIn("secret-token-value", serialized.casefold())


if __name__ == "__main__":
    unittest.main()
