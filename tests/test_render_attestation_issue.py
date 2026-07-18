from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from render_attestation_issue import (  # noqa: E402
    ISSUE_TITLE,
    IssueContractError,
    reduce_issue,
    render_issue_body,
    report_body_fingerprint,
)


def result(status: str, attestation_id: str = "source-one") -> dict[str, object]:
    return {
        "id": attestation_id,
        "source": "https://www.canada.ca/citation",
        "requestUrl": "https://www.canada.ca/citation",
        "path": "ca-tax/value",
        "status": status,
        "actual": {"message": status},
        "expected": {"value": 1},
        "contextFingerprint": "sha256:" + "1" * 64,
        "fix": "Follow the status-specific operating procedure.",
    }


def report(*statuses: str) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "mode": "live",
        "generatedAt": "2026-07-19T00:00:00Z",
        "audit": {
            "attestationCount": len(statuses),
            "claimCount": 0,
            "reviewedLeafCount": len(statuses),
            "liveCapableCount": len(statuses),
        },
        "results": [
            result(status, f"source-{index}")
            for index, status in enumerate(statuses, 1)
        ],
    }


class AttestationIssueTests(unittest.TestCase):
    def test_nonmatch_sections_distinguish_policy_change_from_access(self) -> None:
        body = render_issue_body(
            report("changed", "blocked", "transient", "unsupported")
        )
        self.assertIn("Changed —", body)
        self.assertIn("does not assert a policy value change", body)
        self.assertIn("retry before factual review", body)
        self.assertIn("safe extractor", body)

    def test_create_update_reopen_close_and_noop(self) -> None:
        drift = report("changed")
        created = reduce_issue(drift, [])
        self.assertEqual(created["action"], "create")
        open_issue = {
            "number": 7,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": created["body"],
        }
        self.assertEqual(reduce_issue(drift, [open_issue])["action"], "noop")
        changed_report = report("blocked")
        self.assertEqual(
            reduce_issue(changed_report, [open_issue])["action"], "update"
        )
        closed_issue = dict(open_issue, state="closed")
        self.assertEqual(
            reduce_issue(changed_report, [closed_issue])["action"], "reopen"
        )
        matched = report("match")
        self.assertEqual(reduce_issue(matched, [open_issue])["action"], "close")
        self.assertEqual(
            reduce_issue(matched, [closed_issue])["action"], "noop"
        )

    def test_duplicate_exact_title_fails_closed(self) -> None:
        issue = {"number": 1, "title": ISSUE_TITLE, "state": "open", "body": ""}
        with self.assertRaises(IssueContractError):
            reduce_issue(report("changed"), [issue, dict(issue, number=2)])

    def test_render_is_deterministic_despite_result_order(self) -> None:
        first = report("changed", "blocked")
        second = dict(
            first,
            generatedAt="2026-07-26T00:00:00Z",
            results=list(reversed(first["results"])),
        )
        self.assertEqual(
            report_body_fingerprint(first),
            report_body_fingerprint(second),
        )
        existing = {
            "number": 8,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": render_issue_body(first),
        }
        reduced = reduce_issue(second, [existing])
        self.assertEqual(reduced["action"], "noop")
        self.assertEqual(
            reduced["bodyFingerprint"], report_body_fingerprint(first)
        )
        self.assertNotEqual(render_issue_body(first), render_issue_body(second))


if __name__ == "__main__":
    unittest.main()
