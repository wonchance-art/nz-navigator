from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import hashlib
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
    _validate_trend_state,
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


def request_key(seed: str = "one") -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def report_v2(
    status: str,
    observation_id: str,
    generated_at: str,
    *,
    final_status: str | None = None,
    latency: str = "lt250ms",
    duplicate_results: bool = False,
) -> dict[str, object]:
    request_status = final_status or (
        "ready" if status == "match" else status
    )
    item = result(status)
    item.update({
        "requestKey": request_key(),
        "attemptCount": 1,
        "requestFinalStatus": request_status,
        "latencyBucket": latency,
    })
    results = [item, dict(item, id="source-two")] if duplicate_results else [item]
    return {
        "schemaVersion": 2,
        "mode": "live",
        "generatedAt": generated_at,
        "observationId": observation_id,
        "retryPolicy": {
            "maxAttempts": 3,
            "backoffMs": 500,
            "timeoutSeconds": 15,
        },
        "audit": {
            "attestationCount": len(results),
            "claimCount": 0,
            "reviewedLeafCount": len(results),
            "liveCapableCount": len(results),
            "liveExtractableCount": len(results),
            "fixtureOnlyCount": 0,
        },
        "requestAudit": {
            "schemaVersion": 1,
            "requestCount": 1,
            "totalAttemptCount": 1,
            "retriedRequestCount": 0,
            "requests": [{
                "requestKey": request_key(),
                "requestUrl": "https://www.canada.ca/citation",
                "method": "GET",
                "attemptCount": 1,
                "finalStatus": request_status,
                "latencyBucket": latency,
                "attempts": [{
                    "number": 1,
                    "status": request_status,
                    "latencyBucket": latency,
                }],
            }],
        },
        "results": results,
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

    def test_fixture_only_reason_and_manual_sla_render_in_issue(self) -> None:
        fixture_only = report("unsupported")
        fixture_only["results"][0]["actual"] = {
            "mode": "fixture-only",
            "reason": "Compressed official PDF representation.",
            "manualReviewDays": 7,
        }
        fixture_only["results"][0]["fix"] = (
            "Perform manual official-source review within 7 day(s)."
        )
        body = render_issue_body(fixture_only)
        self.assertIn("Compressed official PDF representation", body)
        self.assertIn("within 7 day(s)", body)

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

    def test_transient_trend_one_two_recovery_and_duplicate_replay(self) -> None:
        first = report_v2(
            "transient", "run.1", "2026-07-19T00:00:00Z"
        )
        created = reduce_issue(first, [])
        self.assertEqual(created["action"], "create")
        state = created["trendState"]["requests"][request_key()]
        self.assertEqual(state["consecutiveTransient"], 1)
        self.assertIn(
            "<code>GET https://www.canada.ca/citation</code>",
            created["body"],
        )
        issue = {
            "number": 10,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": created["body"],
        }
        replayed = reduce_issue(first, [issue])
        self.assertEqual(replayed["action"], "noop")
        self.assertEqual(
            replayed["trendState"]["requests"][request_key()][
                "consecutiveTransient"
            ],
            1,
        )

        second = report_v2(
            "transient", "run.2", "2026-07-26T00:00:00Z"
        )
        updated = reduce_issue(second, [issue])
        self.assertEqual(updated["action"], "update")
        second_state = updated["trendState"]["requests"][request_key()]
        self.assertEqual(second_state["consecutiveTransient"], 2)
        self.assertEqual(second_state["firstSeen"], "2026-07-19T00:00:00Z")
        self.assertEqual(second_state["lastSeen"], "2026-07-26T00:00:00Z")
        issue["body"] = updated["body"]
        older_replay = reduce_issue(first, [issue])
        self.assertEqual(
            older_replay["trendState"]["requests"][request_key()][
                "consecutiveTransient"
            ],
            2,
        )

        recovered_report = report_v2(
            "match",
            "run.3",
            "2026-08-02T00:00:00Z",
            final_status="ready",
        )
        recovered = reduce_issue(recovered_report, [issue])
        self.assertEqual(recovered["action"], "close")
        recovered_state = recovered["trendState"]["requests"][request_key()]
        self.assertEqual(recovered_state["consecutiveTransient"], 0)
        self.assertEqual(recovered_state["recoveredAt"], "2026-08-02T00:00:00Z")
        self.assertIn("Recovered request transport", recovered["body"])
        self.assertIn(
            "endpoint=<code>GET https://www.canada.ca/citation</code>",
            recovered["body"],
        )

    def test_request_endpoint_is_markdown_table_safe(self) -> None:
        unsafe = report_v2(
            "transient", "run.safe", "2026-07-19T00:00:00Z"
        )
        unsafe["requestAudit"]["requests"][0][
            "requestUrl"
        ] = "https://www.canada.ca/a|b`c?<tag>"
        body = reduce_issue(unsafe, [])["body"]
        self.assertIn(
            (
                "<code>GET https://www.canada.ca/a&#124;b&#96;c?"
                "&lt;tag&gt;</code>"
            ),
            body,
        )
        self.assertNotIn("a|b`c?<tag>", body)

    def test_shared_request_counts_once_and_order_latency_are_idempotent(self) -> None:
        first = report_v2(
            "transient",
            "run.shared",
            "2026-07-19T00:00:00Z",
            duplicate_results=True,
        )
        created = reduce_issue(first, [])
        state = created["trendState"]["requests"][request_key()]
        self.assertEqual(state["consecutiveTransient"], 1)
        existing = {
            "number": 11,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": created["body"],
        }
        reordered = report_v2(
            "transient",
            "run.shared",
            "2026-07-26T00:00:00Z",
            latency="1s-4.999s",
            duplicate_results=True,
        )
        reordered["results"] = list(reversed(reordered["results"]))
        reduced = reduce_issue(reordered, [existing])
        self.assertEqual(reduced["action"], "noop")
        self.assertEqual(
            reduced["trendState"]["requests"][request_key()][
                "consecutiveTransient"
            ],
            1,
        )
        self.assertEqual(
            reduced["bodyFingerprint"], created["bodyFingerprint"]
        )

    def test_attempt_status_sequence_is_substantive_but_latency_is_not(self) -> None:
        single = report_v2(
            "changed",
            "run.sequence",
            "2026-07-19T00:00:00Z",
            final_status="ready",
        )
        created = reduce_issue(single, [])
        existing = {
            "number": 15,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": created["body"],
        }
        retried = deepcopy(single)
        request = retried["requestAudit"]["requests"][0]
        request["attemptCount"] = 2
        request["attempts"] = [
            {
                "number": 1,
                "status": "transient",
                "latencyBucket": "lt250ms",
            },
            {
                "number": 2,
                "status": "ready",
                "latencyBucket": "250ms-999ms",
            },
        ]
        request["latencyBucket"] = "250ms-999ms"
        retried["requestAudit"]["totalAttemptCount"] = 2
        retried["requestAudit"]["retriedRequestCount"] = 1
        retried["results"][0]["attemptCount"] = 2
        retried["results"][0]["latencyBucket"] = "250ms-999ms"
        self.assertNotEqual(
            report_body_fingerprint(single),
            report_body_fingerprint(retried),
        )
        self.assertEqual(
            reduce_issue(retried, [existing])["action"], "update"
        )
        latency_only = deepcopy(single)
        latency_only["requestAudit"]["requests"][0][
            "latencyBucket"
        ] = "5s-14.999s"
        latency_only["requestAudit"]["requests"][0]["attempts"][0][
            "latencyBucket"
        ] = "5s-14.999s"
        latency_only["results"][0]["latencyBucket"] = "5s-14.999s"
        self.assertEqual(
            report_body_fingerprint(single),
            report_body_fingerprint(latency_only),
        )
        self.assertEqual(
            reduce_issue(latency_only, [existing])["action"], "noop"
        )

    def test_match_context_is_non_substantive_but_changed_context_is_not(
        self,
    ) -> None:
        first = report("changed", "match")
        created = reduce_issue(first, [])
        existing = {
            "number": 17,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": created["body"],
        }
        match_footer_changed = deepcopy(first)
        match_footer_changed["results"][1][
            "contextFingerprint"
        ] = "sha256:" + "2" * 64
        self.assertEqual(
            report_body_fingerprint(first),
            report_body_fingerprint(match_footer_changed),
        )
        reduced = reduce_issue(match_footer_changed, [existing])
        self.assertEqual(reduced["action"], "noop")
        self.assertEqual(
            reduced["bodyFingerprint"], created["bodyFingerprint"]
        )

        changed_context = deepcopy(first)
        changed_context["results"][0][
            "contextFingerprint"
        ] = "sha256:" + "3" * 64
        self.assertNotEqual(
            report_body_fingerprint(first),
            report_body_fingerprint(changed_context),
        )
        self.assertEqual(
            reduce_issue(changed_context, [existing])["action"], "update"
        )

    def test_malformed_duplicate_and_oversize_trend_markers_fail_closed(self) -> None:
        bodies = [
            "<!-- source-attestation-trend:v1:not+base64 -->",
            (
                "<!-- source-attestation-trend:v1:e30 -->\n"
                "<!-- source-attestation-trend:v1:e30 -->"
            ),
            (
                "<!-- source-attestation-trend:v1:"
                + "A" * (64 * 1024 + 1)
                + " -->"
            ),
        ]
        for body in bodies:
            existing = {
                "number": 12,
                "title": ISSUE_TITLE,
                "state": "open",
                "body": body,
            }
            with self.subTest(body=body[:60]), self.assertRaises(
                IssueContractError
            ):
                reduce_issue(
                    report_v2(
                        "transient",
                        "run.bad",
                        "2026-07-19T00:00:00Z",
                    ),
                    [existing],
                )

    def test_malformed_request_audit_fails_closed(self) -> None:
        base = report_v2(
            "transient", "run.audit", "2026-07-19T00:00:00Z"
        )
        mutations = []
        wrong_final = report_v2(
            "transient", "run.audit", "2026-07-19T00:00:00Z"
        )
        wrong_final["requestAudit"]["requests"][0]["finalStatus"] = "ready"
        mutations.append(wrong_final)
        bad_attempt = report_v2(
            "transient", "run.audit", "2026-07-19T00:00:00Z"
        )
        bad_attempt["requestAudit"]["requests"][0]["attempts"][0][
            "latencyBucket"
        ] = "secret-body"
        mutations.append(bad_attempt)
        duplicate = report_v2(
            "transient", "run.audit", "2026-07-19T00:00:00Z"
        )
        duplicate_item = dict(
            duplicate["requestAudit"]["requests"][0]
        )
        duplicate["requestAudit"]["requests"].append(duplicate_item)
        duplicate["requestAudit"]["requestCount"] = 2
        duplicate["requestAudit"]["totalAttemptCount"] = 2
        mutations.append(duplicate)
        extra_field = report_v2(
            "transient", "run.audit", "2026-07-19T00:00:00Z"
        )
        extra_field["requestAudit"]["requests"][0]["attempts"][0][
            "body"
        ] = "forbidden"
        mutations.append(extra_field)
        self.assertEqual(base["requestAudit"]["requestCount"], 1)
        for mutation in mutations:
            with self.subTest(), self.assertRaises(IssueContractError):
                reduce_issue(mutation, [])

    def test_legacy_v1_report_is_one_observation_without_false_streak(self) -> None:
        legacy = report("transient")
        legacy_marker_body = (
            "Legacy source report\n"
            f"<!-- source-attestation-report:{report_body_fingerprint(legacy)} -->\n"
        )
        existing = {
            "number": 13,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": legacy_marker_body,
        }
        reduced = reduce_issue(legacy, [existing])
        self.assertEqual(reduced["trendState"]["requests"], {})
        self.assertNotIn("consecutive=", reduced["body"])

    def test_trend_history_is_bounded_to_eight_events(self) -> None:
        existing: list[dict[str, object]] = []
        latest = None
        for index in range(1, 11):
            current = report_v2(
                "transient",
                f"run.{index}",
                f"2026-08-{index:02d}T00:00:00Z",
            )
            latest = reduce_issue(current, existing)
            existing = [{
                "number": 14,
                "title": ISSUE_TITLE,
                "state": "open",
                "body": latest["body"],
            }]
        assert latest is not None
        state = latest["trendState"]["requests"][request_key()]
        self.assertEqual(state["consecutiveTransient"], 10)
        self.assertEqual(len(state["events"]), 8)
        self.assertEqual(state["events"][0]["observationId"], "run.3")
        self.assertEqual(state["events"][-1]["observationId"], "run.10")

    def test_trend_marker_cross_field_invariants_fail_closed(self) -> None:
        first = reduce_issue(
            report_v2(
                "transient", "run.1", "2026-07-19T00:00:00Z"
            ),
            [],
        )
        existing = [{
            "number": 16,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": first["body"],
        }]
        second = reduce_issue(
            report_v2(
                "transient", "run.2", "2026-07-26T00:00:00Z"
            ),
            existing,
        )
        active = second["trendState"]
        mutations = []
        bad_status = deepcopy(active)
        bad_status["requests"][request_key()]["events"][-1][
            "status"
        ] = "ready"
        mutations.append(bad_status)
        reversed_dates = deepcopy(active)
        reversed_dates["requests"][request_key()][
            "firstSeen"
        ] = "2026-08-01T00:00:00Z"
        mutations.append(reversed_dates)
        non_chronological = deepcopy(active)
        non_chronological["requests"][request_key()]["events"][-1][
            "observedAt"
        ] = "2026-07-18T00:00:00Z"
        mutations.append(non_chronological)
        last_seen_mismatch = deepcopy(active)
        last_seen_mismatch["requests"][request_key()][
            "lastSeen"
        ] = "2026-07-27T00:00:00Z"
        mutations.append(last_seen_mismatch)

        recovered = reduce_issue(
            report_v2(
                "match",
                "run.3",
                "2026-08-02T00:00:00Z",
                final_status="ready",
            ),
            [{
                "number": 16,
                "title": ISSUE_TITLE,
                "state": "open",
                "body": second["body"],
            }],
        )["trendState"]
        recovered_mismatch = deepcopy(recovered)
        recovered_mismatch["requests"][request_key()][
            "recoveredAt"
        ] = "2026-08-03T00:00:00Z"
        mutations.append(recovered_mismatch)

        for mutation in mutations:
            with self.subTest(), self.assertRaises(IssueContractError):
                _validate_trend_state(mutation)

    def test_candidate_fallback_keeps_transport_trend_and_renders_chain(self) -> None:
        fallback = report_v2(
            "match", "run.fallback.1", "2026-07-19T00:00:00Z"
        )
        primary = fallback["requestAudit"]["requests"][0]
        primary["finalStatus"] = "transient"
        primary["attempts"][0]["status"] = "transient"
        second_key = request_key("fallback")
        fallback["requestAudit"]["requests"].append({
            "requestKey": second_key,
            "requestUrl": "https://www.canada.ca/fr/representation",
            "method": "GET",
            "attemptCount": 1,
            "finalStatus": "ready",
            "latencyBucket": "250ms-999ms",
            "attempts": [{
                "number": 1,
                "status": "ready",
                "latencyBucket": "250ms-999ms",
            }],
        })
        fallback["requestAudit"].update({
            "requestCount": 2,
            "totalAttemptCount": 2,
            "retriedRequestCount": 0,
        })
        fallback["results"][0].update({
            "selectedCandidate": "fr",
            "candidatePolicy": "available-parity",
            "candidateChain": [
                {
                    "candidateId": "en",
                    "requestKey": request_key(),
                    "requestUrl": "https://www.canada.ca/en/representation",
                    "method": "GET",
                    "outcome": "transient",
                    "reason": "HTTP 503",
                    "attemptCount": 1,
                    "latencyBucket": "lt250ms",
                    "attempts": [{
                        "number": 1,
                        "status": "transient",
                        "latencyBucket": "lt250ms",
                    }],
                },
                {
                    "candidateId": "fr",
                    "requestKey": second_key,
                    "requestUrl": "https://www.canada.ca/fr/representation",
                    "method": "GET",
                    "outcome": "match",
                    "reason": {"value": "18-35"},
                    "attemptCount": 1,
                    "latencyBucket": "250ms-999ms",
                    "attempts": [{
                        "number": 1,
                        "status": "ready",
                        "latencyBucket": "250ms-999ms",
                    }],
                },
            ],
        })
        created = reduce_issue(fallback, [])
        self.assertEqual(created["action"], "create")
        self.assertIn("Representation candidate chains", created["body"])
        self.assertIn("available-parity", created["body"])
        self.assertEqual(
            created["trendState"]["requests"][request_key()][
                "consecutiveTransient"
            ],
            1,
        )
        blocked_fallback = deepcopy(fallback)
        blocked_fallback["observationId"] = "run.blocked.1"
        blocked_fallback["requestAudit"]["requests"][0][
            "finalStatus"
        ] = "blocked"
        blocked_fallback["requestAudit"]["requests"][0]["attempts"][0][
            "status"
        ] = "blocked"
        blocked_fallback["results"][0]["candidateChain"][0][
            "outcome"
        ] = "blocked"
        blocked_payload = reduce_issue(blocked_fallback, [])
        self.assertEqual(blocked_payload["action"], "create")
        self.assertIn("blocked candidates require access review", blocked_payload["body"])

        latency_only = deepcopy(fallback)
        latency_only["results"][0]["candidateChain"][1][
            "latencyBucket"
        ] = "15s-plus"
        latency_only["requestAudit"]["requests"][1][
            "latencyBucket"
        ] = "15s-plus"
        latency_only["requestAudit"]["requests"][1]["attempts"][0][
            "latencyBucket"
        ] = "15s-plus"
        self.assertEqual(
            report_body_fingerprint(fallback),
            report_body_fingerprint(latency_only),
        )

        recovered = deepcopy(fallback)
        recovered["observationId"] = "run.fallback.2"
        recovered["generatedAt"] = "2026-07-26T00:00:00Z"
        recovered["requestAudit"]["requests"][0]["finalStatus"] = "ready"
        recovered["requestAudit"]["requests"][0]["attempts"][0][
            "status"
        ] = "ready"
        recovered["results"][0]["candidateChain"][0]["outcome"] = "match"
        recovered["results"][0]["candidateChain"][0][
            "reason"
        ] = {"value": "18-35"}
        existing = [{
            "number": 24,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": created["body"],
        }]
        reduced = reduce_issue(recovered, existing)
        self.assertEqual(reduced["action"], "close")
        self.assertEqual(
            reduced["trendState"]["requests"][request_key()][
                "consecutiveTransient"
            ],
            0,
        )

    def test_manual_review_due_evidence_is_visible_and_substantive(self) -> None:
        overdue = report("unsupported")
        overdue["results"][0]["manualReview"] = {
            "verifiedAt": "2026-07-01",
            "dueDate": "2026-07-08",
            "daysOverdue": 11,
            "evidenceFingerprint": "sha256:" + "a" * 64,
            "reason": "Compressed reviewed evidence.",
            "manualReviewDays": 7,
        }
        body = render_issue_body(overdue)
        self.assertIn("2026-07-08", body)
        self.assertIn("daysOverdue", body)
        changed = deepcopy(overdue)
        changed["results"][0]["manualReview"]["daysOverdue"] = 12
        self.assertNotEqual(
            report_body_fingerprint(overdue),
            report_body_fingerprint(changed),
        )

    def test_retired_request_keys_are_removed_without_hash_only_rows(self) -> None:
        first = report_v2(
            "transient", "retire.1", "2026-07-19T00:00:00Z"
        )
        created = reduce_issue(first, [])
        old_key = request_key()
        self.assertIn(old_key, created["trendState"]["requests"])
        existing = [{
            "number": 31,
            "title": ISSUE_TITLE,
            "state": "open",
            "body": created["body"],
        }]

        replacement = report_v2(
            "match", "retire.2", "2026-07-26T00:00:00Z",
            final_status="ready",
        )
        new_key = request_key("replacement")
        replacement["requestAudit"]["requests"][0].update({
            "requestKey": new_key,
            "requestUrl": "https://www.canada.ca/new-current-source",
        })
        replacement["results"][0].update({
            "requestKey": new_key,
            "requestUrl": "https://www.canada.ca/new-current-source",
        })
        reduced = reduce_issue(replacement, existing)
        self.assertEqual(reduced["action"], "close")
        self.assertNotIn(old_key, reduced["trendState"]["requests"])
        self.assertNotIn(old_key[:19], reduced["body"])
        self.assertIn("new-current-source", reduced["body"])

        replay_existing = [{
            "number": 31,
            "title": ISSUE_TITLE,
            "state": "closed",
            "body": reduced["body"],
        }]
        replay = reduce_issue(replacement, replay_existing)
        self.assertEqual(replay["action"], "noop")
        self.assertEqual(replay["trendState"], reduced["trendState"])

    def test_request_audit_v2_budget_fields_are_strict_and_rendered(self) -> None:
        budgeted = report_v2(
            "transient", "budget.1", "2026-07-19T00:00:00Z"
        )
        budgeted["requestAudit"]["schemaVersion"] = 2
        budgeted["requestAudit"]["requests"][0].update({
            "budgetSeconds": 30,
            "budgetExhausted": True,
        })
        body = render_issue_body(budgeted)
        self.assertIn("Budget", body)
        self.assertIn("exhausted", body)
        self.assertIn("canada.ca/citation", body)

        for field, value in (
            ("budgetSeconds", 0),
            ("budgetSeconds", 61),
            ("budgetExhausted", "yes"),
        ):
            mutation = deepcopy(budgeted)
            mutation["requestAudit"]["requests"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                IssueContractError
            ):
                render_issue_body(mutation)


if __name__ == "__main__":
    unittest.main()
