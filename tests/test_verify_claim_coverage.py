from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import date
from pathlib import Path

from scripts import verify_claim_coverage as coverage


class ClaimCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "data").mkdir()
        self.page = "nz/index.html"

    def write_page(self, html: str) -> None:
        page_path = self.root / self.page
        page_path.parent.mkdir(parents=True, exist_ok=True)
        page_path.write_text(html, encoding="utf-8")

    def write_exemptions(self, exemptions: list[dict] | None = None) -> None:
        payload = {"schemaVersion": 1, "exemptions": exemptions or []}
        (self.root / "data" / "claim-coverage-exemptions.json").write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )

    def verify(self) -> coverage.CoverageReport:
        return coverage.verify_coverage(
            self.root,
            pages=[self.page],
            today=date(2026, 7, 19),
        )

    def test_marked_sensitive_fact_passes(self) -> None:
        self.write_page(
            '<main><p data-claim-id="nz-fee">Working Holiday Visa fee NZD 770</p></main>'
        )
        self.write_exemptions()

        report = self.verify()

        self.assertTrue(report.ok, [issue.render() for issue in report.issues])
        self.assertGreaterEqual(report.marked_count, 1)

    def test_unmarked_fact_fails_but_noise_and_scenario_are_ignored(self) -> None:
        self.write_page(
            """
            <main id="content">
              <p>Student Visa application fee NZD 850</p>
              <p>Updated 2026-07-19. Call 0800 123 456.</p>
              <section id="scenarios"><p>Example Visa fee NZD 999</p></section>
              <svg><text x="-36.8" y="174.7">map</text></svg>
            </main>
            """
        )
        self.write_exemptions()

        report = self.verify()

        uncovered = [
            issue for issue in report.issues if issue.code == "UNCOVERED_CLAIM"
        ]
        self.assertEqual(len(uncovered), 1)
        self.assertIn("850", uncovered[0].actual)
        self.assertNotIn("999", uncovered[0].actual)
        self.assertNotIn("0800", uncovered[0].actual)

    def test_valid_exemption_matches_selector_and_fingerprint(self) -> None:
        self.write_page("<main><p>Student Visa fee NZD 850</p></main>")
        self.write_exemptions()
        candidates, _, _ = coverage.collect_candidates(
            self.root, pages=[self.page]
        )
        candidate = next(item for item in candidates if item.category == "fee")
        self.write_exemptions(
            [
                {
                    "selector": candidate.selector,
                    "fingerprint": candidate.fingerprint,
                    "reason": "Legacy aggregate retained until the next content audit.",
                    "owner": "trust-team",
                    "expiresAt": "2026-08-01",
                }
            ]
        )

        report = self.verify()

        self.assertTrue(report.ok, [issue.render() for issue in report.issues])
        self.assertEqual(report.exempted_count, 1)

    def test_expired_exemption_and_orphan_exemption_fail(self) -> None:
        self.write_page("<main><p>Student Visa fee NZD 850</p></main>")
        self.write_exemptions()
        candidates, _, _ = coverage.collect_candidates(
            self.root, pages=[self.page]
        )
        candidate = next(item for item in candidates if item.category == "fee")
        self.write_exemptions(
            [
                {
                    "selector": candidate.selector,
                    "fingerprint": candidate.fingerprint,
                    "reason": "Expired review window.",
                    "owner": "trust-team",
                    "expiresAt": "2026-07-18",
                },
                {
                    "selector": "nz/index.html::#removed",
                    "fingerprint": "sha256:deadbeef",
                    "reason": "The original node was removed.",
                    "owner": "trust-team",
                    "expiresAt": "2026-08-01",
                },
            ]
        )

        report = self.verify()
        codes = {issue.code for issue in report.issues}
        expired_orphans = [
            issue
            for issue in report.issues
            if issue.code == "ORPHAN_EXEMPTION"
            and issue.selector == candidate.selector
        ]

        self.assertIn("EXPIRED_EXEMPTION", codes)
        self.assertIn("ORPHAN_EXEMPTION", codes)
        self.assertIn("UNCOVERED_CLAIM", codes)
        self.assertEqual(expired_orphans, [])

    def test_changed_text_invalidates_fingerprint(self) -> None:
        self.write_page("<main><p>Student Visa fee NZD 850</p></main>")
        self.write_exemptions()
        candidates, _, _ = coverage.collect_candidates(
            self.root, pages=[self.page]
        )
        original = next(item for item in candidates if item.category == "fee")
        self.write_exemptions(
            [
                {
                    "selector": original.selector,
                    "fingerprint": original.fingerprint,
                    "reason": "Temporary legacy value.",
                    "owner": "trust-team",
                    "expiresAt": "2026-08-01",
                }
            ]
        )
        self.write_page("<main><p>Student Visa fee NZD 900</p></main>")

        report = self.verify()
        codes = {issue.code for issue in report.issues}

        self.assertIn("UNCOVERED_CLAIM", codes)
        self.assertIn("ORPHAN_EXEMPTION", codes)

    def test_structured_db_and_tax_constants_are_scanned(self) -> None:
        self.write_page(
            """
            <main>
              <p><span data-claim-id="student-fee">Student Visa fee NZD 850</span></p>
              <p><span data-claim-id="minimum-wage">Minimum wage NZD 23.95/h</span></p>
            </main>
            <script>
            const DB = {
              fees: {
                student: { v: 850, src: 'https://example.test/' }
              },
              wages: {
                minimum: { v: 23.95, src: 'https://example.test/' }
              },
              pathways: []
            };
            const NP_BRACKETS = [[15600, 0.105], [53500, 0.175]];
            </script>
            """
        )
        self.write_exemptions()

        report = self.verify()
        uncovered = [
            item.actual
            for item in report.issues
            if item.code == "UNCOVERED_CLAIM"
        ]

        self.assertFalse(any("fees.student" in item for item in uncovered))
        self.assertFalse(any("wages.minimum" in item for item in uncovered))
        self.assertTrue(any("NP_BRACKETS" in item for item in uncovered))

    def test_range_keeps_both_values_next_to_units(self) -> None:
        self.write_page("<main><p>Working Holiday Visa age 18–35 years old</p></main>")
        self.write_exemptions()

        report = self.verify()
        candidate = next(item for item in report.uncovered if item.category == "age")

        self.assertEqual(candidate.numbers, ("18", "35"))

    def test_cli_error_is_actionable(self) -> None:
        self.write_page("<main><p>Student Visa fee NZD 850</p></main>")
        self.write_exemptions()
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            exit_code = coverage.main(
                ["--root", str(self.root), "--page", self.page]
            )

        output = stderr.getvalue()
        self.assertEqual(exit_code, 1)
        self.assertIn("code=UNCOVERED_CLAIM", output)
        self.assertIn("selector=", output)
        self.assertIn("Fix:", output)


if __name__ == "__main__":
    unittest.main()
