from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import date, timedelta
from pathlib import Path
from unittest import mock
from urllib import error as urllib_error

from scripts import verify_claims


class FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.headers: dict[str, str] = {}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, size: int = -1) -> bytes:
        return b"x"


class ClaimVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.today = date(2026, 7, 19)
        self.registry_path = self.root / "data" / "claims.json"
        self.registry_path.parent.mkdir(parents=True)

    def claim(self, claim_id: str = "nz.minimum-wage", **overrides: object) -> dict:
        claim = {
            "id": claim_id,
            "country": "NZ",
            "locale": "ko",
            "category": "employment",
            "label": "Adult minimum wage",
            "value": 23.95,
            "unit": "NZD/hour",
            "status": "official",
            "verifiedAt": self.today.isoformat(),
            "effectiveFrom": "2026-04-01",
            "sourceUrl": "https://www.employment.govt.nz/pay-and-hours/",
            "pages": ["nz/index.html"],
            "severity": "critical",
        }
        claim.update(overrides)
        return claim

    def write_page(
        self, claim_ids: list[str], page: str = "nz/index.html"
    ) -> None:
        page_path = self.root / page
        page_path.parent.mkdir(parents=True, exist_ok=True)
        markers = "".join(
            f'<span data-claim-id="{claim_id}">{claim_id}</span>'
            for claim_id in claim_ids
        )
        page_path.write_text(f"<!doctype html><body>{markers}</body>", encoding="utf-8")

    def write_registry(
        self,
        claims: list[object],
        *,
        schema_version: object = 1,
        generated_at: object = "2026-07-19T00:00:00Z",
    ) -> None:
        payload = {
            "schemaVersion": schema_version,
            "generatedAt": generated_at,
            "claims": claims,
        }
        self.registry_path.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )

    def validate(
        self, *, check_links: bool = False
    ) -> verify_claims.ValidationReport:
        return verify_claims.validate_registry(
            self.registry_path,
            self.root,
            today=self.today,
            check_links=check_links,
            timeout=0.1,
        )

    def assert_issue(
        self,
        report: verify_claims.ValidationReport,
        claim_id: str,
        field: str,
    ) -> verify_claims.Issue:
        for issue in report.issues:
            if issue.claim_id == claim_id and issue.field == field:
                return issue
        self.fail(
            f"missing issue ({claim_id}, {field}); got "
            f"{[(item.claim_id, item.field) for item in report.issues]}"
        )

    def test_valid_registry_passes_offline(self) -> None:
        self.write_page(["nz.minimum-wage"])
        self.write_registry([self.claim()])

        with mock.patch.object(
            verify_claims.urllib_request,
            "urlopen",
            side_effect=AssertionError("offline validation must not use network"),
        ):
            report = self.validate()

        self.assertTrue(report.ok, [issue.render() for issue in report.issues])
        self.assertEqual(report.claim_count, 1)
        self.assertEqual(report.checked_pages, {"nz/index.html"})
        self.assertEqual(report.checked_links, 0)

    def test_invalid_json_and_root_metadata_are_reported(self) -> None:
        self.registry_path.write_text("{", encoding="utf-8")
        invalid_json = self.validate()
        self.assert_issue(invalid_json, "<registry>", "json")

        self.registry_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "1",
                    "generatedAt": "2026-07-19T00:00:00",
                    "claims": [],
                }
            ),
            encoding="utf-8",
        )
        bad_root = self.validate()
        self.assert_issue(bad_root, "<registry>", "schemaVersion")
        self.assert_issue(bad_root, "<registry>", "generatedAt")

    def test_required_fields_types_and_unique_ids(self) -> None:
        self.write_page(["duplicate"])
        first = self.claim("duplicate")
        second = self.claim("duplicate", label="", value={"amount": 23.95})
        del second["category"]
        self.write_registry([first, second])

        report = self.validate()

        self.assert_issue(report, "duplicate", "id")
        self.assert_issue(report, "duplicate", "category")
        self.assert_issue(report, "duplicate", "label")
        self.assert_issue(report, "duplicate", "value")

    def test_dates_enums_and_effective_range(self) -> None:
        claim = self.claim(
            "bad-dates",
            status="confirmed",
            severity="urgent",
            verifiedAt="2026-07-20",
            effectiveFrom="2026-12-31",
            effectiveTo="2026-01-01",
        )
        self.write_page(["bad-dates"])
        self.write_registry([claim])

        report = self.validate()

        self.assert_issue(report, "bad-dates", "status")
        self.assert_issue(report, "bad-dates", "severity")
        future = self.assert_issue(report, "bad-dates", "verifiedAt")
        self.assertIn("future", future.message)
        self.assert_issue(report, "bad-dates", "effectiveTo")

    def test_staleness_threshold_boundaries(self) -> None:
        claims = [
            self.claim(
                "critical-fresh",
                verifiedAt=(self.today - timedelta(days=45)).isoformat(),
            ),
            self.claim(
                "critical-stale",
                verifiedAt=(self.today - timedelta(days=46)).isoformat(),
            ),
            self.claim(
                "minor-fresh",
                severity="minor",
                verifiedAt=(self.today - timedelta(days=90)).isoformat(),
            ),
            self.claim(
                "medium-stale",
                severity="medium",
                verifiedAt=(self.today - timedelta(days=91)).isoformat(),
            ),
        ]
        self.write_page([claim["id"] for claim in claims])
        self.write_registry(claims)

        report = self.validate()
        stale_ids = {
            issue.claim_id
            for issue in report.issues
            if issue.field == "verifiedAt" and "stale" in issue.message
        }

        self.assertEqual(stale_ids, {"critical-stale", "medium-stale"})

    def test_country_domain_allowlist_rejects_spoofed_host(self) -> None:
        good = self.claim(
            "ca-good",
            country="CA",
            sourceUrl="https://www.canada.ca/en/services/immigration-citizenship.html",
        )
        bad = self.claim(
            "nz-spoofed",
            sourceUrl="https://immigration.govt.nz.attacker.example/fees",
        )
        common = self.claim(
            "common-oecd",
            country="COMMON",
            sourceUrl="https://www.oecd.org/migration/",
        )
        unsupported = self.claim("unsupported-country", country="GB")
        self.write_page(
            ["ca-good", "nz-spoofed", "common-oecd", "unsupported-country"]
        )
        self.write_registry([good, bad, common, unsupported])

        report = self.validate()

        self.assert_issue(report, "nz-spoofed", "sourceUrl")
        self.assert_issue(report, "unsupported-country", "country")
        self.assertFalse(
            any(issue.claim_id in {"ca-good", "common-oecd"} for issue in report.issues)
        )

    def test_page_must_exist_stay_in_root_and_contain_marker(self) -> None:
        self.write_page([])
        missing_marker = self.claim("missing-marker")
        missing_page = self.claim("missing-page", pages=["ca/missing.html"])
        escaping_page = self.claim("escaping-page", pages=["../outside.html"])
        self.write_registry([missing_marker, missing_page, escaping_page])

        report = self.validate()

        self.assert_issue(report, "missing-marker", "pages[0]")
        self.assert_issue(report, "missing-page", "pages[0]")
        escape = self.assert_issue(report, "escaping-page", "pages[0]")
        self.assertIn("escapes", escape.message)

    def test_parity_requires_matching_value_and_unit(self) -> None:
        korean = self.claim("nz.fee.ko", parityKey="nz.fee")
        japanese = self.claim(
            "nz.fee.ja",
            locale="ja",
            status="derived",
            value=24.0,
            parityKey="nz.fee",
        )
        self.write_page(["nz.fee.ko", "nz.fee.ja"])
        self.write_registry([korean, japanese])

        report = self.validate()
        mismatch = self.assert_issue(report, "nz.fee.ja", "parityKey")
        self.assertIn("value/unit", mismatch.message)

        japanese["parityExemptReason"] = "Japanese page reflects a future effective rate."
        self.write_registry([korean, japanese])
        exempt_report = self.validate()
        self.assertTrue(
            exempt_report.ok,
            [issue.render() for issue in exempt_report.issues],
        )

    def test_parity_exemption_requires_a_parity_key(self) -> None:
        claim = self.claim(
            "orphan-exemption",
            parityExemptReason="This explanation has no group.",
        )
        self.write_page(["orphan-exemption"])
        self.write_registry([claim])

        report = self.validate()

        self.assert_issue(report, "orphan-exemption", "parityExemptReason")

    def test_check_links_uses_head_then_get_fallback(self) -> None:
        self.write_page(["nz.minimum-wage"])
        self.write_registry([self.claim()])
        methods: list[str] = []

        def urlopen(request: object, timeout: float) -> FakeResponse:
            method = request.get_method()
            methods.append(method)
            if method == "HEAD":
                raise urllib_error.URLError("HEAD not supported")
            return FakeResponse(200)

        with mock.patch.object(
            verify_claims.urllib_request, "urlopen", side_effect=urlopen
        ):
            report = self.validate(check_links=True)

        self.assertTrue(report.ok, [issue.render() for issue in report.issues])
        self.assertEqual(methods, ["HEAD", "GET"])
        self.assertEqual(report.checked_links, 1)

    def test_failed_link_check_is_actionable_and_deduplicated(self) -> None:
        first = self.claim("first-link")
        second = self.claim("second-link", locale="ja")
        self.write_page(["first-link", "second-link"])
        self.write_registry([first, second])

        with mock.patch.object(
            verify_claims.urllib_request,
            "urlopen",
            side_effect=urllib_error.URLError("offline"),
        ) as mocked_urlopen:
            report = self.validate(check_links=True)

        self.assert_issue(report, "first-link", "sourceUrl")
        self.assert_issue(report, "second-link", "sourceUrl")
        self.assertEqual(mocked_urlopen.call_count, 2)
        self.assertEqual(report.checked_links, 1)

    def test_cli_returns_one_and_prints_claim_field_and_fix(self) -> None:
        self.write_page([])
        self.write_registry([self.claim("cli-claim")])
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            exit_code = verify_claims.main(
                [str(self.registry_path), "--root", str(self.root)]
            )

        output = stderr.getvalue()
        self.assertEqual(exit_code, 1)
        self.assertIn("ERROR [cli-claim] pages[0]", output)
        self.assertIn("Fix:", output)


if __name__ == "__main__":
    unittest.main()
