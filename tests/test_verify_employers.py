from __future__ import annotations

from copy import deepcopy
from datetime import date
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib import error as urllib_error


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_employers as verifier  # noqa: E402


FIXTURE = ROOT / "tests" / "fixtures" / "employers.json"
TODAY = date(2026, 7, 19)


class FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status: int = 200,
        body: bytes = b"<html>reviewed</html>",
        final_url: str | None = None,
    ) -> None:
        self.status = status
        self.url = url
        self.body = body
        self.final_url = final_url or url

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.final_url

    def read(self, _size: int = -1) -> bytes:
        return self.body if _size < 0 else self.body[:_size]


class EmployerVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "employers.json"
        self.write()

    def write(self) -> None:
        self.path.write_text(
            json.dumps(self.raw, ensure_ascii=False), encoding="utf-8"
        )

    def verify(self) -> verifier.Verification:
        self.write()
        return verifier.verify_registry(self.path, TODAY)

    def fields(self, result: verifier.Verification) -> set[str]:
        return {item.field for item in result.problems}

    def test_reviewed_fixture_and_exact_audit_pass(self) -> None:
        result = self.verify()
        self.assertTrue(result.ok, [item.render() for item in result.problems])
        self.assertEqual(
            result.audit,
            {
                "employerCount": 8,
                "countryCounts": {"NZ": 3, "AU": 5},
                "statusCounts": {
                    "active": 6, "uncertain": 1, "expired": 1
                },
                "contactableCount": 4,
                "expiredCount": 1,
                "nearDuplicateCandidateCount": 0,
                "linkUrlCount": 8,
            },
        )
        self.assertEqual(result.duplicate_candidates, [])

    def test_exact_root_entry_keys_id_and_unknown_enums_fail(self) -> None:
        self.raw["unknown"] = True
        result = self.verify()
        self.assertIn("root.keys", self.fields(result))

        self.setUp()
        row = self.raw["employers"][0]
        row["id"] = "Bad ID"
        row["vacancy"] = True
        row["workTypes"] = ["magic-work"]
        row["source"]["kind"] = "official"
        result = self.verify()
        self.assertIn("entry.keys", self.fields(result))

        self.setUp()
        row = self.raw["employers"][0]
        row["id"] = "Bad ID"
        row["workTypes"] = ["magic-work"]
        row["source"]["kind"] = "official"
        result = self.verify()
        self.assertIn("id", self.fields(result))
        self.assertIn("workTypes", self.fields(result))
        self.assertIn("source.kind", self.fields(result))

        self.setUp()
        self.raw["employers"][0].pop("source")
        result = self.verify()
        self.assertIn("entry.keys", self.fields(result))

        self.setUp()
        self.raw["employers"][1]["id"] = self.raw["employers"][0]["id"]
        result = self.verify()
        self.assertIn("id", self.fields(result))

    def test_coordinate_postcode_state_and_precision_are_bounded(self) -> None:
        row = self.raw["employers"][3]
        row["location"]["lat"] = -50
        row["location"]["state"] = "NSW"
        row["location"]["postcode"] = "4670"
        row["location"]["precision"] = "exact"
        row["location"].pop("address")
        result = self.verify()
        self.assertIn("location.lat/lng", self.fields(result))
        self.assertIn("location.state/postcode", self.fields(result))
        self.assertIn("location.address", self.fields(result))

        self.setUp()
        self.raw["employers"][0]["location"]["postcode"] = "318"
        result = self.verify()
        self.assertIn("location.postcode", self.fields(result))

        self.setUp()
        self.raw["employers"][0]["location"]["lat"] = float("nan")
        result = self.verify()
        self.assertIn("location.lat", self.fields(result))

    def test_source_and_contact_schemes_and_host_promotion_fail_closed(self) -> None:
        row = self.raw["employers"][0]
        row["source"]["url"] = "http://www.immigration.govt.nz/register"
        result = self.verify()
        self.assertIn("source.url", self.fields(result))

        self.setUp()
        row = self.raw["employers"][2]
        row["contact"] = {"kind": "email", "url": "https://example.com"}
        row["source"]["url"] = "https://fake-association.example/list"
        result = self.verify()
        self.assertIn("contact.url", self.fields(result))
        self.assertIn("source.url", self.fields(result))

        self.setUp()
        row = self.raw["employers"][3]
        row["source"]["kind"] = "government-register"
        result = self.verify()
        self.assertIn("source.url", self.fields(result))

        self.setUp()
        row = self.raw["employers"][3]
        row["contact"]["url"] = "https://unrelated.example/careers"
        result = self.verify()
        self.assertIn("source.url/contact.url", self.fields(result))

    def test_ausveg_industry_host_accepts_subdomain_but_rejects_typosquat(
        self,
    ) -> None:
        row = self.raw["employers"][3]
        row["source"]["kind"] = "industry-association"
        row["source"]["url"] = (
            "https://www.ausveg.com.au/articles/"
            "australia-japan-horticulture-showcase/"
        )
        self.raw["audit"]["linkUrlCount"] = 9
        result = self.verify()
        self.assertTrue(result.ok, [item.render() for item in result.problems])

        self.setUp()
        row = self.raw["employers"][3]
        row["source"]["kind"] = "industry-association"
        row["source"]["url"] = (
            "https://ausveg.com.au.example/"
            "australia-japan-horticulture-showcase/"
        )
        result = self.verify()
        self.assertIn("source.url", self.fields(result))

    def test_malformed_nested_types_fail_closed_without_exception(self) -> None:
        row = self.raw["employers"][0]
        row["workTypes"] = [{"unexpected": "object"}]
        row["contact"] = {"kind": "company"}
        result = self.verify()
        self.assertIn("workTypes", self.fields(result))
        self.assertIn("contact.url", self.fields(result))

        self.setUp()
        first = self.raw["employers"][0]
        second = self.raw["employers"][2]
        second["name"] = first["name"]
        second["location"]["lat"] = "not-a-number"
        result = self.verify()
        self.assertIn("location.lat", self.fields(result))

    def test_stale_false_active_expiry_and_expired_contract(self) -> None:
        active = self.raw["employers"][0]
        active["nextReviewAt"] = "2026-07-18"
        active["source"]["effectiveTo"] = "2026-07-18"
        expired = self.raw["employers"][1]
        expired["source"].pop("effectiveTo")
        result = self.verify()
        self.assertIn("nextReviewAt", self.fields(result))
        self.assertIn("status", self.fields(result))
        self.assertIn("source.effectiveTo", self.fields(result))

        self.setUp()
        self.raw["employers"][0]["source"]["checkedAt"] = "2026-02-30"
        self.raw["employers"][0]["source"]["effectiveTo"] = "2026-13-01"
        result = self.verify()
        self.assertIn("source.checkedAt", self.fields(result))
        self.assertIn("source.effectiveTo", self.fields(result))

    def test_exact_duplicate_fails_but_multibranch_and_near_candidate_are_explicit(
        self,
    ) -> None:
        baseline = self.verify()
        self.assertTrue(baseline.ok)
        southern = [
            row for row in baseline.employers
            if row["name"] == "Southern Orchards"
        ]
        self.assertEqual(len(southern), 2)

        duplicate = deepcopy(self.raw["employers"][3])
        duplicate["id"] = "au-southern-orchards-bundaberg-copy"
        self.raw["employers"].append(duplicate)
        result = self.verify()
        self.assertIn("duplicate", self.fields(result))

        self.setUp()
        second = self.raw["employers"][4]
        second["location"].update({
            "label": "Bundaberg second branch",
            "address": "11 Orchard Road, Bundaberg QLD 4670",
            "region": "Wide Bay",
            "state": "QLD",
            "postcode": "4670",
            "lat": -24.8655,
            "lng": 152.349,
        })
        self.raw["audit"]["nearDuplicateCandidateCount"] = 1
        result = self.verify()
        self.assertTrue(result.ok, [item.render() for item in result.problems])
        self.assertEqual(len(result.duplicate_candidates), 1)
        self.assertLessEqual(
            result.duplicate_candidates[0]["distanceMeters"], 200
        )

    def test_vacancy_and_eligibility_false_positive_fail(self) -> None:
        row = self.raw["employers"][0]
        row["name"] = "Apata Group — hiring now"
        row["vacancyStatus"] = "current"
        row["eligibility"]["classification"] = "not-applicable"
        row["eligibility"]["requiresRoleCheck"] = False
        result = self.verify()
        self.assertIn("vacancyStatus", self.fields(result))
        self.assertIn("vacancyStatus/text", self.fields(result))
        self.assertIn("eligibility.requiresRoleCheck", self.fields(result))
        self.assertIn("eligibility", self.fields(result))

    def test_unverified_source_cannot_be_active(self) -> None:
        row = self.raw["employers"][7]
        row["source"]["kind"] = "unverified"
        result = self.verify()
        self.assertIn("status", self.fields(result))

    def test_link_check_fetches_each_url_once_and_separates_statuses(self) -> None:
        validated = self.verify()
        self.assertTrue(validated.ok)
        template = deepcopy(validated.employers[7])
        urls = {
            "https://harvestmoon.com.au/ok": "match",
            "https://harvestmoon.com.au/gone": "changed",
            "https://harvestmoon.com.au/blocked": "blocked",
            "https://harvestmoon.com.au/limited": "transient",
            "https://harvestmoon.com.au/server": "transient",
            "https://harvestmoon.com.au/redirect": "unsupported",
            "https://harvestmoon.com.au/oversized": "match",
        }
        employers = []
        for index, url in enumerate(urls):
            item = deepcopy(template)
            item["id"] = f"au-link-{index}"
            item["source"]["url"] = url
            item["contact"] = {"kind": "none"}
            employers.append(item)
        shared = deepcopy(employers[0])
        shared["id"] = "au-link-shared"
        employers.append(shared)
        calls: dict[str, int] = {}

        def fake_open(request: object, **_kwargs: object) -> FakeResponse:
            url = request.full_url  # type: ignore[attr-defined]
            self.assertEqual(request.get_method(), "GET")  # type: ignore[attr-defined]
            self.assertIsNone(request.data)  # type: ignore[attr-defined]
            self.assertEqual(  # type: ignore[attr-defined]
                request.get_header("Accept-encoding"), "identity"
            )
            calls[url] = calls.get(url, 0) + 1
            if url.endswith("/gone"):
                raise urllib_error.HTTPError(url, 404, "gone", {}, None)
            if url.endswith("/blocked"):
                raise urllib_error.HTTPError(url, 403, "blocked", {}, None)
            if url.endswith("/limited"):
                raise urllib_error.HTTPError(url, 429, "limited", {}, None)
            if url.endswith("/server"):
                raise urllib_error.HTTPError(url, 503, "server", {}, None)
            if url.endswith("/redirect"):
                return FakeResponse(
                    url, final_url="https://unofficial.example/landing",
                    body=b"do not store secret-personal-content",
                )
            if url.endswith("/oversized"):
                return FakeResponse(
                    url,
                    body=(
                        b"bounded-reviewed-page "
                        + b"x" * verifier.MAX_BODY_BYTES
                        + b"oversized-private-tail"
                    ),
                )
            return FakeResponse(
                url, body=b"do not store secret-personal-content"
            )

        report = verifier.check_links(
            employers,
            urlopen=fake_open,
            generated_at="2026-07-19",
        )
        by_url = {item["url"]: item["status"] for item in report["results"]}
        self.assertEqual(by_url, urls)
        self.assertEqual(calls[employers[0]["source"]["url"]], 1)
        self.assertNotIn(
            "secret-personal-content",
            json.dumps(report, ensure_ascii=False),
        )
        self.assertNotIn(
            "oversized-private-tail",
            json.dumps(report, ensure_ascii=False),
        )
        self.assertEqual(
            report["audit"],
            {
                "urlCount": 7,
                "match": 2,
                "changed": 1,
                "blocked": 1,
                "transient": 2,
                "unsupported": 1,
            },
        )

    def test_cli_error_is_actionable(self) -> None:
        self.raw["employers"][0]["location"]["postcode"] = "999"
        self.write()
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "verify_employers.py"),
                str(self.path),
                "--today",
                "2026-07-19",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("id=nz-rse-apata-te-puke", result.stderr)
        self.assertIn("field=location.postcode", result.stderr)
        self.assertIn("actual=", result.stderr)
        self.assertIn("expected=", result.stderr)
        self.assertIn("Fix:", result.stderr)


if __name__ == "__main__":
    unittest.main()
