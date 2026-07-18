from __future__ import annotations

from copy import deepcopy
from datetime import date
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_source_attestations as verifier  # noqa: E402


FIXTURES = ROOT / "tests" / "fixtures" / "source-attestations"
TODAY = date(2026, 7, 19)


def fingerprint(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class SourceAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        fixture_dir = self.root / "tests" / "fixtures" / "source-attestations"
        fixture_dir.parent.mkdir(parents=True)
        shutil.copytree(FIXTURES, fixture_dir)
        self.fixture_dir = fixture_dir
        self.boundary = {
            "schemaVersion": 1,
            "targets": [
                {"id": "nz-wage", "reviewed": {"value": 23.95}},
                {"id": "au-pdf", "reviewed": {"value": [[0.1, 0.2]]}},
                {"id": "ca-json", "reviewed": {"value": 0.25}},
                {"id": "au-api", "reviewed": {"value": 840}},
            ],
        }
        self.claims = {
            "schemaVersion": 1,
            "audit": {},
            "claims": [
                self.claim("claim-wage", 23.95, "NZD/hour",
                           "https://www.employment.govt.nz/minimum-wage"),
                self.claim("claim-pdf", [[0.1, 0.2]], "ratio",
                           "https://www.ato.gov.au/rates.pdf"),
                self.claim("claim-json", 0.25, "ratio",
                           "https://www.canada.ca/policy.json"),
                self.claim(
                    "claim-api",
                    840,
                    "AUD",
                    "https://immi.homeaffairs.gov.au/visas/getting-a-visa/fees-and-charges",
                ),
            ],
        }
        self.registry = {
            "schemaVersion": 1,
            "boundaryManifest": "boundary.json",
            "claimScope": [
                "claim-wage", "claim-pdf", "claim-json", "claim-api"
            ],
            "attestations": [
                self.html_attestation(),
                self.pdf_attestation(),
                self.json_attestation(),
                self.api_attestation(),
            ],
        }
        self.write_json("boundary.json", self.boundary)
        self.write_json("claims.json", self.claims)
        self.write_json("attestations.json", self.registry)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def claim(
        claim_id: str, value: object, unit: str, source: str
    ) -> dict[str, object]:
        return {
            "id": claim_id,
            "status": "official",
            "sourceUrl": source,
            "value": value,
            "unit": unit,
        }

    def fixture(self, name: str, media: str, final_url: str) -> dict[str, object]:
        path = self.fixture_dir / name
        return {
            "path": f"tests/fixtures/source-attestations/{name}",
            "mediaType": media,
            "sha256": fingerprint(path),
            "httpStatus": 200,
            "finalUrl": final_url,
        }

    def common(
        self,
        attestation_id: str,
        jurisdiction: str,
        source: str,
        target: str,
        claim_id: str,
        expected: dict[str, object],
        fixture: dict[str, object],
        extractor: dict[str, object],
        request: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "id": attestation_id,
            "jurisdiction": jurisdiction,
            "sourceUrl": source,
            "request": request or {"method": "GET"},
            "verifiedAt": "2026-07-19",
            "effectiveFrom": "2026-04-01",
            "reviewAfterDays": 90,
            "targets": [{"targetId": target, "reviewedPath": "/value"}],
            "claims": [{"claimId": claim_id}],
            "extractor": extractor,
            "expected": expected,
            "fixture": fixture,
        }

    def html_attestation(self) -> dict[str, object]:
        source = "https://www.employment.govt.nz/minimum-wage"
        return self.common(
            "nz-wage-source", "NZ", source, "nz-wage", "claim-wage",
            {"type": "number", "unit": "NZD/hour", "value": 23.95},
            self.fixture("employment-wage.html", "text/html", source),
            {
                "mode": "html-table-record",
                "params": {
                    "section": "The following rates are effective from 1 April 2026",
                    "headers": [
                        "Type of minimum wage", "Per hour", "8-hour-day",
                        "40-hour week", "80-hour fortnight",
                    ],
                    "result": "scalar",
                    "fields": [{
                        "key": "adult", "rowLabels": ["Adult"],
                        "valueHeader": "Per hour",
                        "transform": "currency-to-number",
                        "unit": "NZD/hour",
                    }],
                },
            },
        )

    def pdf_attestation(self) -> dict[str, object]:
        source = "https://www.ato.gov.au/rates.pdf"
        return self.common(
            "au-pdf-source", "AU", source, "au-pdf", "claim-pdf",
            {"type": "array", "unit": "ratio", "value": [[0.1, 0.2]]},
            self.fixture("official-source.pdf", "application/pdf", source),
            {
                "mode": "pdf-table",
                "params": {
                    "anchor": "Reviewed rates",
                    "headers": ["Lower", "Upper"],
                    "unitLabel": "Unit",
                    "valueTypes": ["number", "number"],
                    "nullToken": "null",
                    "delimiter": "|",
                },
            },
        )

    def json_attestation(self) -> dict[str, object]:
        source = "https://www.canada.ca/policy.json"
        return self.common(
            "ca-json-source", "CA", source, "ca-json", "claim-json",
            {"type": "number", "unit": "ratio", "value": 0.25},
            self.fixture("official-source.json", "application/json", source),
            {"mode": "json-pointer", "params": {"pointer": "/policy"}},
        )

    def api_attestation(self) -> dict[str, object]:
        source = (
            "https://immi.homeaffairs.gov.au/visas/getting-a-visa/"
            "fees-and-charges"
        )
        endpoint = (
            "https://immi.homeaffairs.gov.au/_layouts/15/api/"
            "data.aspx/GetPriceList"
        )
        return self.common(
            "au-api-source", "AU", source, "au-api", "claim-api",
            {"type": "number", "unit": "AUD", "value": 840},
            self.fixture("home-affairs-fees.json", "application/json", endpoint),
            {
                "mode": "api-json-record",
                "params": {
                    "arrayPointer": "/d/data",
                    "match": {"VisaType": "417-A", "ApplicantType": "Base"},
                    "valuePointer": "/Price",
                    "transform": "currency-to-number",
                },
            },
            {
                "method": "POST",
                "url": endpoint,
                "jsonBody": {"onshore": "All", "category": "Visa"},
            },
        )

    def write_json(self, name: str, value: object) -> None:
        (self.root / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def run_verify(
        self, registry: dict[str, object] | None = None
    ) -> verifier.AttestationReport:
        if registry is not None:
            self.write_json("attestations.json", registry)
        return verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            boundary_manifest_path="boundary.json",
            claims_path="claims.json",
            today=TODAY,
        )

    def assert_status(self, report: verifier.AttestationReport, status: str) -> None:
        self.assertIn(status, [result.status for result in report.results])

    def test_offline_html_pdf_json_api_registry_passes_with_audit(self) -> None:
        report = self.run_verify()
        self.assertTrue(report.ok, [result.render() for result in report.results])
        self.assertEqual(report.fetchedUrls, 4)
        self.assertEqual(
            report.audit,
            {
                "attestationCount": 4,
                "claimCount": 4,
                "reviewedLeafCount": 5,
                "liveCapableCount": 4,
            },
        )
        api = next(result for result in report.results if result.id == "au-api-source")
        self.assertNotEqual(api.source, api.requestUrl)

    def test_real_ird_tax_table_without_caption_or_unit_row(self) -> None:
        unit, value = verifier._extract_html_table_record(
            (FIXTURES / "ird-tax.html").read_bytes(),
            {
                "section": "From 1 April 2025",
                "headers": ["For each dollar of income", "Tax rate"],
                "result": "scalar",
                "fields": [{
                    "key": "brackets",
                    "rowLabels": [
                        "0 - $15,600", "$15,601 – $53,500",
                        "$53,501 – $78,100", "$78,101 – $180,000",
                        "$180,001 and over",
                    ],
                    "valueHeader": "Tax rate",
                    "transform": "tax-brackets",
                    "unit": "NZD/rate",
                }],
            },
        )
        self.assertEqual(unit, "NZD/rate")
        self.assertEqual(value[-1], [None, 0.39])
        serialized_unit, serialized = verifier._extract_html_table_record(
            (FIXTURES / "ird-tax.html").read_bytes(),
            {
                "section": "From 1 April 2025",
                "headers": ["For each dollar of income", "Tax rate"],
                "result": "scalar",
                "fields": [{
                    "key": "brackets",
                    "rowLabels": [
                        "0 - $15,600", "$15,601 – $53,500",
                        "$53,501 – $78,100", "$78,101 – $180,000",
                        "$180,001 and over",
                    ],
                    "valueHeader": "Tax rate",
                    "transform": "tax-brackets-serialization",
                    "unit": "NZD/rate",
                }],
            },
        )
        self.assertEqual(serialized_unit, "NZD/rate")
        self.assertEqual(
            serialized,
            "15600@0.105;53500@0.175;78100@0.30;"
            "180000@0.33;above@0.39",
        )

    def test_real_inz_h4_sibling_values(self) -> None:
        unit, value = verifier._extract_html_labelled_values(
            (FIXTURES / "inz-hero.html").read_bytes(),
            {
                "anchor": "Working Holiday Visa",
                "result": "object",
                "fields": [
                    {"key": "months", "label": "Length of stay",
                     "transform": "duration-months", "unit": "months"},
                    {"key": "cost", "label": "Cost",
                     "transform": "currency-to-number", "unit": "NZD"},
                    {"key": "age", "label": "Age range",
                     "transform": "inclusive-range", "unit": "years"},
                ],
            },
        )
        self.assertEqual(value, {"months": 12, "cost": 770, "age": "18-30"})
        self.assertEqual(unit["cost"], "NZD")

    def test_real_ircc_details_section_row_selection(self) -> None:
        unit, value = verifier._extract_html_table_record(
            (FIXTURES / "ircc-fees.html").read_bytes(),
            {
                "section": "International Experience Canada",
                "headers": ["Fees", "$CAN"],
                "result": "scalar",
                "fields": [{
                    "key": "owp",
                    "rowLabels": ["Open work permit holder fee"],
                    "valueHeader": "$CAN",
                    "transform": "currency-to-number",
                    "unit": "CAD",
                }],
            },
        )
        self.assertEqual((unit, value), ("CAD", 100))

    def test_prose_fixed_transforms_cover_production_sentences(self) -> None:
        body = (FIXTURES / "prose.html").read_bytes()
        cases = [
            ("NZD $20,000 for each year, plus outward travel costs.",
             "leading-currency-to-number", "NZD", 20000),
            ("The eligibility age will increase from 18–30 to 18–35.",
             "final-inclusive-range", "years", "18-35"),
            ("Eligible participants may receive a work permit for up to 24 months.",
             "duration-months", "months", 24),
        ]
        for anchor, transform, unit, expected in cases:
            with self.subTest(transform=transform):
                self.assertEqual(
                    verifier._extract_html_text_anchor(
                        body, {"anchor": anchor, "transform": transform, "unit": unit}
                    ),
                    (unit, expected),
                )

    def test_nested_list_paragraph_is_not_double_counted(self) -> None:
        body = (
            "<ul><li><p>Eligible participants may receive a work permit "
            "for up to 24 months.</p></li></ul>"
        ).encode()
        self.assertEqual(
            verifier._extract_html_text_anchor(
                body,
                {
                    "anchor": (
                        "Eligible participants may receive a work permit "
                        "for up to 24 months."
                    ),
                    "transform": "duration-months",
                    "unit": "months",
                },
            ),
            ("months", 24),
        )

    def test_json_unit_tree_and_long_exact_anchor(self) -> None:
        unit, value = verifier._extract_json_record(
            json.dumps({
                "cohort": {
                    "unit": {"cap": "AUD", "rate": "decimal rate"},
                    "value": {"cap": 45000, "rate": 0.15},
                }
            }).encode(),
            {"pointer": "/cohort"},
        )
        self.assertEqual(unit, {"cap": "AUD", "rate": "decimal rate"})
        self.assertEqual(value, {"cap": 45000, "rate": 0.15})
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._extract_json_record(
                b'{"cohort":{"unit":{"cap":"AUD"},"value":{"cap":1,"rate":0.1}}}',
                {"pointer": "/cohort"},
            )
        anchor = "A" * 250
        verifier._validate_extractor({
            "mode": "html-text-anchor",
            "params": {"anchor": anchor, "transform": "integer", "unit": "count"},
        })
        with self.assertRaises(verifier.RegistryError):
            verifier._validate_extractor({
                "mode": "html-text-anchor",
                "params": {
                    "anchor": "A" * (verifier.MAX_ANCHOR_TEXT + 1),
                    "transform": "integer",
                    "unit": "count",
                },
            })

    def test_embedded_acc_percent_both_units_and_mismatch(self) -> None:
        text = "$1.75 per $100 (1.75%)"
        self.assertEqual(
            verifier._transform_html_value(text, "embedded-percent"), 1.75
        )
        self.assertEqual(
            verifier._transform_html_value(
                text, "embedded-percent-to-decimal"
            ),
            0.0175,
        )
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._transform_html_value(
                "$1.75 per $100 (1.74%)", "embedded-percent"
            )

    def test_layout_partial_and_duplicate_rows_are_changed(self) -> None:
        for replacement in (
            "<td>$23.95</td><td>$191.60</td><td>$958.00</td><td>$1,916.00</td>",
            "<tr><td>Adult</td><td>$23.95</td><td>$191.60</td><td>$958.00</td><td>$1,916.00</td></tr>"
            "<tr><td>Adult</td><td>$23.95</td><td>$191.60</td><td>$958.00</td><td>$1,916.00</td></tr>",
        ):
            with self.subTest(replacement=replacement[:20]):
                registry = deepcopy(self.registry)
                path = self.fixture_dir / "employment-wage.html"
                original = (FIXTURES / "employment-wage.html").read_text()
                row = "<tr><td>Adult</td><td>$23.95</td><td>$191.60</td><td>$958.00</td><td>$1,916.00</td></tr>"
                path.write_text(original.replace(row, replacement))
                registry["attestations"][0]["fixture"]["sha256"] = fingerprint(path)
                self.assert_status(self.run_verify(registry), "changed")
                shutil.copy2(FIXTURES / "employment-wage.html", path)

    def test_api_record_zero_and_duplicate_match_are_changed(self) -> None:
        for records in ([], [
            {"VisaType": "417-A", "ApplicantType": "Base", "Price": "AUD840"},
            {"VisaType": "417-A", "ApplicantType": "Base", "Price": "AUD840"},
        ]):
            with self.subTest(count=len(records)):
                registry = deepcopy(self.registry)
                path = self.fixture_dir / "home-affairs-fees.json"
                path.write_text(json.dumps({"d": {"data": records}}))
                registry["attestations"][3]["fixture"]["sha256"] = fingerprint(path)
                self.assert_status(self.run_verify(registry), "changed")
                shutil.copy2(FIXTURES / "home-affairs-fees.json", path)

    def test_post_request_same_host_and_canonical_cache_key(self) -> None:
        first = self.registry["attestations"][3]
        second = deepcopy(first)
        second["request"]["jsonBody"] = {"category": "Visa", "onshore": "All"}
        self.assertEqual(
            verifier._request_key(first), verifier._request_key(second)
        )
        self.assertTrue(self.run_verify().ok)

    def test_post_cross_host_get_url_and_unofficial_url_fail_closed(self) -> None:
        mutations = [
            ("POST", "https://www.ato.gov.au/api", {"x": "y"}),
            ("GET", "https://immi.homeaffairs.gov.au/api", None),
            ("POST", "https://example.com/api", {"x": "y"}),
        ]
        for method, url, body in mutations:
            with self.subTest(method=method, url=url):
                registry = deepcopy(self.registry)
                request = {"method": method, "url": url}
                if body is not None:
                    request["jsonBody"] = body
                registry["attestations"][3]["request"] = request
                self.assert_status(self.run_verify(registry), "unsupported")
        registry = deepcopy(self.registry)
        registry["attestations"][0]["sourceUrl"] = "https://example.com/policy"
        self.assert_status(self.run_verify(registry), "unsupported")

    def test_unofficial_redirect_and_unsupported_pdf_fail_closed(self) -> None:
        attestation = self.registry["attestations"][0]
        result = verifier._evaluate_response(
            attestation,
            verifier.SourceResponse(
                200,
                "https://example.com/redirect",
                "text/html",
                (FIXTURES / "employment-wage.html").read_bytes(),
            ),
            offline=False,
            root=self.root,
        )
        self.assertEqual(result.status, "unsupported")
        with self.assertRaises(verifier.UnsupportedExtraction):
            verifier._extract_pdf_table(
                b"%PDF-1.4\n/FlateDecode\n",
                self.pdf_attestation()["extractor"]["params"],
            )

    def test_status_blocked_login_transient_empty_and_5xx(self) -> None:
        cases = [
            ("bot-blocked.html", 200, "blocked"),
            ("login.html", 200, "blocked"),
            ("employment-wage.html", 429, "transient"),
            ("employment-wage.html", 503, "transient"),
        ]
        for filename, status, expected_status in cases:
            with self.subTest(filename=filename, status=status):
                registry = deepcopy(self.registry)
                fixture = registry["attestations"][0]["fixture"]
                path = self.fixture_dir / filename
                fixture.update({
                    "path": f"tests/fixtures/source-attestations/{filename}",
                    "sha256": fingerprint(path),
                    "httpStatus": status,
                })
                self.assert_status(self.run_verify(registry), expected_status)
        empty = self.fixture_dir / "empty.html"
        empty.write_bytes(b"")
        registry = deepcopy(self.registry)
        registry["attestations"][0]["fixture"].update({
            "path": "tests/fixtures/source-attestations/empty.html",
            "sha256": fingerprint(empty),
        })
        self.assert_status(self.run_verify(registry), "changed")

    def test_normal_recaptcha_config_is_not_a_block_challenge(self) -> None:
        normal = (FIXTURES / "normal-recaptcha.html").read_bytes()
        self.assertFalse(verifier._blocked_body("text/html", normal))
        self.assertTrue(
            verifier._blocked_body(
                "text/html",
                b"<html><title>Just a moment...</title>"
                b"<script id='cf-chl-widget'></script></html>",
            )
        )
        self.assertTrue(
            verifier._blocked_body(
                "text/html", b"<h1>Verify you are human</h1>"
            )
        )

    def test_fixture_fingerprint_and_unit_change_are_changed(self) -> None:
        registry = deepcopy(self.registry)
        registry["attestations"][0]["fixture"]["sha256"] = "sha256:" + "0" * 64
        self.assert_status(self.run_verify(registry), "changed")
        registry = deepcopy(self.registry)
        registry["attestations"][0]["extractor"]["params"]["fields"][0]["unit"] = (
            "NZD/day"
        )
        self.assert_status(self.run_verify(registry), "changed")
        registry = deepcopy(self.registry)
        registry["attestations"][3]["expected"]["unit"] = "CAD"
        claims = deepcopy(self.claims)
        claims["claims"][3]["unit"] = "CAD"
        self.write_json("claims.json", claims)
        self.assert_status(self.run_verify(registry), "changed")

    def test_stale_orphan_duplicate_unmapped_and_nonfinite_fail_closed(self) -> None:
        mutations = []
        stale = deepcopy(self.registry)
        stale["attestations"][0]["verifiedAt"] = "2025-01-01"
        mutations.append(stale)
        orphan = deepcopy(self.registry)
        orphan["attestations"][0]["claims"][0]["claimId"] = "missing"
        mutations.append(orphan)
        duplicate = deepcopy(self.registry)
        duplicate["attestations"][1]["claims"] = [{"claimId": "claim-wage"}]
        mutations.append(duplicate)
        unmapped = deepcopy(self.registry)
        unmapped["attestations"][0].pop("claims")
        mutations.append(unmapped)
        arbitrary = deepcopy(self.registry)
        arbitrary["attestations"][0]["extractor"]["params"]["regex"] = ".*"
        mutations.append(arbitrary)
        for registry in mutations:
            with self.subTest():
                self.assert_status(self.run_verify(registry), "unsupported")
        (self.root / "attestations.json").write_text(
            '{"schemaVersion":1,"boundaryManifest":"boundary.json",'
            '"attestations":[NaN]}'
        )
        report = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            claims_path="claims.json",
            today=TODAY,
        )
        self.assert_status(report, "unsupported")

    def test_review_after_day_is_inclusive_then_stale_next_day(self) -> None:
        registry = deepcopy(self.registry)
        for attestation in registry["attestations"]:
            attestation["verifiedAt"] = "2026-04-20"
            attestation["reviewAfterDays"] = 90
        self.write_json("attestations.json", registry)
        report = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            claims_path="claims.json",
            today=date(2026, 7, 19),
        )
        self.assertTrue(report.ok)
        report = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            claims_path="claims.json",
            today=date(2026, 7, 20),
        )
        self.assert_status(report, "unsupported")

    def test_non_object_registry_root_is_actionable(self) -> None:
        (self.root / "attestations.json").write_text("[]\n")
        report = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            claims_path="claims.json",
            today=TODAY,
        )
        self.assert_status(report, "unsupported")

    def test_declared_audit_must_equal_deterministic_counts(self) -> None:
        claims = deepcopy(self.claims)
        claims["audit"]["sourceAttestations"] = {
            "attestationCount": 99,
            "claimCount": 4,
            "reviewedLeafCount": 4,
            "liveCapableCount": 4,
        }
        self.write_json("claims.json", claims)
        report = self.run_verify()
        self.assert_status(report, "unsupported")

    def test_live_post_uses_endpoint_and_canonical_body(self) -> None:
        attestation = self.registry["attestations"][3]
        captured = {}

        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _limit):
                return (FIXTURES / "home-affairs-fees.json").read_bytes()

            def geturl(self):
                return attestation["request"]["url"]

            def getcode(self):
                return 200

        def opener(request, **_kwargs):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["body"] = request.data
            return Response()

        response = verifier._live_response(attestation, 1, urlopen=opener)
        self.assertEqual(captured["url"], attestation["request"]["url"])
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(
            captured["body"], b'{"category":"Visa","onshore":"All"}'
        )
        self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
