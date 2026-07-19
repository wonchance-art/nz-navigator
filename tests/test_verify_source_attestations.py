from __future__ import annotations

from copy import deepcopy
from datetime import date
import hashlib
import json
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import unittest
from urllib import error as urllib_error
import zlib


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
                "liveExtractableCount": 4,
                "fixtureOnlyCount": 0,
            },
        )
        payload = report.to_json()
        self.assertEqual(
            set(payload["audit"]),
            {
                "attestationCount",
                "claimCount",
                "reviewedLeafCount",
                "liveCapableCount",
                "liveExtractableCount",
                "fixtureOnlyCount",
            },
        )
        self.assertEqual(payload["requestAudit"]["requestCount"], 4)
        self.assertEqual(payload["requestAudit"]["totalAttemptCount"], 4)
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

    def test_ato_whm_first_band_and_super_number_percentage(self) -> None:
        whm_unit, whm_value = verifier._extract_html_table_record(
            (FIXTURES / "ato-whm.html").read_bytes(),
            {
                "section": "Working holiday maker tax rates 2025–26",
                "headers": ["Taxable income", "Tax on this income"],
                "result": "scalar",
                "fields": [{
                    "key": "whm",
                    "rowLabels": ["0 – $45,000"],
                    "valueHeader": "Tax on this income",
                    "transform": "ato-first-tax-band",
                    "unit": {"cap": "AUD", "rate": "decimal rate"},
                }],
            },
        )
        self.assertEqual(
            (whm_unit, whm_value),
            (
                {"cap": "AUD", "rate": "decimal rate"},
                {"cap": 45000, "rate": 0.15},
            ),
        )
        super_unit, super_value = verifier._extract_html_table_record(
            (FIXTURES / "ato-super.html").read_bytes(),
            {
                "section": "Table 21: Super guarantee percentage",
                "headers": [
                    "Period",
                    "General super guarantee (%)",
                    (
                        "Super guarantee (%) for Norfolk Island "
                        "(transitional rate) (from 1 July 2016)"
                    ),
                ],
                "result": "scalar",
                "fields": [{
                    "key": "rate",
                    "rowLabels": ["1 July 2026 – 30 June 2027"],
                    "valueHeader": "General super guarantee (%)",
                    "transform": "percentage-number-to-decimal",
                    "unit": "decimal rate",
                }],
            },
        )
        self.assertEqual((super_unit, super_value), ("decimal rate", 0.12))
        for bad in ("12.00%", "12.00 11", "-1", "101"):
            with self.subTest(bad=bad), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._transform_html_value(
                    bad, "percentage-number-to-decimal"
                )

    def test_ato_law_whm_first_band_binds_later_year_table(self) -> None:
        source = (
            "https://www.ato.gov.au/law/view/print?"
            "DocID=PAC%2F20240003%2FSch1-Cl4&PiT=99991231235958"
        )
        fixture_path = self.fixture_dir / "ato-whm-law.html"
        boundary = {
            "schemaVersion": 1,
            "targets": [{
                "id": "au-whm-law",
                "reviewed": {
                    "whm": {"cap": 45000, "rate": 0.15}
                },
            }],
        }
        registry = {
            "schemaVersion": 1,
            "boundaryManifest": "boundary.json",
            "attestations": [{
                "id": "au-whm-law-source",
                "jurisdiction": "AU",
                "sourceUrl": source,
                "request": {"method": "GET"},
                "verifiedAt": "2026-07-19",
                "effectiveFrom": "2024-07-01",
                "reviewAfterDays": 90,
                "targets": [{
                    "targetId": "au-whm-law",
                    "reviewedPath": "/whm",
                }],
                "extractor": {
                    "mode": "html-table-record",
                    "params": {
                        "section": "Repeal the table, substitute:",
                        "headers": verifier.ATO_LAW_FIRST_BAND_HEADERS,
                        "result": "scalar",
                        "fields": [{
                            "key": "whm",
                            "rowLabels": ["1"],
                            "valueHeader": "The rate is:",
                            "transform": "ato-law-first-tax-band",
                            "unit": {
                                "cap": "AUD",
                                "rate": "decimal rate",
                            },
                        }],
                    },
                },
                "expected": {
                    "type": "object",
                    "unit": {
                        "cap": "AUD",
                        "rate": "decimal rate",
                    },
                    "value": {"cap": 45000, "rate": 0.15},
                },
                "fixture": {
                    "path": (
                        "tests/fixtures/source-attestations/"
                        "ato-whm-law.html"
                    ),
                    "mediaType": "text/html",
                    "sha256": fingerprint(fixture_path),
                    "httpStatus": 200,
                    "finalUrl": source,
                },
            }],
        }
        self.write_json("boundary.json", boundary)
        self.write_json(
            "claims.json",
            {"schemaVersion": 1, "audit": {}, "claims": []},
        )
        baseline = (FIXTURES / "ato-whm-law.html").read_text()

        def run(body: str) -> verifier.AttestationReport:
            fixture_path.write_text(body)
            mutated = deepcopy(registry)
            mutated["attestations"][0]["fixture"]["sha256"] = fingerprint(
                fixture_path
            )
            self.write_json("attestations.json", mutated)
            return verifier.verify_source_attestations(
                self.root,
                attestations_path="attestations.json",
                boundary_manifest_path="boundary.json",
                claims_path="claims.json",
                today=TODAY,
            )

        self.assertTrue(run(baseline).ok)
        title_start = baseline.index(
            "    <tr>\n      <th>"
            + verifier.ATO_LAW_FIRST_BAND_TITLE
        )
        title_end = (
            baseline.index("    </tr>", title_start)
            + len("    </tr>\n")
        )
        title_row = baseline[title_start:title_end]
        header_start = baseline.index(
            "    <tr>\n      <th>Item</th>", title_end
        )
        header_end = (
            baseline.index("    </tr>", header_start)
            + len("    </tr>\n")
        )
        header_row = baseline[header_start:header_end]
        without_title = baseline[:title_start] + baseline[title_end:]
        mutations = [
            baseline.replace(
                verifier.ATO_LAW_FIRST_BAND_TITLE,
                "Tax rates for working holiday makers",
            ),
            baseline.replace("<td>1</td>", "<td>2</td>"),
            baseline.replace(
                "does not exceed $45,000",
                "is less than $45,000",
            ),
            baseline.replace("The rate is:", "Rate"),
            baseline.replace("<td>15%</td>", "<td>16%</td>"),
            baseline.replace(
                "<td>does not exceed $45,000</td>", ""
            ),
            baseline.replace(
                "</tbody>",
                (
                    "<tr><td>1</td><td>does not exceed $45,000</td>"
                    "<td>15%</td></tr></tbody>"
                ),
            ),
            baseline.replace(
                "<th></th>", "<th>unexpected</th>", 1
            ),
            baseline.replace(
                header_row, title_row + header_row, 1
            ),
            without_title.replace(
                header_row, header_row + title_row, 1
            ),
        ]
        for body in mutations:
            with self.subTest(body=body[-100:]):
                self.assert_status(run(body), "changed")

    def test_ato_law_transform_schema_is_exact(self) -> None:
        base = {
            "mode": "html-table-record",
            "params": {
                "section": "Repeal the table, substitute:",
                "headers": verifier.ATO_LAW_FIRST_BAND_HEADERS,
                "result": "scalar",
                "fields": [{
                    "key": "whm",
                    "rowLabels": ["1"],
                    "valueHeader": "The rate is:",
                    "transform": "ato-law-first-tax-band",
                    "unit": {
                        "cap": "AUD",
                        "rate": "decimal rate",
                    },
                }],
            },
        }
        verifier._validate_extractor(base)
        mutations = []
        bad_headers = deepcopy(base)
        bad_headers["params"]["headers"][1] = "Taxable income"
        mutations.append(bad_headers)
        bad_item = deepcopy(base)
        bad_item["params"]["fields"][0]["rowLabels"] = ["2"]
        mutations.append(bad_item)
        bad_column = deepcopy(base)
        bad_column["params"]["fields"][0]["valueHeader"] = "Item"
        mutations.append(bad_column)
        bad_unit = deepcopy(base)
        bad_unit["params"]["fields"][0]["unit"]["rate"] = "percent"
        mutations.append(bad_unit)
        for extractor in mutations:
            with self.subTest(), self.assertRaises(verifier.RegistryError):
                verifier._validate_extractor(extractor)

    def test_ato_whm_and_lito_adversarial_grammar_fails_closed(self) -> None:
        whm = (FIXTURES / "ato-whm.html").read_text()
        for old, new in (
            ("0 – $45,000", "1 – $45,000"),
            ("0 – $45,000", "0 – $45,000 or $50,000"),
            ("15c for each $1", "15c for each $2"),
        ):
            with self.subTest(new=new), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_html_table_record(
                    whm.replace(old, new).encode(),
                    {
                        "section": "Working holiday maker tax rates 2025–26",
                        "headers": ["Taxable income", "Tax on this income"],
                        "result": "scalar",
                        "fields": [{
                            "key": "whm",
                            "rowLabels": [new if old.startswith("0 ") else "0 – $45,000"],
                            "valueHeader": "Tax on this income",
                            "transform": "ato-first-tax-band",
                            "unit": {
                                "cap": "AUD",
                                "rate": "decimal rate",
                            },
                        }],
                    },
                )
        lito_params = {
            "anchor": "Low income tax offset",
            "items": [
                (
                    "$37,500 or less, you will get "
                    "the maximum offset of $700"
                ),
                (
                    "between $37,501 and $45,000, you will get "
                    "$700 minus 5 cents for every $1 above $37,500"
                ),
                (
                    "between $45,001 and $66,667, you will get "
                    "$325 minus 1.5 cents for every $1 above $45,000."
                ),
            ],
        }
        unit, value = verifier._extract_ato_lito(
            (FIXTURES / "ato-lito.html").read_bytes(), lito_params
        )
        self.assertEqual(unit, verifier.ATO_LITO_UNIT)
        self.assertEqual(
            value,
            {
                "maxOffset": 700,
                "fullTo": 37500,
                "taper1To": 45000,
                "taper1Rate": 0.05,
                "cutOut": 66667,
                "taper2Rate": 0.015,
            },
        )
        lito = (FIXTURES / "ato-lito.html").read_text()
        for old, new in (
            ("$37,501 and $45,000", "$37,502 and $45,000"),
            ("$325 minus", "$326 minus"),
            ("1.5 cents", "1.4 cents"),
            ("</ul>", f"<li>{lito_params['items'][2]}</li></ul>"),
        ):
            mutated = lito.replace(old, new)
            mutated_params = deepcopy(lito_params)
            mutated_params["items"] = [
                item.replace(old, new) for item in mutated_params["items"]
            ]
            if old == "</ul>":
                mutated_params = lito_params
            with self.subTest(new=new[:30]), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_ato_lito(
                    mutated.encode(), mutated_params
                )

    def test_medicare_loose_text_is_exact_and_not_double_collected(self) -> None:
        anchor = (
            "The rate of levy payable by a person upon a taxable income is 2%."
        )
        params = {
            "anchor": anchor,
            "transform": "percent-to-decimal",
            "unit": "decimal rate",
        }
        self.assertEqual(
            verifier._extract_html_text_anchor(
                (FIXTURES / "ato-medicare.html").read_bytes(), params
            ),
            ("decimal rate", 0.02),
        )
        base = (FIXTURES / "ato-medicare.html").read_text()
        mutations = [
            base.replace("is 2%.", "is 2.1%."),
            base.replace("</body>", f"<br>{anchor}</body>"),
            base.replace("is 2%.", "is <strong>2%</strong>."),
        ]
        for mutated in mutations:
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_html_text_anchor(
                    mutated.encode(), params
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

    def test_request_url_overrides_are_same_host_and_fail_closed(self) -> None:
        source = "https://www.ato.gov.au/rates-and-calculators"
        content = (
            "https://www.ato.gov.au/api/public/content/"
            "0-2319183b-9958-4848-88f9-ea9dc64b121e"
        )
        verifier._validate_request(
            {"method": "GET", "url": content}, source, "AU"
        )
        verifier._validate_request({"method": "GET"}, source, "AU")
        mutations = [
            ("POST", "https://www.ato.gov.au/api", {"x": "y"}),
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
        invalid_gets = [
            {"method": "GET", "url": "https://ato.gov.au/api/content"},
            {"method": "GET", "url": "https://example.com/api/content"},
            {"method": "GET", "url": content + "?view=1"},
            {"method": "GET", "url": content, "jsonBody": {}},
        ]
        for request in invalid_gets:
            with self.subTest(request=request), self.assertRaises(
                verifier.RegistryError
            ):
                verifier._validate_request(request, source, "AU")
        registry = deepcopy(self.registry)
        registry["attestations"][0]["sourceUrl"] = "https://example.com/policy"
        self.assert_status(self.run_verify(registry), "unsupported")

    def test_transient_retry_recovers_and_shared_request_fetches_once_per_attempt(
        self,
    ) -> None:
        first = self.html_attestation()
        second = deepcopy(first)
        second["id"] = "nz-wage-source-two"
        second["targets"] = [
            {"targetId": "nz-wage-two", "reviewedPath": "/value"}
        ]
        second["claims"] = [{"claimId": "claim-wage-two"}]
        self.boundary = {
            "schemaVersion": 1,
            "targets": [
                {"id": "nz-wage", "reviewed": {"value": 23.95}},
                {"id": "nz-wage-two", "reviewed": {"value": 23.95}},
            ],
        }
        self.claims = {
            "schemaVersion": 1,
            "audit": {},
            "claims": [
                self.claim(
                    "claim-wage",
                    23.95,
                    "NZD/hour",
                    first["sourceUrl"],
                ),
                self.claim(
                    "claim-wage-two",
                    23.95,
                    "NZD/hour",
                    first["sourceUrl"],
                ),
            ],
        }
        self.registry = {
            "schemaVersion": 1,
            "boundaryManifest": "boundary.json",
            "claimScope": ["claim-wage", "claim-wage-two"],
            "attestations": [first, second],
        }
        self.write_json("boundary.json", self.boundary)
        self.write_json("claims.json", self.claims)
        self.write_json("attestations.json", self.registry)

        outcomes = iter([503, 200])
        calls: list[str] = []

        class Response:
            headers = {"Content-Type": "text/html"}

            def __init__(self, status: int) -> None:
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                if self.status == 503:
                    return b"<title>Just a moment...</title>"
                return (FIXTURES / "employment-wage.html").read_bytes()

            def geturl(self):
                return first["sourceUrl"]

            def getcode(self):
                return self.status

        def opener(request, **_kwargs):
            calls.append(request.full_url)
            return Response(next(outcomes))

        clocks = iter([0.0, 0.1, 1.0, 1.4])
        sleeps: list[float] = []
        report = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            boundary_manifest_path="boundary.json",
            claims_path="claims.json",
            mode="live",
            today=TODAY,
            max_attempts=3,
            retry_backoff_ms=10,
            observation_id="run.1",
            urlopen=opener,
            clock=lambda: next(clocks),
            sleeper=sleeps.append,
        )
        self.assertTrue(report.ok, [item.render() for item in report.results])
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, [0.01])
        self.assertEqual(report.fetchedUrls, 1)
        self.assertEqual(report.requests[0].attemptCount, 2)
        self.assertEqual(
            [attempt.status for attempt in report.requests[0].attempts],
            ["transient", "ready"],
        )
        self.assertEqual(
            {item.attemptCount for item in report.results}, {2}
        )
        payload = report.to_json()
        self.assertEqual(payload["requestAudit"]["totalAttemptCount"], 2)
        self.assertEqual(payload["requestAudit"]["retriedRequestCount"], 1)

    def test_implicit_live_observation_tracks_semantics_not_latency(self) -> None:
        response = verifier.SourceResponse(
            200,
            "https://www.employment.govt.nz/minimum-wage",
            "text/html",
            b"reviewed",
        )

        def build(
            attempts: tuple[verifier.AttemptAudit, ...],
            total_latency: str,
            result_status: str = "match",
            observation_id: str | None = None,
            context: bytes = b"reviewed-context",
        ) -> verifier.AttestationReport:
            execution = verifier.RequestExecution(
                "sha256:" + "1" * 64,
                response.final_url,
                "GET",
                attempts,
                attempts[-1].status,
                total_latency,
                response,
            )
            result = verifier._attach_request_execution(
                verifier._result(
                    "source-one",
                    response.final_url,
                    "/value",
                    result_status,
                    1,
                    1,
                    "No action required.",
                    context=context,
                ),
                execution,
            )
            report = verifier.AttestationReport(
                "live",
                "2026-07-19T00:00:00Z",
                observation_id,
                results=[result],
                requests=[execution],
            )
            report.audit = {
                "attestationCount": 1,
                "claimCount": 0,
                "reviewedLeafCount": 1,
                "liveCapableCount": 1,
                "liveExtractableCount": 1,
                "fixtureOnlyCount": 0,
            }
            return report

        ready = build(
            (verifier.AttemptAudit(1, "ready", "lt250ms"),),
            "lt250ms",
        )
        slower = build(
            (verifier.AttemptAudit(1, "ready", "5s-14.999s"),),
            "5s-14.999s",
        )
        footer_changed = build(
            (verifier.AttemptAudit(1, "ready", "lt250ms"),),
            "lt250ms",
            context=b"unrelated-footer-changed",
        )
        recovered = build(
            (
                verifier.AttemptAudit(1, "transient", "lt250ms"),
                verifier.AttemptAudit(2, "ready", "lt250ms"),
            ),
            "250ms-999ms",
        )
        changed = build(
            (verifier.AttemptAudit(1, "ready", "lt250ms"),),
            "lt250ms",
            result_status="changed",
        )
        changed_context = build(
            (verifier.AttemptAudit(1, "ready", "lt250ms"),),
            "lt250ms",
            result_status="changed",
            context=b"changed-source-context",
        )
        ready_id = ready.to_json()["observationId"]
        self.assertRegex(ready_id, r"^[0-9a-f]{64}$")
        self.assertEqual(ready_id, slower.to_json()["observationId"])
        self.assertEqual(
            ready_id, footer_changed.to_json()["observationId"]
        )
        self.assertNotEqual(
            ready_id, recovered.to_json()["observationId"]
        )
        self.assertNotEqual(ready_id, changed.to_json()["observationId"])
        self.assertNotEqual(
            changed.to_json()["observationId"],
            changed_context.to_json()["observationId"],
        )
        explicit = build(
            (verifier.AttemptAudit(1, "ready", "lt250ms"),),
            "lt250ms",
            observation_id="workflow.1",
        )
        self.assertEqual(
            explicit.to_json()["observationId"], "workflow.1"
        )

    def test_transient_retry_exhaustion_preserves_bounded_history(self) -> None:
        attestation = self.html_attestation()
        calls: list[int] = []

        class Response:
            status = 503
            headers = {"Content-Type": "text/html"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"temporarily unavailable"

            def geturl(self):
                return attestation["sourceUrl"]

            def getcode(self):
                return self.status

        def opener(_request, **_kwargs):
            calls.append(1)
            return Response()

        clocks = iter([0.0, 0.1, 1.0, 1.2, 2.0, 2.3])
        sleeps: list[float] = []
        execution = verifier._live_execution(
            attestation,
            max_attempts=3,
            retry_backoff_ms=20,
            timeout=1,
            urlopen=opener,
            clock=lambda: next(clocks),
            sleeper=sleeps.append,
        )
        self.assertEqual(execution.finalStatus, "transient")
        self.assertEqual(execution.attemptCount, 3)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps, [0.02, 0.04])
        self.assertEqual(
            [attempt.number for attempt in execution.attempts], [1, 2, 3]
        )
        self.assertTrue(
            all(
                attempt.status == "transient"
                for attempt in execution.attempts
            )
        )

    def test_nontransient_transport_statuses_are_never_retried(self) -> None:
        attestation = self.html_attestation()

        class Response:
            headers = {"Content-Type": "text/html"}

            def __init__(self, status: int, body: bytes) -> None:
                self.status = status
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return self.body

            def geturl(self):
                return attestation["sourceUrl"]

            def getcode(self):
                return self.status

        cases = [
            (403, b"denied", "blocked"),
            (404, b"missing", "changed"),
            (200, b"", "changed"),
            (
                200,
                b"x" * (verifier.MAX_BODY_BYTES + 1),
                "unsupported",
            ),
            (
                200,
                b"<title>Just a moment...</title>",
                "blocked",
            ),
        ]
        for status, body, expected in cases:
            calls = []
            clocks = iter([0.0, 0.1])

            def opener(_request, **_kwargs):
                calls.append(1)
                return Response(status, body)

            execution = verifier._live_execution(
                attestation,
                max_attempts=4,
                retry_backoff_ms=10,
                timeout=1,
                urlopen=opener,
                clock=lambda: next(clocks),
                sleeper=lambda _delay: self.fail("unexpected retry"),
            )
            with self.subTest(status=status, expected=expected):
                self.assertEqual(execution.finalStatus, expected)
                self.assertEqual(execution.attemptCount, 1)
                self.assertEqual(len(calls), 1)

        altered = (
            FIXTURES / "employment-wage.html"
        ).read_bytes().replace(b"$23.95", b"$24.00", 1)
        calls = []
        clocks = iter([0.0, 0.1])

        def altered_opener(_request, **_kwargs):
            calls.append(1)
            return Response(200, altered)

        execution = verifier._live_execution(
            attestation,
            max_attempts=4,
            retry_backoff_ms=10,
            timeout=1,
            urlopen=altered_opener,
            clock=lambda: next(clocks),
            sleeper=lambda _delay: self.fail("unexpected retry"),
        )
        result = verifier._evaluate_response(
            attestation,
            execution.response,
            offline=False,
            root=self.root,
        )
        self.assertEqual(execution.finalStatus, "ready")
        self.assertEqual(result.status, "changed")
        self.assertEqual(len(calls), 1)

    def test_retry_settings_and_fixture_only_live_policy_fail_closed(self) -> None:
        for kwargs in (
            {"max_attempts": 0},
            {"max_attempts": 5},
            {"retry_backoff_ms": 0},
            {"retry_backoff_ms": 2001},
            {"timeout": 0},
            {"timeout": 61},
        ):
            values = {
                "max_attempts": 1,
                "retry_backoff_ms": 1,
                "timeout": 1,
                "observation_id": "run.1",
                **kwargs,
            }
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                verifier._validate_execution_settings("live", **values)
        with self.assertRaises(ValueError):
            verifier._validate_execution_settings(
                "offline",
                max_attempts=2,
                retry_backoff_ms=1,
                timeout=1,
                observation_id="offline",
            )

        registry = deepcopy(self.registry)
        for attestation in registry["attestations"]:
            attestation["livePolicy"] = {
                "mode": "fixture-only",
                "reason": "Compressed official representation.",
                "manualReviewDays": 7,
            }
        offline = self.run_verify(registry)
        self.assertTrue(offline.ok)
        self.assertEqual(offline.audit["liveExtractableCount"], 0)
        self.assertEqual(offline.audit["fixtureOnlyCount"], 4)

        def no_network(*_args, **_kwargs):
            self.fail("fixture-only live policy attempted a network request")

        live = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            claims_path="claims.json",
            mode="live",
            today=TODAY,
            observation_id="run.fixture",
            urlopen=no_network,
        )
        self.assertEqual(live.fetchedUrls, 0)
        self.assertTrue(
            all(item.status == "unsupported" for item in live.results)
        )
        self.assertTrue(
            all(item.attemptCount == 0 for item in live.results)
        )
        self.assertIn("Compressed official", live.results[0].actual["reason"])
        self.assertIn("7 day", live.results[0].fix)

        invalid = [
            {"mode": "unknown", "reason": "x", "manualReviewDays": 7},
            {"mode": "fixture-only", "manualReviewDays": 7},
            {"mode": "fixture-only", "reason": "", "manualReviewDays": 7},
            {"mode": "fixture-only", "reason": "x", "manualReviewDays": 0},
            {"mode": "fixture-only", "reason": "x", "manualReviewDays": 31},
        ]
        for policy in invalid:
            mutated = deepcopy(self.registry)
            mutated["attestations"][0]["livePolicy"] = policy
            with self.subTest(policy=policy):
                self.assert_status(self.run_verify(mutated), "unsupported")

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
        with self.assertRaises(verifier.ChangedExtraction):
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
            "liveExtractableCount": 4,
            "fixtureOnlyCount": 0,
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

    def test_candidate_transient_falls_back_but_changed_short_circuits(self) -> None:
        transient_path = self.fixture_dir / "primary-transient.html"
        transient_path.write_text("<h1>temporary</h1>", encoding="utf-8")
        alternate_path = self.fixture_dir / "alternate-wage.html"
        alternate_path.write_bytes(
            (FIXTURES / "employment-wage.html").read_bytes()
        )
        alternate_url = (
            "https://www.employment.govt.nz/minimum-wage/representation"
        )
        registry = deepcopy(self.registry)
        attestation = registry["attestations"][0]
        attestation["fixture"] = self.fixture(
            "primary-transient.html", "text/html", attestation["sourceUrl"]
        )
        attestation["fixture"]["httpStatus"] = 503
        attestation["requestCandidates"] = [
            {
                "id": "citation",
                "sourceRelation": "citation",
                "request": attestation["request"],
                "mediaType": "text/html",
                "fixture": deepcopy(attestation["fixture"]),
            },
            {
                "id": "alternate",
                "sourceRelation": "same-host",
                "request": {"method": "GET", "url": alternate_url},
                "mediaType": "text/html",
                "fixture": self.fixture(
                    "alternate-wage.html", "text/html", alternate_url
                ),
            },
        ]
        attestation["candidatePolicy"] = {"mode": "available-parity"}
        report = self.run_verify(registry)
        result = next(item for item in report.results if item.id == "nz-wage-source")
        self.assertEqual(result.status, "match")
        self.assertEqual(result.selectedCandidate, "alternate")
        self.assertEqual(
            [item["outcome"] for item in result.candidateChain],
            ["transient", "match"],
        )

        changed_path = self.fixture_dir / "primary-changed.html"
        changed_path.write_text(
            (FIXTURES / "employment-wage.html")
            .read_text(encoding="utf-8")
            .replace("$23.95", "$99.95"),
            encoding="utf-8",
        )
        attestation["fixture"] = self.fixture(
            "primary-changed.html", "text/html", attestation["sourceUrl"]
        )
        attestation["requestCandidates"][0]["fixture"] = deepcopy(
            attestation["fixture"]
        )
        report = self.run_verify(registry)
        result = next(item for item in report.results if item.id == "nz-wage-source")
        self.assertEqual(result.status, "changed")
        self.assertIsNone(result.selectedCandidate)
        self.assertEqual(len(result.candidateChain), 1)

    def test_available_parity_candidate_mode_and_candidate_schema_fail_closed(self) -> None:
        alternate_path = self.fixture_dir / "alternate-parity.html"
        alternate_path.write_bytes(
            (FIXTURES / "employment-wage.html").read_bytes()
        )
        alternate_url = (
            "https://www.employment.govt.nz/minimum-wage/parity"
        )
        registry = deepcopy(self.registry)
        attestation = registry["attestations"][0]
        attestation["candidatePolicy"] = {"mode": "available-parity"}
        attestation["requestCandidates"] = [
            {
                "id": "citation",
                "sourceRelation": "citation",
                "request": attestation["request"],
                "mediaType": "text/html",
                "fixture": deepcopy(attestation["fixture"]),
            },
            {
                "id": "reviewed-alt",
                "sourceRelation": "same-host",
                "request": {"method": "GET", "url": alternate_url},
                "mediaType": "text/html",
                "extractor": deepcopy(attestation["extractor"]),
                "fixture": self.fixture(
                    "alternate-parity.html", "text/html", alternate_url
                ),
            },
        ]
        report = self.run_verify(registry)
        result = next(item for item in report.results if item.id == "nz-wage-source")
        self.assertEqual(result.status, "match")
        self.assertEqual(len(result.candidateChain), 2)

        mutations = []
        duplicate = deepcopy(registry)
        duplicate["attestations"][0]["requestCandidates"][1][
            "request"
        ] = {"method": "GET"}
        duplicate["attestations"][0]["requestCandidates"][1][
            "fixture"
        ] = deepcopy(duplicate["attestations"][0]["fixture"])
        mutations.append(duplicate)
        unofficial = deepcopy(registry)
        unofficial["attestations"][0]["requestCandidates"][1][
            "request"
        ] = {"method": "GET", "url": "https://example.com/policy"}
        mutations.append(unofficial)
        cross_host = deepcopy(registry)
        cross_host["attestations"][0]["requestCandidates"][1][
            "request"
        ] = {
            "method": "GET",
            "url": "https://www.ird.govt.nz/policy",
        }
        mutations.append(cross_host)
        bad_media = deepcopy(registry)
        bad_media["attestations"][0]["requestCandidates"][1][
            "mediaType"
        ] = "text/plain"
        mutations.append(bad_media)
        for mutation in mutations:
            with self.subTest():
                self.assert_status(self.run_verify(mutation), "unsupported")

    def test_candidate_blocked_all_transient_unsupported_changed_matrix(self) -> None:
        alternate_url = (
            "https://www.employment.govt.nz/minimum-wage/fallback"
        )
        alternate_path = self.fixture_dir / "matrix-alternate.html"
        alternate_path.write_bytes(
            (FIXTURES / "employment-wage.html").read_bytes()
        )

        def candidate_registry(
            primary_name: str,
            primary_status: int,
            alternate_name: str,
            alternate_status: int,
        ) -> dict[str, object]:
            registry = deepcopy(self.registry)
            attestation = registry["attestations"][0]
            attestation["fixture"] = self.fixture(
                primary_name,
                "text/html",
                attestation["sourceUrl"],
            )
            attestation["fixture"]["httpStatus"] = primary_status
            alternate_fixture = self.fixture(
                alternate_name, "text/html", alternate_url
            )
            alternate_fixture["httpStatus"] = alternate_status
            attestation["candidatePolicy"] = {
                "mode": "available-parity"
            }
            attestation["requestCandidates"] = [
                {
                    "id": "primary",
                    "sourceRelation": "citation",
                    "request": {"method": "GET"},
                    "mediaType": "text/html",
                    "fixture": deepcopy(attestation["fixture"]),
                },
                {
                    "id": "alternate",
                    "sourceRelation": "same-host",
                    "request": {"method": "GET", "url": alternate_url},
                    "mediaType": "text/html",
                    "fixture": alternate_fixture,
                },
            ]
            return registry

        blocked = self.fixture_dir / "matrix-blocked.html"
        blocked.write_text("<h1>access denied</h1>", encoding="utf-8")
        blocked_registry = candidate_registry(
            "matrix-blocked.html", 403, "matrix-alternate.html", 200
        )
        result = next(
            item
            for item in self.run_verify(blocked_registry).results
            if item.id == "nz-wage-source"
        )
        self.assertEqual(result.status, "match")
        self.assertEqual(
            [item["outcome"] for item in result.candidateChain],
            ["blocked", "match"],
        )

        transient = self.fixture_dir / "matrix-transient.html"
        transient.write_text("<h1>temporary</h1>", encoding="utf-8")
        transient_alt = self.fixture_dir / "matrix-transient-alt.html"
        transient_alt.write_text("<h1>temporary too</h1>", encoding="utf-8")
        all_transient = candidate_registry(
            "matrix-transient.html",
            503,
            "matrix-transient-alt.html",
            503,
        )
        result = next(
            item
            for item in self.run_verify(all_transient).results
            if item.id == "nz-wage-source"
        )
        self.assertEqual(result.status, "transient")
        self.assertEqual(
            [item["outcome"] for item in result.candidateChain],
            ["transient", "transient"],
        )

        unsupported_pdf = self.fixture_dir / "matrix-unsupported.pdf"
        unsupported_pdf.write_bytes(
            b"%PDF-1.4\n/ObjStm\n%%EOF\n"
        )
        changed_alt = self.fixture_dir / "matrix-changed.html"
        changed_alt.write_text(
            (FIXTURES / "employment-wage.html")
            .read_text(encoding="utf-8")
            .replace("$23.95", "$24.95"),
            encoding="utf-8",
        )
        unsupported_changed = candidate_registry(
            "matrix-blocked.html", 200, "matrix-changed.html", 200
        )
        attestation = unsupported_changed["attestations"][0]
        attestation["fixture"] = self.fixture(
            "matrix-unsupported.pdf",
            "application/pdf",
            attestation["sourceUrl"],
        )
        attestation["extractor"] = deepcopy(
            self.pdf_attestation()["extractor"]
        )
        attestation["requestCandidates"][0].update({
            "mediaType": "application/pdf",
            "extractor": deepcopy(attestation["extractor"]),
            "fixture": deepcopy(attestation["fixture"]),
        })
        attestation["requestCandidates"][1]["extractor"] = deepcopy(
            self.html_attestation()["extractor"]
        )
        result = next(
            item
            for item in self.run_verify(unsupported_changed).results
            if item.id == "nz-wage-source"
        )
        self.assertEqual(result.status, "changed")
        self.assertEqual(
            [item["outcome"] for item in result.candidateChain],
            ["unsupported", "changed"],
        )

        primary_context = verifier._candidate_contexts(
            blocked_registry["attestations"][0]
        )[0][1]
        redirected = verifier._evaluate_response(
            primary_context,
            verifier.SourceResponse(
                200,
                "https://www.ird.govt.nz/minimum-wage",
                "text/html",
                (FIXTURES / "employment-wage.html").read_bytes(),
            ),
            offline=False,
            root=self.root,
        )
        self.assertEqual(redirected.status, "unsupported")

    def test_html_section_text_scopes_en_and_fr_iec_values(self) -> None:
        english = b"""
        <h3>Republic of Korea \xe2\x80\x93 Working Holiday</h3>
        <p>Korean citizens can now participate in IEC twice for up to 24 months per participation...</p>
        <ul><li>be between the ages of 18 and 35 (inclusive)</li></ul>
        <h3>Another country</h3><p>up to 24 months per participation...</p>
        """
        french = """
        <h3>République de Corée — Vacances-travail</h3>
        <p>Description : les citoyens peuvent participer (jusqu’à 24 mois par participation).</p>
        <li>être âgé de 18 à 35 ans, inclusivement</li>
        """.encode("utf-8")
        cases = [
            (
                english,
                {
                    "heading": "Republic of Korea – Working Holiday",
                    "anchor": (
                        "Korean citizens can now participate in IEC twice "
                        "for up to 24 months per participation..."
                    ),
                    "transform": "duration-months",
                    "unit": "months",
                },
                24,
            ),
            (
                english,
                {
                    "heading": "Republic of Korea – Working Holiday",
                    "anchor": (
                        "be between the ages of 18 and 35 (inclusive)"
                    ),
                    "transform": "inclusive-range",
                    "unit": "age",
                },
                "18-35",
            ),
            (
                french,
                {
                    "heading": "République de Corée — Vacances-travail",
                    "anchor": (
                        "être âgé de 18 à 35 ans, inclusivement"
                    ),
                    "transform": "inclusive-range",
                    "unit": "age",
                },
                "18-35",
            ),
            (
                french,
                {
                    "heading": "République de Corée — Vacances-travail",
                    "anchor": (
                        "Description : les citoyens peuvent participer "
                        "(jusqu’à 24 mois par participation)."
                    ),
                    "transform": "duration-months",
                    "unit": "months",
                },
                24,
            ),
        ]
        for body, params, expected in cases:
            with self.subTest(params=params):
                unit, value = verifier._extract_html_section_text(
                    body, params
                )
                self.assertEqual(unit, params["unit"])
                self.assertEqual(value, expected)
        duplicate = english.replace(
            b"</ul>", b"<li>be between the ages of 18 and 35 (inclusive)</li></ul>"
        )
        age_params = {
            "heading": "Republic of Korea – Working Holiday",
            "anchor": "be between the ages of 18 and 35 (inclusive)",
            "transform": "inclusive-range",
            "unit": "age",
        }
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._extract_html_section_text(duplicate, age_params)
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._extract_html_section_text(
                english.replace(b"<h3>Republic", b"<h2>Republic"), age_params
            )
        for malformed in (
            "be between the ages of 18 and 35",
            "be between the ages of 35 and 18 (inclusive)",
            "be between the ages of 18 and 35 (inclusive) and 36 to 40",
            "Description : jusqu’à 24 mois et 12 mois.",
            "Description : jusqu’à vingt-quatre mois.",
        ):
            transform = (
                "inclusive-range"
                if malformed.startswith("be between")
                else "duration-months"
            )
            with self.subTest(malformed=malformed), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._transform_html_value(malformed, transform)

    def test_fixture_only_manual_review_due_is_inclusive_and_independent(self) -> None:
        registry = deepcopy(self.registry)
        attestation = registry["attestations"][0]
        attestation["verifiedAt"] = "2024-02-29"
        attestation["reviewAfterDays"] = 1000
        attestation["livePolicy"] = {
            "mode": "fixture-only",
            "reason": "Compressed reviewed evidence.",
            "manualReviewDays": 1,
        }
        self.write_json("attestations.json", registry)
        on_due = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            claims_path="claims.json",
            today=date(2024, 3, 1),
        )
        result = next(item for item in on_due.results if item.id == "nz-wage-source")
        self.assertEqual(result.status, "match")
        self.assertEqual(result.manualReview["dueDate"], "2024-03-01")
        next_day = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            claims_path="claims.json",
            today=date(2024, 3, 2),
        )
        result = next(item for item in next_day.results if item.id == "nz-wage-source")
        self.assertEqual(result.status, "unsupported")
        self.assertEqual(result.manualReview["daysOverdue"], 1)
        self.assertEqual(
            result.manualReview["evidenceFingerprint"],
            attestation["fixture"]["sha256"],
        )

    @staticmethod
    def compressed_pdf(content: bytes, *, filter_name: str = "FlateDecode") -> bytes:
        stream = zlib.compress(content)
        header = b"%PDF-1.4\n"
        first = b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        second = (
            b"2 0 obj\n<< /Length "
            + str(len(stream)).encode("ascii")
            + b" /Filter /"
            + filter_name.encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream\nendobj\n"
        )
        prefix = header + first + second
        xref_offset = len(prefix)
        xref = (
            b"xref\n0 3\n0000000000 65535 f \n"
            b"0000000009 00000 n \n0000000048 00000 n \n"
            b"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n"
            + str(xref_offset).encode("ascii")
            + b"\n%%EOF\n"
        )
        return prefix + xref

    @staticmethod
    def multi_stream_pdf(contents: list[bytes]) -> bytes:
        prefix = bytearray(b"%PDF-1.4\n")
        for index, content in enumerate(contents, 1):
            stream = zlib.compress(content)
            prefix.extend(
                f"{index} 0 obj\n<< /Length {len(stream)} "
                "/Filter /FlateDecode >>\nstream\n".encode("ascii")
            )
            prefix.extend(stream)
            prefix.extend(b"\nendstream\nendobj\n")
        xref_offset = len(prefix)
        prefix.extend(
            b"xref\n0 1\n0000000000 65535 f \n"
            b"trailer\n<< /Size 1 >>\nstartxref\n"
            + str(xref_offset).encode("ascii")
            + b"\n%%EOF\n"
        )
        return bytes(prefix)

    def test_bounded_flate_pdf_and_adversarial_features(self) -> None:
        content = (
            b"BT\n(Reviewed rates) Tj\n(Unit|ratio) Tj\n"
            b"(Lower|Upper) Tj\n(0.1|0.2) Tj\nET"
        )
        unit, value = verifier._extract_pdf_table(
            self.compressed_pdf(content),
            self.pdf_attestation()["extractor"]["params"],
        )
        self.assertEqual((unit, value), ("ratio", [[0.1, 0.2]]))
        tj_array = (
            b"BT\n[(Reviewed ) 20 (rates)] TJ\n"
            b"[(Unit|) -5 (ratio)] TJ\n"
            b"[(Lower|Upper)] TJ\n[(0.1|0.2)] TJ\nET"
        )
        self.assertEqual(
            verifier._extract_pdf_table(
                self.compressed_pdf(tj_array),
                self.pdf_attestation()["extractor"]["params"],
            ),
            ("ratio", [[0.1, 0.2]]),
        )
        cases = [
            self.compressed_pdf(content, filter_name="LZWDecode"),
            self.compressed_pdf(content) + b"\ntruncated",
            self.compressed_pdf(content).replace(
                b"/Type /Catalog", b"/Type /Catalog /Encrypt true"
            ),
            self.compressed_pdf(content).replace(
                b"/Type /Catalog", b"/Type /Catalog /ToUnicode 3 0 R"
            ),
            self.compressed_pdf(content + b"\n(Reviewed rates) Tj"),
            self.compressed_pdf(
                b"BT\n(Reviewed rates) Tj\n(Unit|ratio) Tj\n"
                b"(Lower|Upper) Tj\nET"
            ),
            self.compressed_pdf(
                b"BT\n<5265766965776564207261746573> Tj\nET"
            ),
            self.compressed_pdf(
                b"BT\n[(Reviewed ) <7261746573>] TJ\nET"
            ),
            self.compressed_pdf(
                b"(Reviewed rates) Tj\nBT\n(Unit|ratio) Tj\nET"
            ),
            b"%PDF-1.4\nBT\n(Reviewed rates) Tj\nET\n%%EOF\n",
            self.compressed_pdf(content).replace(
                b"/Type /Catalog", b"/Type/XRef"
            ),
            self.compressed_pdf(content).replace(
                b"/Type /Catalog", b"/Type /Catalog /DecodeParms <<>>"
            ),
        ]
        for body in cases:
            with self.subTest(), self.assertRaises(
                (verifier.UnsupportedExtraction, verifier.ChangedExtraction)
            ):
                verifier._extract_pdf_table(
                    body, self.pdf_attestation()["extractor"]["params"]
                )
        with self.assertRaises(verifier.UnsupportedExtraction):
            verifier._bounded_flate(zlib.compress(b"A" * 100_000))
        block = b"".join(
            hashlib.sha256(str(index).encode()).digest()
            for index in range(512)
        )
        aggregate = self.multi_stream_pdf(
            [block * 132, block * 132]
        )
        self.assertLess(len(aggregate), verifier.MAX_BODY_BYTES)
        with self.assertRaises(verifier.UnsupportedExtraction):
            verifier._pdf_literal_lines(aggregate)

    def test_ato_law_lito_current_table_ignores_hidden_history(self) -> None:
        params = {
            "actTitle": "Income Tax Assessment Act 1997",
            "section": "SECTION 61-115",
            "sectionTitle": "Amount of the Low Income tax offset",
            "tableTitle": "Amount of your tax offset",
        }
        current = """
        <h1>Income Tax Assessment Act 1997</h1>
        <div id="lawBody">
        <p><strong>SECTION 61-115</strong>&nbsp;<strong>Amount of the Low Income tax offset</strong>&nbsp;</p>
        <div class="center"><table>
        <tr><th>Amount of your tax offset</th></tr>
        <tr><th>Item</th><th>If your relevant income:</th><th>The amount of your tax offset is:</th></tr>
        <tr><td>1</td><td>does not exceed $ 37,500</td><td>$ 700</td></tr>
        <tr><td>2</td><td>exceeds $ 37,500 but is not more than $ 45,000</td><td>$ 700, less an amount equal to 5% of the excess</td></tr>
        <tr><td>3</td><td>exceeds $ 45,000 but is not more than $ 66,667</td><td>$ 325, less an amount equal to 1.5% of the excess</td></tr>
        </table></div></div>
        """
        hidden = """
        <div id="History_old"><div class="panel-info" style="display:none"><blockquote><table>
        <tr><th>Amount of your tax offset</th></tr>
        <tr><th>Item</th><th>If your relevant income:</th><th>The amount of your tax offset is:</th></tr>
        <tr><td>1</td><td>does not exceed $ 37,000</td><td>$ 645</td></tr>
        </table></blockquote></div></div>
        """
        unit, value = verifier._extract_ato_law_lito(
            (current + hidden).encode("utf-8"), params
        )
        self.assertEqual(unit, verifier.ATO_LITO_UNIT)
        self.assertEqual(
            value,
            {
                "maxOffset": 700,
                "fullTo": 37500,
                "taper1To": 45000,
                "taper1Rate": 0.05,
                "cutOut": 66667,
                "taper2Rate": 0.015,
            },
        )
        mutations = [
            current.replace("Amount of your tax offset</th>", "Wrong</th>", 1),
            current.replace("<th>Item</th>", "<th>Items</th>"),
            current.replace("<td>2</td>", "<td>4</td>"),
            current.replace("does not exceed", "is at most"),
            current.replace("$ 700", "$ 701", 1),
            current.replace("1.5%", "1.6%"),
            current.replace("</table></div>", "</table></div>" + current),
            current.replace(
                '<div id="lawBody">',
                '<div id="other">',
            ),
            current.replace(
                "<p><strong>SECTION 61-115</strong>&nbsp;<strong>"
                "Amount of the Low Income tax offset</strong>&nbsp;</p>",
                "<h2>SECTION 61-115</h2>"
                "<h3>Amount of the Low Income tax offset</h3>",
            ),
            current.replace(
                "<strong>Amount of the Low Income tax offset</strong>",
                "",
            ),
            current.replace(
                "</p>",
                "</p><p><strong>SECTION 61-115</strong>&nbsp;<strong>"
                "Amount of the Low Income tax offset</strong></p>",
                1,
            ),
        ]
        for mutation in mutations:
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_ato_law_lito(
                    (mutation + hidden).encode("utf-8"), params
                )

    def test_ato_resident_law_and_tax_free_band_are_exact(self) -> None:
        title = "Tax rates for resident taxpayers for the 2026-27 year of income"
        table = f"""
        <div id="LawBody"><div class="center"><table>
        <tr><th>{title}</th><th></th><th></th></tr>
        <tr><th>Item</th><th>For the part of the ordinary taxable income of the taxpayer that:</th><th>The rate is:</th></tr>
        <tr><td>1</td><td>exceeds the tax-free threshold but does not exceed $45,000</td><td>15%</td></tr>
        <tr><td>2</td><td>exceeds $45,000 but does not exceed $135,000</td><td>30%</td></tr>
        <tr><td>3</td><td>exceeds $135,000 but does not exceed $190,000</td><td>37%</td></tr>
        <tr><td>4</td><td>exceeds $190,000</td><td>45%</td></tr>
        </table>
        <table><tr><th>Tax rates for resident taxpayers for the 2027-28 year of income</th></tr>
        <tr><th>Item</th><th>For the part of the ordinary taxable income of the taxpayer that:</th><th>The rate is:</th></tr>
        <tr><td>1</td><td>exceeds the tax-free threshold but does not exceed $45,000</td><td>14%</td></tr>
        </table></div></div>
        """
        unit, value = verifier._extract_ato_law_resident_brackets(
            table.encode("utf-8"), {"tableTitle": title}
        )
        self.assertEqual(unit, "AUD/rate")
        self.assertEqual(
            value,
            [[45000, .15], [135000, .3], [190000, .37], [None, .45]],
        )
        self.assertEqual(
            verifier._extract_ato_law_resident_brackets(
                table.replace('id="LawBody"', 'id="lawBody"').encode(
                    "utf-8"
                ),
                {"tableTitle": title},
            )[1],
            value,
        )
        for mutation in (
            table.replace("2026-27", "2025-26", 1),
            table.replace("<th>Item</th>", "<th>Items</th>", 1),
            table.replace("<td>3</td>", "<td>5</td>"),
            table.replace("does not exceed $45,000", "is below $45,000", 1),
            table.replace("$135,000", "$134,000", 1),
            table.replace('id="LawBody"', 'id="lawbody"'),
        ):
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_ato_law_resident_brackets(
                    mutation.encode("utf-8"), {"tableTitle": title}
                )
        _unit, changed_rates = verifier._extract_ato_law_resident_brackets(
            table.replace("30%", "31%", 1).encode("utf-8"),
            {"tableTitle": title},
        )
        self.assertNotEqual(changed_rates, value)

        heading = "What is the tax-free threshold"
        anchor = (
            "The tax-free threshold is the amount of income you can earn "
            "before you pay tax. Most Australian residents can claim "
            "tax-free threshold on the first $18,200 of the income they "
            "earn in the income year."
        )
        body = f"<h2>{heading}</h2><p>{anchor}</p>".encode("utf-8")
        self.assertEqual(
            verifier._extract_ato_tax_free_band(
                body, {"heading": heading, "anchor": anchor}
            ),
            ("AUD/rate", [18200, 0]),
        )
        for mutation in (
            body.replace(b"<h2>", b"<h3>"),
            body.replace(b"before you pay tax", b"before tax applies"),
            body.replace(b"the first", b"an initial"),
            body.replace(b"$18,200", b"$19,200"),
            body + body,
        ):
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_ato_tax_free_band(
                    mutation, {"heading": heading, "anchor": anchor}
                )

    def test_target_expected_path_maps_expected_subtree(self) -> None:
        record_path = self.fixture_dir / "nested-policy.json"
        record_path.write_text(
            json.dumps({
                "record": {
                    "unit": {"item": "ratio"},
                    "value": {"item": 0.25},
                }
            }),
            encoding="utf-8",
        )
        registry = deepcopy(self.registry)
        attestation = registry["attestations"][2]
        attestation["expected"] = {
            "type": "object",
            "unit": {"item": "ratio"},
            "value": {"item": 0.25},
        }
        attestation["extractor"]["params"]["pointer"] = "/record"
        attestation["fixture"] = self.fixture(
            "nested-policy.json",
            "application/json",
            attestation["sourceUrl"],
        )
        attestation["targets"][0]["expectedPath"] = "/item"
        attestation["claims"][0]["expectedPath"] = "/item"
        report = self.run_verify(registry)
        self.assertTrue(report.ok, [item.render() for item in report.results])
        broken = deepcopy(registry)
        broken["attestations"][2]["targets"][0]["expectedPath"] = "/missing"
        self.assert_status(self.run_verify(broken), "unsupported")

    def test_cra_t4127_en_fr_normalize_to_one_version(self) -> None:
        cases = [
            (
                b"<h1>T4127-JUL Payroll Deductions Formulas - 123rd Edition - Effective July 1, 2026</h1>",
                {"language": "en"},
            ),
            (
                "<h1>T4127-JUL Formules pour le calcul des retenues sur la paie - 123e édition - En vigueur le 1er juillet 2026</h1>".encode(
                    "utf-8"
                ),
                {"language": "fr"},
            ),
        ]
        for body, params in cases:
            with self.subTest(params=params):
                self.assertEqual(
                    verifier._extract_cra_t4127_version(body, params),
                    ("table version", "T4127-123rd-2026-07"),
                )
        mutations = [
            cases[0][0].replace(b"123rd", b"123th"),
            cases[0][0] + cases[0][0],
            cases[1][0].replace(
                "123e édition".encode(), "123rd Edition".encode()
            ),
        ]
        for body in mutations:
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_cra_t4127_version(
                    body, {"language": "en"}
                )
        self.assertNotEqual(
            verifier._extract_cra_t4127_version(
                cases[0][0].replace(b"July", b"June"),
                {"language": "en"},
            )[1],
            "T4127-123rd-2026-07",
        )

    def test_component_target_scope_is_an_exact_nonoverlapping_partition(self) -> None:
        self.boundary["targets"].append({
            "id": "ca-components",
            "reviewed": {"left": 0.25, "right": 0.25},
        })
        registry = deepcopy(self.registry)
        registry["targetComponents"] = [{
            "targetId": "ca-components",
            "components": [
                {"id": "left-source", "reviewedPaths": ["/left"]},
                {"id": "right-source", "reviewedPaths": ["/right"]},
            ],
        }]
        for name in ("left", "right"):
            attestation = deepcopy(self.json_attestation())
            attestation["id"] = f"component-{name}"
            attestation.pop("claims")
            attestation["targets"] = [{
                "targetId": "ca-components",
                "componentId": f"{name}-source",
                "reviewedPath": f"/{name}",
            }]
            registry["attestations"].append(attestation)
        self.write_json("boundary.json", self.boundary)
        report = self.run_verify(registry)
        self.assertTrue(report.ok, [item.render() for item in report.results])

        mutations = []
        overlap = deepcopy(registry)
        overlap["targetComponents"][0]["components"][1][
            "reviewedPaths"
        ] = ["/left"]
        mutations.append(overlap)
        missing = deepcopy(registry)
        missing["targetComponents"][0]["components"][1][
            "reviewedPaths"
        ] = ["/left"]
        mutations.append(missing)
        root = deepcopy(registry)
        root["targetComponents"][0]["components"][0][
            "reviewedPaths"
        ] = ["/"]
        mutations.append(root)
        wrong_owner = deepcopy(registry)
        wrong_owner["attestations"][-1]["targets"][0][
            "componentId"
        ] = "left-source"
        mutations.append(wrong_owner)
        duplicate_mapping = deepcopy(registry)
        duplicate_mapping["attestations"].append(
            deepcopy(duplicate_mapping["attestations"][-1])
        )
        duplicate_mapping["attestations"][-1]["id"] = "component-right-two"
        mutations.append(duplicate_mapping)
        for mutation in mutations:
            with self.subTest():
                self.assert_status(self.run_verify(mutation), "unsupported")

    def test_cra_t4127_csv_fixed_cohorts_and_adversarial_mutations(self) -> None:
        rates = (
            '"Table 8.1 Rates (R, V), income thresholds (A), and constants (K, KP) effective July 1, 2026",,,,,,,,,\r\n'
            ',,1st,2nd,3rd,4th,5th,6th,7th,8th\r\n'
            'Federal,A,0,"58,523","117,045","181,440","258,482",,,\r\n'
            ',R,0.14,0.205,0.26,0.29,0.33,,,\r\n'
            ',K,0,"3,804","10,241","15,685","26,024",,,\r\n'
            'BC,A,0,"50,363","100,728","115,648","140,430","190,405","265,545",\r\n'
            ',V,0.0614,0.077,0.105,0.1229,0.147,0.168,0.205,\r\n'
            ',KP,0,786,"3,606","5,676","9,061","13,059","22,884",\r\n'
        ).encode("cp1252")
        base = {
            "publication": "T4127-123rd",
            "effectiveDate": "2026-07-01",
            "encoding": "windows-1252",
        }
        unit, value = verifier._extract_cra_t4127_csv(
            rates, {**base, "cohort": "table-8.1-federal-rates"}
        )
        self.assertEqual(unit, {"brackets": "CAD/rate"})
        self.assertEqual(value["brackets"][0], [58523, 0.14])
        self.assertEqual(value["brackets"][-1], [None, 0.33])
        bc_unit, bc_value = verifier._extract_cra_t4127_csv(
            rates,
            {**base, "cohort": "table-8.1-bc-thresholds-tail-rates"},
        )
        self.assertEqual(
            bc_unit,
            {"thresholds": "CAD", "ratesAfterFirst": "decimal rate"},
        )
        self.assertEqual(len(bc_value["thresholds"]), 7)
        self.assertIsNone(bc_value["thresholds"][-1])
        self.assertEqual(len(bc_value["ratesAfterFirst"]), 6)

        for mutation in (
            rates.replace(b"July 1, 2026", b"July 1, 2025", 1),
            rates.replace(b",V,0.0614", b",V,NaN", 1),
            rates.replace(b",V,0.0614", b",X,0.0614", 1),
            rates + rates.splitlines(keepends=True)[5],
            rates.replace(b"0.0614", b"0.056", 1),
        ):
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_cra_t4127_csv(
                    mutation,
                    {**base, "cohort": "table-8.1-bc-thresholds-tail-rates"},
                )

        cpp = (
            "Table 8.3 Canada Pension Plan / Quebec Pension Plan 2026 contribution rates and amounts,,,,,,\r\n"
            "CPP/QPP,Year’s Maximum Pensionable Earnings (YMPE),Basic Exemption,Year’s Maximum Contributory Earnings,Employee  and Employer Total Contribution Rate,Maximum Employee and Employer Total Contribution*,YMPE Before Rounding\r\n"
            ",,,(YMCE),,,\r\n"
            'CPP (Canada except QC),"74,600.00","3,500.00","71,100.00",0.0595,"4,230.45","74,696.54"\r\n'
            'QPP (QC),"74,600.00","3,500.00","71,100.00",0.063,"4,479.30","74,696.54"\r\n'
        ).encode("cp1252")
        cpp_params = {
            "publication": "T4127-122nd",
            "effectiveDate": "2026-01-01",
            "encoding": "windows-1252",
            "cohort": "table-8.3-cpp-total",
        }
        self.assertEqual(
            verifier._extract_cra_t4127_csv(cpp, cpp_params),
            (
                {"ympe": "CAD", "exempt": "CAD", "rate": "decimal rate"},
                {"ympe": 74600, "exempt": 3500, "rate": 0.0595},
            ),
        )
        with self.assertRaises(verifier.UnsupportedExtraction):
            verifier._extract_cra_t4127_csv(
                cpp, {**cpp_params, "encoding": "utf-8"}
            )

        bpa = (
            "Table 8.9 Federal claim codes (using maximum BPAF),,,,\r\n"
            'Claim code,Total claim amount ($) from,Total claim amount ($) to,"Option 1, TC ($)","Option 1, K1 ($)"\r\n'
            "0,No claim amount,No claim amount,0,0\r\n"
            '1,0,"16,452.00","16,452.00","2,303.28"\r\n'
        ).encode("cp1252")
        bpa_params = {
            "publication": "T4127-122nd",
            "effectiveDate": "2026-01-01",
            "encoding": "windows-1252",
            "cohort": "table-8.9-federal-bpa",
        }
        self.assertEqual(
            verifier._extract_cra_t4127_csv(bpa, bpa_params),
            ({"bpa": "CAD"}, {"bpa": 16452}),
        )
        for mutation in (
            bpa.replace(b"16,452.00", b"16,451.00", 1),
            bpa + b'1,0,"16,452.00","16,452.00","2,303.28"\r\n',
        ):
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_cra_t4127_csv(mutation, bpa_params)

    def test_cra_csv_registry_binds_url_date_unit_and_value(self) -> None:
        body = (
            '"Table 8.1 Rates (R, V), income thresholds (A), and constants (K, KP) effective July 1, 2026",,,,,,,,,\r\n'
            ',,1st,2nd,3rd,4th,5th,6th,7th,8th\r\n'
            'Federal,A,0,"58,523","117,045","181,440","258,482",,,\r\n'
            ',R,0.14,0.205,0.26,0.29,0.33,,,\r\n'
            ',K,0,"3,804","10,241","15,685","26,024",,,\r\n'
        ).encode("cp1252")
        path = self.fixture_dir / "cra-rates.csv"
        path.write_bytes(body)
        value = {
            "brackets": [
                [58523, 0.14], [117045, 0.205], [181440, 0.26],
                [258482, 0.29], [None, 0.33],
            ]
        }
        self.boundary["targets"].append({"id": "ca-csv", "reviewed": value})
        self.write_json("boundary.json", self.boundary)
        registry = deepcopy(self.registry)
        citation = (
            "https://www.canada.ca/en/revenue-agency/services/forms-publications/"
            "payroll/t4127-payroll-deductions-formulas/t4127-jul/"
            "t4127-jul-payroll-deductions-formulas.html"
        )
        request_url = (
            "https://www.canada.ca/content/dam/cra-arc/formspubs/pub/"
            "t4127-jul/rates-income-thresholds-constants-26e.csv"
        )
        attestation = {
            "id": "cra-rates-federal",
            "jurisdiction": "CA",
            "sourceUrl": citation,
            "request": {"method": "GET", "url": request_url},
            "verifiedAt": "2026-07-19",
            "effectiveFrom": "2026-07-01",
            "reviewAfterDays": 90,
            "extractor": {
                "mode": "cra-t4127-csv",
                "params": {
                    "publication": "T4127-123rd",
                    "effectiveDate": "2026-07-01",
                    "encoding": "windows-1252",
                    "cohort": "table-8.1-federal-rates",
                },
            },
            "expected": {
                "type": "object",
                "unit": {"brackets": "CAD/rate"},
                "value": value,
            },
            "fixture": self.fixture("cra-rates.csv", "text/csv", request_url),
            "targets": [{"targetId": "ca-csv", "reviewedPath": "/"}],
        }
        registry["attestations"].append(attestation)
        report = self.run_verify(registry)
        self.assertTrue(report.ok, [item.render() for item in report.results])

        wrong_url = deepcopy(registry)
        wrong_url["attestations"][-1]["request"]["url"] = request_url.replace(
            "26e.csv", "25e.csv"
        )
        wrong_url["attestations"][-1]["fixture"]["finalUrl"] = wrong_url[
            "attestations"
        ][-1]["request"]["url"]
        self.assert_status(self.run_verify(wrong_url), "unsupported")

        old_date = deepcopy(registry)
        old_date["attestations"][-1]["extractor"]["params"][
            "effectiveDate"
        ] = "2025-07-01"
        self.assert_status(self.run_verify(old_date), "unsupported")

        wrong_unit = deepcopy(registry)
        wrong_unit["attestations"][-1]["expected"]["unit"] = {
            "brackets": "CAD"
        }
        self.assert_status(self.run_verify(wrong_unit), "changed")

        wrong_expected = deepcopy(registry)
        wrong_expected["attestations"][-1]["expected"]["value"][
            "brackets"
        ][0][0] = 58524
        self.assert_status(self.run_verify(wrong_expected), "unsupported")

        path.write_bytes(body.replace(b"0.205", b"0.206", 1))
        changed_source = deepcopy(registry)
        changed_source["attestations"][-1]["fixture"]["sha256"] = fingerprint(path)
        self.assert_status(self.run_verify(changed_source), "changed")

    def test_cra_bc_and_ontario_fixed_html_components(self) -> None:
        bc = (
            "<h4>British Columbia</h4>"
            "<p>On February 17, 2026, the Government of British Columbia announced a change to the lowest personal income tax rate and the BC tax reduction. For 2026 and subsequent years, the lowest personal tax rate is increased from 5.06% to 5.60%.</p>"
            "<p>Since the employers have used a lower tax rate for the first six months of the year, a prorated lowest personal income tax rate of 6.14% will apply for the remaining six months commencing with the first payroll in July. The tax rates and brackets are as follows:</p>"
            "<p>See Table 8.1 for rates, income thresholds, and constants and Table 8.2 for other rates and amounts. The Option 2 rates will not be prorated.</p>"
        )
        self.assertEqual(
            verifier._extract_cra_t4127_bc_annual_rate(
                bc.encode(), {"effectiveYear": 2026}
            ),
            ({"rate": "decimal rate"}, {"rate": 0.056}),
        )
        for mutation in (
            bc.replace("5.60%", "6.14%", 1),
            bc.replace("not be prorated", "be prorated"),
            bc + bc,
        ):
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_cra_t4127_bc_annual_rate(
                    mutation.encode(), {"effectiveYear": 2026}
                )

        health_items = "".join(
            f"<li>{item}</li>" for item in verifier.CRA_T4032_ON_HEALTH_BLOCKS
        )
        ontario = (
            "<h1>Payroll Deductions Tables - CPP, EI, and income tax deductions - Ontario</h1>"
            f"<h3>Ontario health premium</h3><ul>{health_items}</ul>"
            "<h3>Tax reduction</h3>"
            "<p>Basic personal amount........................................ $300</p>"
            f"<p>{verifier.CRA_T4032_ON_REDUCTION_SENTENCE}</p>"
        )
        unit, value = verifier._extract_cra_t4032_on(
            ontario.encode(), {"effectiveDate": "2026-01-01"}
        )
        self.assertEqual(unit, {"taxReduction": "CAD", "health": "CAD/rate"})
        self.assertEqual(value["taxReduction"], 600)
        self.assertEqual(value["health"]["above"]["cap"], 900)
        for mutation in (
            ontario.replace("$36,000", "$36,001", 1),
            ontario.replace("$300</p>", "$301</p>"),
            ontario + ontario,
        ):
            with self.subTest(), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_cra_t4032_on(
                    mutation.encode(), {"effectiveDate": "2026-01-01"}
                )

    def test_request_and_attestation_budgets_are_bounded(self) -> None:
        attestation = self.html_attestation()

        class Response:
            status = 503
            headers = {"Content-Type": "text/html"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"temporary"

            def geturl(self):
                return attestation["sourceUrl"]

            def getcode(self):
                return self.status

        clocks = iter([0.0, 0.1])
        execution = verifier._live_execution(
            attestation,
            max_attempts=4,
            retry_backoff_ms=100,
            timeout=15,
            request_budget_seconds=0.15,
            urlopen=lambda *_args, **_kwargs: Response(),
            clock=lambda: next(clocks),
            sleeper=lambda _delay: self.fail("budget must stop backoff"),
        )
        self.assertEqual(execution.finalStatus, "transient")
        self.assertEqual(execution.attemptCount, 1)
        self.assertTrue(execution.budgetExhausted)
        self.assertLessEqual(execution.elapsedSeconds, 0.15)

        alt_url = "https://www.employment.govt.nz/minimum-wage/alternate"
        alt_path = self.fixture_dir / "budget-alt.html"
        alt_path.write_bytes((FIXTURES / "employment-wage.html").read_bytes())
        registry = deepcopy(self.registry)
        live_attestation = registry["attestations"][0]
        live_attestation["candidatePolicy"] = {"mode": "available-parity"}
        live_attestation["requestCandidates"] = [
            {
                "id": "primary", "sourceRelation": "citation",
                "request": {"method": "GET"}, "mediaType": "text/html",
                "fixture": deepcopy(live_attestation["fixture"]),
            },
            {
                "id": "alternate", "sourceRelation": "same-host",
                "request": {"method": "GET", "url": alt_url},
                "mediaType": "text/html",
                "fixture": self.fixture("budget-alt.html", "text/html", alt_url),
            },
        ]
        registry["attestations"] = [live_attestation]
        registry["claimScope"] = ["claim-wage"]
        self.boundary = {
            "schemaVersion": 1,
            "targets": [{"id": "nz-wage", "reviewed": {"value": 23.95}}],
        }
        self.claims = {
            "schemaVersion": 1,
            "audit": {},
            "claims": [self.claim(
                "claim-wage", 23.95, "NZD/hour", live_attestation["sourceUrl"]
            )],
        }
        self.write_json("boundary.json", self.boundary)
        self.write_json("claims.json", self.claims)
        self.write_json("attestations.json", registry)
        calls: list[str] = []
        clocks = iter([0.0, 0.1])

        def opener(request, **_kwargs):
            calls.append(request.full_url)
            return Response()

        report = verifier.verify_source_attestations(
            self.root,
            attestations_path="attestations.json",
            boundary_manifest_path="boundary.json",
            claims_path="claims.json",
            mode="live",
            today=TODAY,
            max_attempts=1,
            timeout=1,
            request_budget_seconds=1,
            attestation_budget_seconds=1,
            observation_id="budget.1",
            urlopen=opener,
            clock=lambda: next(clocks),
            sleeper=lambda _delay: None,
        )
        result = next(item for item in report.results if item.id == "nz-wage-source")
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            [item["attemptCount"] for item in result.candidateChain], [1, 0]
        )
        self.assertTrue(result.candidateChain[1]["budgetExhausted"])

    def test_live_transport_headers_and_certificate_error_are_explicit(
        self,
    ) -> None:
        attestation = self.html_attestation()
        captured: list[dict[str, str]] = []

        def certificate_failure(request, **_kwargs):
            captured.append({
                key.lower(): value
                for key, value in request.header_items()
            })
            reason = ssl.SSLCertVerificationError(
                1, "certificate verify failed: reviewed test"
            )
            raise urllib_error.URLError(reason)

        clocks = iter([0.0, 1.1])
        execution = verifier._live_execution(
            attestation,
            max_attempts=1,
            retry_backoff_ms=1,
            timeout=1,
            request_budget_seconds=1,
            urlopen=certificate_failure,
            clock=lambda: next(clocks),
            sleeper=lambda _delay: self.fail("unexpected retry"),
        )
        self.assertEqual(captured, [{
            "user-agent": (
                "curl/8.7.1 NZ-Navigator-Source-Attestation/1.0"
            ),
            "accept": (
                "text/html,application/xhtml+xml,application/pdf,"
                "application/json;q=0.9,*/*;q=0.1"
            ),
            "connection": "close",
            "accept-encoding": "identity",
        }])
        self.assertEqual(execution.finalStatus, "transient")
        self.assertTrue(execution.budgetExhausted)
        self.assertIn(
            "TLS certificate verification failed",
            execution.response.error,
        )
        self.assertIn(
            "request time budget exhausted", execution.response.error
        )
        result = verifier._evaluate_response(
            attestation,
            execution.response,
            offline=False,
            root=self.root,
        )
        self.assertEqual(result.status, "transient")
        self.assertIn("TLS certificate verification failed", result.actual)


if __name__ == "__main__":
    unittest.main()
