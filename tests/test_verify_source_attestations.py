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
        ready_id = ready.to_json()["observationId"]
        self.assertRegex(ready_id, r"^[0-9a-f]{64}$")
        self.assertEqual(ready_id, slower.to_json()["observationId"])
        self.assertNotEqual(
            ready_id, recovered.to_json()["observationId"]
        )
        self.assertNotEqual(ready_id, changed.to_json()["observationId"])
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


if __name__ == "__main__":
    unittest.main()
