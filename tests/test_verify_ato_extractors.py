from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_source_attestations as verifier  # noqa: E402


FIXTURES = ROOT / "tests" / "fixtures" / "source-attestations"


class AtoExtractorContractTests(unittest.TestCase):
    @staticmethod
    def whm_params(
        *,
        row_label: str = "0 – $45,000",
        unit: object | None = None,
    ) -> dict[str, object]:
        return {
            "section": "Working holiday maker tax rates 2025–26",
            "headers": ["Taxable income", "Tax on this income"],
            "result": "scalar",
            "fields": [{
                "key": "whm",
                "rowLabels": [row_label],
                "valueHeader": "Tax on this income",
                "transform": "ato-first-tax-band",
                "unit": unit or {
                    "cap": "AUD",
                    "rate": "decimal rate",
                },
            }],
        }

    @staticmethod
    def lito_params() -> dict[str, object]:
        return {
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

    def test_ato_first_tax_band_returns_aligned_value_and_unit_trees(
        self,
    ) -> None:
        unit, value = verifier._extract_html_table_record(
            (FIXTURES / "ato-whm.html").read_bytes(),
            self.whm_params(),
        )
        self.assertEqual(
            unit, {"cap": "AUD", "rate": "decimal rate"}
        )
        self.assertEqual(value, {"cap": 45000, "rate": 0.15})
        self.assertTrue(verifier._unit_tree_aligned(unit, value))

        extractor = {
            "mode": "html-table-record",
            "params": self.whm_params(),
        }
        verifier._validate_extractor(extractor)
        for wrong_unit in (
            {"cap": "AUD"},
            {"cap": "AUD", "rate": "percent"},
            "AUD/rate",
        ):
            with self.subTest(unit=wrong_unit), self.assertRaises(
                verifier.RegistryError
            ):
                mutated = deepcopy(extractor)
                mutated["params"]["fields"][0]["unit"] = wrong_unit
                verifier._validate_extractor(mutated)

    def test_ato_first_tax_band_cardinality_and_grammar_fail_closed(
        self,
    ) -> None:
        original = (FIXTURES / "ato-whm.html").read_text()
        row = (
            "<tr><td>0 – $45,000</td>"
            "<td>15c for each $1</td></tr>"
        )
        duplicate = original.replace("</tbody>", f"{row}</tbody>")
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._extract_html_table_record(
                duplicate.encode(), self.whm_params()
            )

        missing = original.replace(row, "")
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._extract_html_table_record(
                missing.encode(), self.whm_params()
            )

        label_mutations = (
            "1 – $45,000",
            "0 - $45,000",
            "0 – $045,000",
            "0 – $4,5000",
            "0 – $45,000 and $50,000",
        )
        for label in label_mutations:
            with self.subTest(label=label), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_html_table_record(
                    original.replace("0 – $45,000", label).encode(),
                    self.whm_params(row_label=label),
                )

        for rate in (
            "015c for each $1",
            "15c for each $2",
            "15 cents for each $1",
            "101c for each $1",
            "15c plus 1c for each $1",
        ):
            with self.subTest(rate=rate), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_html_table_record(
                    original.replace("15c for each $1", rate).encode(),
                    self.whm_params(),
                )

    def test_ato_lito_exact_cardinality_continuity_and_arithmetic(
        self,
    ) -> None:
        original = (FIXTURES / "ato-lito.html").read_text()
        params = self.lito_params()
        unit, value = verifier._extract_ato_lito(
            original.encode(), params
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
        self.assertTrue(verifier._unit_tree_aligned(unit, value))

        duplicate = original.replace(
            "</ul>", f"<li>{params['items'][2]}</li></ul>"
        )
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._extract_ato_lito(duplicate.encode(), params)

        first, second = params["items"][:2]
        reordered = original.replace(first, "__FIRST__").replace(
            second, first
        ).replace("__FIRST__", second)
        with self.assertRaises(verifier.ChangedExtraction):
            verifier._extract_ato_lito(reordered.encode(), params)

        mutations = (
            ("$37,500 or less", "$37,50 or less"),
            ("$37,500 or less", "$037,500 or less"),
            ("$37,501 and $45,000", "$37,502 and $45,000"),
            ("$325 minus", "$326 minus"),
            ("1.5 cents", "01.5 cents"),
            ("$66,667", "$66,668"),
        )
        for old, new in mutations:
            mutated = original.replace(old, new)
            mutated_params = deepcopy(params)
            mutated_params["items"] = [
                item.replace(old, new) for item in params["items"]
            ]
            with self.subTest(new=new), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._extract_ato_lito(
                    mutated.encode(), mutated_params
                )

    def test_percentage_number_to_decimal_is_canonical_and_bounded(
        self,
    ) -> None:
        for raw, expected in (
            ("0", 0.0),
            ("12", 0.12),
            ("12.00", 0.12),
            ("100", 1.0),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(
                    verifier._transform_html_value(
                        raw, "percentage-number-to-decimal"
                    ),
                    expected,
                )
        for raw in (
            "012.00",
            "12.00%",
            "12.00 11",
            "-1",
            "+12",
            "101",
            "NaN",
            "Infinity",
        ):
            with self.subTest(raw=raw), self.assertRaises(
                verifier.ChangedExtraction
            ):
                verifier._transform_html_value(
                    raw, "percentage-number-to-decimal"
                )

    def test_content_get_override_is_same_host_official_and_body_free(
        self,
    ) -> None:
        source = "https://www.ato.gov.au/rates-and-calculators"
        content = (
            "https://www.ato.gov.au/api/public/content/"
            "0-2319183b-9958-4848-88f9-ea9dc64b121e"
        )
        verifier._validate_request(
            {"method": "GET", "url": content}, source, "AU"
        )
        context = {
            "sourceUrl": source,
            "request": {"method": "GET", "url": content},
        }
        self.assertEqual(verifier._request_url(context), content)
        self.assertTrue(verifier._request_key(context).startswith(content))

        invalid = (
            {"method": "GET", "url": "https://ato.gov.au/api/public/content/x"},
            {"method": "GET", "url": "https://example.com/content/x"},
            {"method": "GET", "url": content.replace("https:", "http:")},
            {
                "method": "GET",
                "url": content.replace(
                    "www.ato.gov.au", "user@www.ato.gov.au"
                ),
            },
            {"method": "GET", "url": content + "?view=1"},
            {"method": "GET", "url": content + "#fragment"},
            {"method": "GET", "url": content, "jsonBody": {}},
        )
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(
                verifier.RegistryError
            ):
                verifier._validate_request(request, source, "AU")


if __name__ == "__main__":
    unittest.main()
