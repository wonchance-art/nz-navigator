from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scripts import verify_runtime_parity as parity


class RuntimeParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "data").mkdir()
        (self.root / "tests" / "fixtures").mkdir(parents=True)
        self.write_page("nz/index.html")

    def write_page(
        self,
        page: str,
        *,
        fee: int | float = 850,
        tax_rate: str = "0.0175",
    ) -> None:
        path = self.root / page
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"""
            <!doctype html><script>
            const DB = {{
              fees: {{
                student: {{ v: {fee}, label: `Student ${{'fee'}}` }},
                levy: {{ v: 100 }}
              }},
              estimates: {{ insurance: {{ v: [600, 800] }} }},
              pathways: [{{
                id: 'A',
                details: {{ requirements: ['18–35 years'] }},
                stages: [{{ name: 'WHV', months: 12 }}]
              }}]
            }};
            const TAX = {{ rate: {tax_rate}, bad: NaN }};
            const BRACKETS = [[15600, 0.105], [Infinity, 0.39]];
            const COMPUTED = 1 + 2;
            </script>
            """,
            encoding="utf-8",
        )

    def claim(
        self,
        claim_id: str,
        value: object,
        unit: str,
        *,
        page: str = "nz/index.html",
        parity_key: str | None = None,
    ) -> dict:
        edition = page.split("/", 1)[0]
        country, locale = {
            "nz": ("NZ", "ko"),
            "ja": ("NZ", "ja"),
            "ca": ("CA", "ko"),
            "au": ("AU", "ko"),
        }[edition]
        result = {
            "id": claim_id,
            "country": country,
            "locale": locale,
            "value": value,
            "unit": unit,
            "pages": [page],
        }
        if parity_key:
            result["parityKey"] = parity_key
        return result

    def binding(
        self,
        claim_id: str,
        runtime_path: str | list[str],
        unit: str,
        *,
        value_type: str = "number",
        page: str = "nz/index.html",
        transform: dict | None = None,
        boundary: str | None = None,
    ) -> dict:
        result = {
            "claimId": claim_id,
            "edition": page.split("/", 1)[0],
            "page": page,
            "runtimePath": runtime_path,
            "type": value_type,
            "unit": unit,
            "transform": transform or {"op": "identity"},
        }
        if boundary:
            result["boundary"] = {"kind": boundary}
        return result

    def write_claims(self, claims: list[dict]) -> None:
        (self.root / "data" / "claims.json").write_text(
            json.dumps({"schemaVersion": 1, "claims": claims}),
            encoding="utf-8",
        )

    def write_bindings(
        self,
        bindings: list[dict],
        *,
        claim_scope: list[str] | None = None,
        parity_keys: list[str] | None = None,
    ) -> None:
        payload = {"schemaVersion": 1, "bindings": bindings}
        if claim_scope is not None:
            payload["claimScope"] = claim_scope
        if parity_keys is not None:
            payload["parityKeys"] = parity_keys
        (self.root / "tests" / "fixtures" / "bindings.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    def verify(self) -> parity.RuntimeReport:
        return parity.verify_runtime_parity(
            self.root,
            claims_path="data/claims.json",
            bindings_path="tests/fixtures/bindings.json",
        )

    def test_actual_four_edition_fixture_passes(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]

        report = parity.verify_runtime_parity(
            repository_root,
            claims_path="data/claims.json",
            bindings_path="tests/fixtures/runtime-bindings.json",
        )

        self.assertTrue(report.ok, [issue.render() for issue in report.issues])
        self.assertEqual(report.checked_bindings, 15)
        age = next(
            item
            for item in report.boundary_cases
            if item["claimId"] == "au-ko-whv-age"
        )
        self.assertEqual(age["values"], ["18", "35"])

    def test_identity_and_stable_array_selector_pass(self) -> None:
        claims = [
            self.claim("student-fee", 850, "NZD"),
            self.claim("whv-months", 12, "months"),
        ]
        bindings = [
            self.binding("student-fee", "DB.fees.student.v", "NZD"),
            self.binding(
                "whv-months",
                "DB.pathways[id=A].stages[0].months",
                "months",
                boundary="duration",
            ),
        ]
        self.write_claims(claims)
        self.write_bindings(bindings)

        report = self.verify()

        self.assertTrue(report.ok, [issue.render() for issue in report.issues])
        self.assertEqual(report.checked_bindings, 2)
        self.assertEqual(report.boundary_cases[0]["values"], ["12"])

    def test_allowlisted_transforms_and_boundaries(self) -> None:
        claims = [
            self.claim("total-fee", 950, "NZD"),
            self.claim("tax-rate", 1.75, "percent"),
            self.claim(
                "brackets",
                "15600@0.105;above@0.39",
                "NZD/rate",
            ),
            self.claim("age", "18-35", "years"),
            self.claim("insurance", "600-800", "NZD"),
        ]
        bindings = [
            self.binding(
                "total-fee",
                ["DB.fees.student.v", "DB.fees.levy.v"],
                "NZD",
                transform={"op": "sum"},
            ),
            self.binding(
                "tax-rate",
                "TAX.rate",
                "percent",
                transform={"op": "multiply", "factor": 100},
                boundary="rate",
            ),
            self.binding(
                "brackets",
                "BRACKETS",
                "NZD/rate",
                value_type="string",
                transform={
                    "op": "serializeBrackets",
                    "infinityLabel": "above",
                },
                boundary="rate",
            ),
            self.binding(
                "age",
                "DB.pathways[id=A].details.requirements[0]",
                "years",
                value_type="string",
                transform={"op": "extractRange"},
                boundary="age",
            ),
            self.binding(
                "insurance",
                "DB.estimates.insurance.v",
                "NZD",
                value_type="string",
                transform={"op": "joinRange"},
                boundary="insurance",
            ),
        ]
        self.write_claims(claims)
        self.write_bindings(bindings)

        report = self.verify()

        self.assertTrue(report.ok, [issue.render() for issue in report.issues])
        self.assertEqual(report.checked_bindings, 5)
        self.assertEqual(len(report.boundary_cases), 4)

    def test_value_mismatch_is_actionable(self) -> None:
        self.write_claims([self.claim("student-fee", 900, "NZD")])
        self.write_bindings(
            [self.binding("student-fee", "DB.fees.student.v", "NZD")]
        )

        report = self.verify()
        issue = next(item for item in report.issues if item.code == "VALUE_MISMATCH")
        rendered = issue.render()

        self.assertIn("claim=student-fee", rendered)
        self.assertIn("edition=nz", rendered)
        self.assertIn("runtimePath=DB.fees.student.v", rendered)
        self.assertIn("actual=850", rendered)
        self.assertIn("expected=900", rendered)
        self.assertIn("Fix:", rendered)

    def test_unit_mismatch_fails_before_value_comparison(self) -> None:
        self.write_claims([self.claim("student-fee", 850, "NZD")])
        self.write_bindings(
            [self.binding("student-fee", "DB.fees.student.v", "CAD")]
        )

        report = self.verify()

        self.assertIn("UNIT_MISMATCH", {issue.code for issue in report.issues})

    def test_type_mismatch_is_reported(self) -> None:
        self.write_claims([self.claim("student-fee", 850, "NZD")])
        self.write_bindings(
            [
                self.binding(
                    "student-fee",
                    "DB.fees.student.v",
                    "NZD",
                    value_type="string",
                )
            ]
        )

        report = self.verify()

        self.assertIn("TYPE_MISMATCH", {issue.code for issue in report.issues})

    def test_orphan_claim_binding_and_duplicate_binding_fail(self) -> None:
        claims = [
            self.claim("student-fee", 850, "NZD"),
            self.claim("unbound", 100, "NZD"),
        ]
        bindings = [
            self.binding("student-fee", "DB.fees.student.v", "NZD"),
            self.binding("student-fee", "DB.fees.levy.v", "NZD"),
            self.binding("missing-claim", "TAX.rate", "percent"),
        ]
        self.write_claims(claims)
        self.write_bindings(
            bindings,
            claim_scope=["student-fee", "unbound", "missing-claim"],
        )

        report = self.verify()
        codes = {issue.code for issue in report.issues}

        self.assertIn("DUPLICATE_BINDING", codes)
        self.assertIn("ORPHAN_CLAIM", codes)
        self.assertIn("ORPHAN_BINDING", codes)
        self.assertIn("UNKNOWN_SCOPE_CLAIM", codes)

    def test_bad_selector_and_non_finite_runtime_fail(self) -> None:
        claims = [
            self.claim("missing-path", 1, "count"),
            self.claim("nan-value", 1, "count"),
        ]
        bindings = [
            self.binding("missing-path", "DB.fees.unknown.v", "count"),
            self.binding("nan-value", "TAX.bad", "count"),
        ]
        self.write_claims(claims)
        self.write_bindings(bindings)

        report = self.verify()
        codes = {issue.code for issue in report.issues}

        self.assertIn("BAD_RUNTIME_PATH", codes)
        self.assertIn("NON_FINITE_RUNTIME", codes)

    def test_computed_javascript_expression_is_not_executed(self) -> None:
        self.write_claims([self.claim("computed", 3, "count")])
        self.write_bindings(
            [self.binding("computed", "COMPUTED", "count")]
        )

        report = self.verify()
        issue = next(
            item for item in report.issues if item.code == "EXTRACTION_FAILED"
        )

        self.assertIn("data literal", str(issue.actual))

    def test_edition_mismatch_is_reported(self) -> None:
        self.write_claims([self.claim("student-fee", 850, "NZD")])
        binding = self.binding(
            "student-fee",
            "DB.fees.student.v",
            "NZD",
        )
        binding["edition"] = "ja"
        self.write_bindings([binding])

        report = self.verify()

        self.assertIn("EDITION_MISMATCH", {issue.code for issue in report.issues})

    def test_nz_ja_runtime_parity_mismatch_is_reported(self) -> None:
        self.write_page("ja/index.html", fee=851)
        claims = [
            self.claim(
                "nz-fee",
                850,
                "NZD",
                parity_key="paired-fee",
            ),
            self.claim(
                "ja-fee",
                851,
                "NZD",
                page="ja/index.html",
                parity_key="paired-fee",
            ),
        ]
        bindings = [
            self.binding("nz-fee", "DB.fees.student.v", "NZD"),
            self.binding(
                "ja-fee",
                "DB.fees.student.v",
                "NZD",
                page="ja/index.html",
            ),
        ]
        self.write_claims(claims)
        self.write_bindings(bindings, parity_keys=["paired-fee"])

        report = self.verify()

        self.assertIn(
            "RUNTIME_PARITY_MISMATCH",
            {issue.code for issue in report.issues},
        )

    def test_cli_requires_explicit_bindings(self) -> None:
        stderr = io.StringIO()

        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            parity.main([])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--bindings", stderr.getvalue())

    def test_cli_dumps_boundaries_with_explicit_bindings(self) -> None:
        self.write_claims([self.claim("tax-rate", 1.75, "percent")])
        self.write_bindings(
            [
                self.binding(
                    "tax-rate",
                    "TAX.rate",
                    "percent",
                    transform={"op": "multiply", "factor": 100},
                    boundary="rate",
                )
            ]
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = parity.main(
                [
                    "--root",
                    str(self.root),
                    "--claims",
                    "data/claims.json",
                    "--bindings",
                    "tests/fixtures/bindings.json",
                    "--dump-boundaries",
                ]
            )

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertIn('"claimId": "tax-rate"', stdout.getvalue())

    def test_public_runtime_audit_must_match_verified_totals(self) -> None:
        claims = [self.claim("student-fee", 850, "NZD")]
        (self.root / "data" / "claims.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "audit": {
                        "runtimeBindings": {
                            "claimCount": 99,
                            "bindingCount": 99,
                            "boundarySetCount": 99,
                        }
                    },
                    "claims": claims,
                }
            ),
            encoding="utf-8",
        )
        self.write_bindings(
            [self.binding("student-fee", "DB.fees.student.v", "NZD")]
        )

        production_bindings = self.root / "data" / "runtime-bindings.json"
        production_bindings.write_text(
            (
                self.root
                / "tests"
                / "fixtures"
                / "bindings.json"
            ).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        report = parity.verify_runtime_parity(
            self.root,
            claims_path="data/claims.json",
            bindings_path="data/runtime-bindings.json",
        )

        issue = next(
            item
            for item in report.issues
            if item.code == "PUBLIC_AUDIT_MISMATCH"
        )
        self.assertEqual(issue.claim_id, "<runtime-audit>")
        self.assertIn("runtimeBindings", issue.fix)


if __name__ == "__main__":
    unittest.main()
