from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class ClaimLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository_root = Path(__file__).resolve().parents[1]
        cls.runner = cls.repository_root / "scripts" / "verify_claim_lineage.mjs"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "data" / "attestation-fixtures").mkdir(parents=True)
        (self.root / "tests" / "fixtures").mkdir(parents=True)
        for edition in ("nz", "ja", "ca", "au"):
            (self.root / edition).mkdir()
            shutil.copyfile(
                self.repository_root / edition / "index.html",
                self.root / edition / "index.html",
            )
        shutil.copytree(
            self.repository_root / "data" / "attestation-fixtures",
            self.root / "data" / "attestation-fixtures",
            dirs_exist_ok=True,
        )
        for name in ("claims.json", "source-attestations.json", "runtime-bindings.json"):
            shutil.copyfile(
                self.repository_root / "data" / name,
                self.root / "data" / name,
            )
        shutil.copyfile(
            self.repository_root / "tests" / "fixtures" / "boundary-executions.json",
            self.root / "tests" / "fixtures" / "boundary-executions.json",
        )
        shutil.copyfile(
            self.repository_root / "tests" / "fixtures" / "claim-lineage.json",
            self.root / "tests" / "fixtures" / "claim-lineage.json",
        )
        self._migrate_fixture_registries()

    @property
    def claims_path(self) -> Path:
        return self.root / "data" / "claims.json"

    @property
    def attestations_path(self) -> Path:
        return self.root / "data" / "source-attestations.json"

    @property
    def bindings_path(self) -> Path:
        return self.root / "data" / "runtime-bindings.json"

    @property
    def boundaries_path(self) -> Path:
        return self.root / "tests" / "fixtures" / "boundary-executions.json"

    @property
    def lineage_path(self) -> Path:
        return self.root / "tests" / "fixtures" / "claim-lineage.json"

    @staticmethod
    def read_json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def claim(self, claim_id: str) -> dict:
        claims = self.read_json(self.claims_path)
        return next(item for item in claims["claims"] if item["id"] == claim_id)

    def mapping(self, target: str) -> dict:
        lineage = self.read_json(self.lineage_path)
        return next(item for item in lineage["mappings"] if item["target"] == target)

    def attestation(self, attestation_id: str) -> dict:
        attestations = self.read_json(self.attestations_path)
        return next(
            item for item in attestations["attestations"]
            if item["id"] == attestation_id
        )

    def _migrate_fixture_registries(self) -> None:
        claims = self.read_json(self.claims_path)
        by_id = {item["id"]: item for item in claims["claims"]}
        resident = by_id["au-ko-tax-brackets-2026"]
        resident["status"] = "derived"
        by_id["ca-ko-tax-on-60000"]["effectiveFrom"] = "2026-07-01"
        by_id["ca-ko-tax-on-60000"]["sourceUrl"] = (
            "https://www.canada.ca/en/revenue-agency/services/"
            "forms-publications/payroll/t4127-payroll-deductions-formulas/"
            "t4127-jul.html"
        )
        for item in by_id.values():
            if item["status"] == "derived" and item["severity"] == "critical":
                item["verifiedAt"] = "2026-07-19"

        open_work = copy.deepcopy(by_id["ca-ko-work-permit-fee"])
        open_work.update({
            "id": "ca-ko-open-work-permit-holder-fee",
            "label": "Open work permit holder fee component",
            "value": 100,
            "verifiedAt": "2026-07-19",
            "effectiveFrom": "2025-12-01",
        })
        by_id[open_work["id"]] = open_work
        crs_source = (
            "https://www.canada.ca/en/immigration-refugees-citizenship/"
            "services/immigrate-canada/express-entry/eligibility/"
            "comprehensive-ranking-system/grid.html"
        )
        crs_components = {
            "ca-ko-crs-age35-no-spouse": ("CRS age 35, no spouse", 77),
            "ca-ko-crs-bachelor-no-spouse": ("CRS bachelor, no spouse", 120),
            "ca-ko-crs-clb7-four-no-spouse": ("CRS CLB 7 in four abilities, no spouse", 68),
            "ca-ko-crs-canadian-work1-no-spouse": ("CRS one year Canadian work, no spouse", 40),
        }
        for claim_id, (label, value) in crs_components.items():
            component = copy.deepcopy(by_id["ca-ko-crs-core-maximum"])
            component.update({
                "id": claim_id,
                "label": label,
                "value": value,
                "unit": "points",
                "status": "official",
                "severity": "critical",
                "verifiedAt": "2026-07-19",
                "effectiveFrom": "2026-07-19",
                "sourceUrl": crs_source,
                "pages": ["ca/index.html"],
            })
            component.pop("effectiveTo", None)
            by_id[claim_id] = component
        claims["claims"] = list(by_id.values())
        self.write_json(self.claims_path, claims)

        fixture = {
            "openWorkPermitHolder": 100,
            "crs": {"age": 77, "education": 120, "language": 68, "experience": 40},
        }
        fixture_path = self.root / "data" / "attestation-fixtures" / "lineage-inputs.json"
        fixture_bytes = json.dumps(fixture, separators=(",", ":")).encode()
        fixture_path.write_bytes(fixture_bytes)
        fixture_contract = {
            "path": "data/attestation-fixtures/lineage-inputs.json",
            "sha256": f"sha256:{hashlib.sha256(fixture_bytes).hexdigest()}",
        }
        attestations = self.read_json(self.attestations_path)
        attestations["attestations"].extend([
            {
                "id": "lineage-open-work-fee",
                "sourceUrl": open_work["sourceUrl"],
                "verifiedAt": "2026-07-19",
                "effectiveFrom": "2025-12-01",
                "reviewAfterDays": 45,
                "expected": {"value": 100, "unit": "CAD"},
                "fixture": fixture_contract,
                "claims": [{"claimId": open_work["id"]}],
            },
            {
                "id": "lineage-crs-components",
                "sourceUrl": crs_source,
                "verifiedAt": "2026-07-19",
                "effectiveFrom": "2026-07-19",
                "reviewAfterDays": 45,
                "expected": {
                    "value": fixture["crs"],
                    "unit": {
                        "age": "points",
                        "education": "points",
                        "language": "points",
                        "experience": "points",
                    },
                },
                "fixture": fixture_contract,
                "claims": [
                    {"claimId": claim_id, "expectedPath": f"/{key}"}
                    for key, claim_id in (
                        ("age", "ca-ko-crs-age35-no-spouse"),
                        ("education", "ca-ko-crs-bachelor-no-spouse"),
                        ("language", "ca-ko-crs-clb7-four-no-spouse"),
                        ("experience", "ca-ko-crs-canadian-work1-no-spouse"),
                    )
                ],
            },
        ])
        self.write_json(self.attestations_path, attestations)

    def run_runner(self, *, coverage: bool = False) -> subprocess.CompletedProcess[str]:
        command = [
            "node", str(self.runner),
            "--root", str(self.root),
            "--claims", "data/claims.json",
            "--attestations", "data/source-attestations.json",
            "--bindings", "data/runtime-bindings.json",
            "--boundaries", "tests/fixtures/boundary-executions.json",
            "--lineage", "tests/fixtures/claim-lineage.json",
            "--today", "2026-07-19",
        ]
        if coverage:
            command.append("--require-critical-coverage")
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def test_actual_four_edition_fixture_executes_all_eleven(self) -> None:
        result = self.run_runner()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("11/11 mapping(s)", result.stdout)
        self.assertIn("11 executed", result.stdout)
        self.assertIn('"derivedCriticalCount":11', result.stdout)

    def test_resident_brackets_are_source_attested_and_serialized(self) -> None:
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("11 executed", result.stdout)

        attestations = self.read_json(self.attestations_path)
        source = next(
            item for item in attestations["attestations"]
            if item["id"] == "au-resident-tax-brackets"
        )
        source["expected"]["value"][0][0] = 46000
        self.write_json(self.attestations_path, attestations)
        changed = self.run_runner()
        self.assertEqual(changed.returncode, 1)
        self.assertIn("BOUNDARY_EVIDENCE_MISMATCH", changed.stderr)
        self.assertIn("claim=au-ko-tax-brackets-2026", changed.stderr)

    def test_resident_bracket_unit_drift_fails(self) -> None:
        attestations = self.read_json(self.attestations_path)
        source = next(
            item for item in attestations["attestations"]
            if item["id"] == "au-resident-tax-free-band"
        )
        source["expected"]["unit"] = "percent"
        self.write_json(self.attestations_path, attestations)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("source unit", result.stderr)
        self.assertIn("AUD/rate", result.stderr)

    def test_mutated_official_input_and_output_drift_fail(self) -> None:
        claims = self.read_json(self.claims_path)
        input_claim = next(
            item for item in claims["claims"]
            if item["id"] == "ca-ko-open-work-permit-holder-fee"
        )
        input_claim["value"] = 101
        output_claim = next(
            item for item in claims["claims"] if item["id"] == "ca-ko-crs-sample-305"
        )
        output_claim["value"] = 306
        self.write_json(self.claims_path, claims)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("INPUT_VALUE_MISMATCH", result.stderr)
        self.assertIn("OUTPUT_CLAIM_MISMATCH", result.stderr)

    def test_calculator_branch_mutation_and_sample_hardcoding_fail(self) -> None:
        nz_page = self.root / "nz" / "index.html"
        source = nz_page.read_text(encoding="utf-8")
        source = source.replace(
            "const acc = Math.min(gross, NP_ACC.cap) * NP_ACC.rate;",
            "const acc = gross * NP_ACC.rate;",
            1,
        )
        nz_page.write_text(source, encoding="utf-8")
        branch = self.run_runner()
        self.assertEqual(branch.returncode, 1)
        self.assertIn("BOUNDARY_GATE_FAILED", branch.stderr)

        self.setUp()
        nz_page = self.root / "nz" / "index.html"
        source = nz_page.read_text(encoding="utf-8")
        source = source.replace(
            "function npTax(g) {",
            "function npTax(g) { if(g === 72_800) return 1;",
            1,
        )
        nz_page.write_text(source, encoding="utf-8")
        hardcoded = self.run_runner()
        self.assertEqual(hardcoded.returncode, 1)
        self.assertIn("reviewed sample literal 72800", hardcoded.stderr)

    def test_crs_component_and_profile_mutations_fail(self) -> None:
        ca_page = self.root / "ca" / "index.html"
        source = ca_page.read_text(encoding="utf-8").replace(
            "a35: 77,",
            "a35: 78,",
            1,
        )
        ca_page.write_text(source, encoding="utf-8")
        component = self.run_runner()
        self.assertEqual(component.returncode, 1)
        self.assertIn("CRS age runtime 78", component.stderr)

        lineage = self.read_json(self.lineage_path)
        profile = next(
            item for item in lineage["mappings"] if item["target"] == "ca-crs-profile-305"
        )
        profile["inputClaimIds"][0] = "ca-ko-crs-age-a99"
        self.write_json(self.lineage_path, lineage)
        mutated_profile = self.run_runner()
        self.assertEqual(mutated_profile.returncode, 1)
        self.assertIn("INPUT_SET_MISMATCH", mutated_profile.stderr)

        self.setUp()
        ca_page = self.root / "ca" / "index.html"
        source = ca_page.read_text(encoding="utf-8").replace(
            "const total = ageScore + eduScore + langScore + expScore;",
            "const total = 305;",
            1,
        )
        ca_page.write_text(source, encoding="utf-8")
        hardcoded = self.run_runner()
        self.assertEqual(hardcoded.returncode, 1)
        self.assertIn("CRS renderer contains reviewed output literal 305", hardcoded.stderr)

        self.setUp()
        claims = self.read_json(self.claims_path)
        age = next(
            item for item in claims["claims"] if item["id"] == "ca-ko-crs-age35-no-spouse"
        )
        age["unit"] = "score"
        self.write_json(self.claims_path, claims)
        attestations = self.read_json(self.attestations_path)
        source = next(
            item for item in attestations["attestations"]
            if item["id"] == "lineage-crs-components"
        )
        source["expected"]["unit"]["age"] = "score"
        self.write_json(self.attestations_path, attestations)
        wrong_unit = self.run_runner()
        self.assertEqual(wrong_unit.returncode, 1)
        self.assertIn("CRS component inputs must use exact points units", wrong_unit.stderr)

    def test_cycle_unknown_and_stale_input_fail_closed(self) -> None:
        lineage = self.read_json(self.lineage_path)
        nz = next(item for item in lineage["mappings"] if item["target"] == "nz-netpay-72800")
        ja = next(item for item in lineage["mappings"] if item["target"] == "ja-netpay-72800")
        nz["inputClaimIds"][0] = "nz-ja-netpay-72800"
        ja["inputClaimIds"][0] = "nz-ko-netpay-72800"
        self.write_json(self.lineage_path, lineage)
        cycle = self.run_runner()
        self.assertEqual(cycle.returncode, 1)
        self.assertIn("LINEAGE_CYCLE", cycle.stderr)

        self.setUp()
        claims = self.read_json(self.claims_path)
        claims["claims"] = [
            item for item in claims["claims"]
            if item["id"] != "ca-ko-open-work-permit-holder-fee"
        ]
        self.write_json(self.claims_path, claims)
        unknown = self.run_runner()
        self.assertEqual(unknown.returncode, 1)
        self.assertIn("UNKNOWN_INPUT_CLAIM", unknown.stderr)

        claims = self.read_json(self.claims_path)
        stale = next(
            item for item in claims["claims"] if item["id"] == "ca-ko-iec-program-fee"
        )
        stale["verifiedAt"] = "2025-01-01"
        self.write_json(self.claims_path, claims)
        stale_result = self.run_runner()
        self.assertEqual(stale_result.returncode, 1)
        self.assertIn("CLAIM_DATE_INVALID", stale_result.stderr)

    def test_unit_type_date_cross_edition_and_parity_fail(self) -> None:
        claims = self.read_json(self.claims_path)
        by_id = {item["id"]: item for item in claims["claims"]}
        by_id["ca-ko-iec-fees"]["unit"] = "USD"
        by_id["ca-ko-pgwp-fee"]["pages"] = ["nz/index.html"]
        by_id["nz-ja-netpay-72800"]["value"] = 57465
        self.write_json(self.claims_path, claims)
        lineage = self.read_json(self.lineage_path)
        item = next(entry for entry in lineage["mappings"] if entry["target"] == "ca-on-netpay-60000")
        item["dates"]["effectiveFrom"] = "2026-01-01"
        invalid_type = next(
            entry for entry in lineage["mappings"]
            if entry["target"] == "nz-ja-whv-uncapped"
        )
        invalid_type["expected"]["type"] = "number"
        self.write_json(self.lineage_path, lineage)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("OUTPUT_CLAIM_MISMATCH", result.stderr)
        self.assertIn("CLAIM_EDITION_MISMATCH", result.stderr)
        self.assertIn("NZ_JA_PARITY_MISMATCH", result.stderr)
        self.assertIn("OUTPUT_DATE_MISMATCH", result.stderr)
        self.assertIn("EXPECTED_SCHEMA_INVALID", result.stderr)

    def test_negative_evidence_zero_one_two_cardinality(self) -> None:
        baseline = self.run_runner()
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        attestation = self.attestation("nz-japan-whv-hero")
        fixture_path = self.root / attestation["fixture"]["path"]
        original = fixture_path.read_text(encoding="utf-8")
        for count in (1, 2):
            changed = original + ("<h4>Quota</h4>" * count)
            fixture_path.write_text(changed, encoding="utf-8")
            attestations = self.read_json(self.attestations_path)
            source = next(
                item for item in attestations["attestations"]
                if item["id"] == "nz-japan-whv-hero"
            )
            source["fixture"]["sha256"] = (
                "sha256:" + hashlib.sha256(changed.encode()).hexdigest()
            )
            self.write_json(self.attestations_path, attestations)
            result = self.run_runner()
            self.assertEqual(result.returncode, 1)
            self.assertIn("LINEAGE_EXECUTION_FAILED", result.stderr)

    def test_duplicate_missing_orphan_and_expression_injection_fail(self) -> None:
        lineage = self.read_json(self.lineage_path)
        lineage["mappings"].append(copy.deepcopy(lineage["mappings"][0]))
        lineage["mappings"][1]["expression"] = "process.exit(0)"
        lineage["mappings"].pop(2)
        self.write_json(self.lineage_path, lineage)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("DUPLICATE_MAPPING", result.stderr)
        self.assertIn("MAPPING_SCHEMA_INVALID", result.stderr)
        self.assertIn("MISSING_MAPPING", result.stderr)
        self.assertNotIn("process.exit(0)\n", result.stdout)

    def test_boundary_component_missing_duplicate_and_partial_fail(self) -> None:
        attestations = self.read_json(self.attestations_path)
        bracket = next(
            item for item in attestations["attestations"]
            if item["id"] == "au-resident-tax-brackets"
        )
        bracket["targets"].pop()
        bracket["targets"].append(copy.deepcopy(bracket["targets"][0]))
        self.write_json(self.attestations_path, attestations)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("BOUNDARY_EVIDENCE_CARDINALITY", result.stderr)
        self.assertIn("au-tax/resident/brackets", result.stderr)

    def _attest_every_official_critical(self) -> None:
        claims = self.read_json(self.claims_path)
        attestations = self.read_json(self.attestations_path)
        covered = {
            mapping["claimId"]
            for item in attestations["attestations"]
            for mapping in item.get("claims", [])
        }
        for item in attestations["attestations"]:
            if any(
                mapping["claimId"] == "nz-ko-whv-quota-2026"
                for mapping in item.get("claims", [])
            ):
                item["effectiveFrom"] = "2026-05-14"
        fixture_path = self.root / "data" / "attestation-fixtures" / "coverage.json"
        fixture_path.write_text("{}", encoding="utf-8")
        fixture = {
            "path": "data/attestation-fixtures/coverage.json",
            "sha256": f"sha256:{hashlib.sha256(b'{}').hexdigest()}",
        }
        for claim in claims["claims"]:
            if (
                claim["status"] != "official"
                or claim["severity"] != "critical"
                or claim["id"] in covered
            ):
                continue
            item = {
                "id": f"coverage-{claim['id']}",
                "sourceUrl": claim["sourceUrl"],
                "verifiedAt": "2026-07-19",
                "effectiveFrom": claim["effectiveFrom"],
                "reviewAfterDays": 45,
                "expected": {"value": claim["value"], "unit": claim["unit"]},
                "fixture": fixture,
                "claims": [{"claimId": claim["id"]}],
            }
            if "effectiveTo" in claim:
                item["effectiveTo"] = claim["effectiveTo"]
            attestations["attestations"].append(item)
        self.write_json(self.attestations_path, attestations)

    def test_strict_critical_coverage_can_reach_zero(self) -> None:
        self._attest_every_official_critical()

        result = self.run_runner(coverage=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"remainingCriticalCount":0', result.stdout)

    def test_public_audit_must_match_exactly(self) -> None:
        first = self.run_runner()
        self.assertEqual(first.returncode, 0, first.stderr)
        audit = json.loads(first.stdout.split("audit=", 1)[1].rsplit(".", 1)[0])
        claims = self.read_json(self.claims_path)
        claims.setdefault("audit", {})["claimLineage"] = audit
        self.write_json(self.claims_path, claims)
        exact = self.run_runner()
        self.assertEqual(exact.returncode, 0, exact.stderr)

        claims = self.read_json(self.claims_path)
        claims["audit"]["claimLineage"]["executedCount"] -= 1
        self.write_json(self.claims_path, claims)
        mismatch = self.run_runner()
        self.assertEqual(mismatch.returncode, 1)
        self.assertIn("PUBLIC_AUDIT_MISMATCH", mismatch.stderr)


if __name__ == "__main__":
    unittest.main()
