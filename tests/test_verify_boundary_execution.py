from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class BoundaryExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository_root = Path(__file__).resolve().parents[1]
        cls.runner = (
            cls.repository_root
            / "scripts"
            / "verify_boundary_execution.mjs"
        )

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "data").mkdir()
        (self.root / "tests" / "fixtures").mkdir(parents=True)
        for edition in ("nz", "ja", "ca", "au"):
            (self.root / edition).mkdir()
            shutil.copyfile(
                self.repository_root / edition / "index.html",
                self.root / edition / "index.html",
            )
        shutil.copyfile(
            self.repository_root / "data" / "claims.json",
            self.root / "data" / "claims.json",
        )
        shutil.copyfile(
            self.repository_root / "data" / "runtime-bindings.json",
            self.root / "data" / "runtime-bindings.json",
        )
        shutil.copyfile(
            self.repository_root
            / "tests"
            / "fixtures"
            / "boundary-executions.json",
            self.root
            / "tests"
            / "fixtures"
            / "boundary-executions.json",
        )

    @property
    def manifest_path(self) -> Path:
        return (
            self.root
            / "tests"
            / "fixtures"
            / "boundary-executions.json"
        )

    def read_manifest(self) -> dict:
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def write_manifest(self, manifest: dict) -> None:
        self.manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    def run_runner(
        self,
        *,
        manifest: str = "tests/fixtures/boundary-executions.json",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "node",
                str(self.runner),
                "--root",
                str(self.root),
                "--claims",
                "data/claims.json",
                "--bindings",
                "data/runtime-bindings.json",
                "--manifest",
                manifest,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_reviewed_four_edition_manifest_runs_143_probes(self) -> None:
        result = self.run_runner()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("16 mapping(s)", result.stdout)
        self.assertIn("4 execution target(s)", result.stdout)
        self.assertIn("143 probe(s)", result.stdout)

    def test_bracket_regression_reports_below_exact_and_above(self) -> None:
        manifest = self.read_manifest()
        manifest["targets"][0]["reviewed"]["brackets"][0][1] = 0.106
        self.write_manifest(manifest)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("BOUNDARY_PROBE_MISMATCH", result.stderr)
        self.assertIn("edition=nz", result.stderr)
        self.assertIn("claim=nz-ko-income-tax-brackets-2026", result.stderr)
        self.assertIn("probe=just-below@15600:15599", result.stderr)
        self.assertIn("probe=exact@15600:15600", result.stderr)
        self.assertIn("probe=just-above@15600:15601", result.stderr)
        self.assertIn("actual=", result.stderr)
        self.assertIn("expected=", result.stderr)
        self.assertIn("Fix:", result.stderr)

    def test_acc_cap_plateau_executes_actual_renderer_expression(self) -> None:
        nz_page = self.root / "nz" / "index.html"
        source = nz_page.read_text(encoding="utf-8")
        source = source.replace(
            "const acc = Math.min(gross, NP_ACC.cap) * NP_ACC.rate;",
            "const acc = gross * NP_ACC.rate;",
            1,
        )
        nz_page.write_text(source, encoding="utf-8")

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("boundary=nz-acc-cap-plateau", result.stderr)
        self.assertIn(
            "probe=just-above@156641:156642",
            result.stderr,
        )
        self.assertIn("claim=nz-ko-acc-cap-2026", result.stderr)

    def test_missing_and_orphan_mapping_fail(self) -> None:
        manifest = self.read_manifest()
        removed = manifest["mappings"].pop(0)
        orphan = copy.deepcopy(removed)
        orphan["claimId"] = "not-a-boundary-claim"
        manifest["mappings"].append(orphan)
        self.write_manifest(manifest)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("MISSING_MAPPING", result.stderr)
        self.assertIn("ORPHAN_MAPPING", result.stderr)
        self.assertIn("claim=nz-ko-whv-duration", result.stderr)
        self.assertIn("claim=not-a-boundary-claim", result.stderr)

    def test_orphan_target_fails(self) -> None:
        manifest = self.read_manifest()
        orphan = copy.deepcopy(manifest["targets"][0])
        orphan["id"] = "unreferenced-nz-target"
        manifest["targets"].append(orphan)
        self.write_manifest(manifest)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("ORPHAN_TARGET", result.stderr)
        self.assertIn("boundary=unreferenced-nz-target", result.stderr)

    def test_semantic_age_probe_uses_claim_boundary(self) -> None:
        claims_path = self.root / "data" / "claims.json"
        claims = json.loads(claims_path.read_text(encoding="utf-8"))
        claim = next(
            item
            for item in claims["claims"]
            if item["id"] == "ca-ko-iec-age"
        )
        claim["value"] = "19-35"
        claims_path.write_text(json.dumps(claims), encoding="utf-8")

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("claim=ca-ko-iec-age", result.stderr)
        self.assertIn("boundary=inclusive-range", result.stderr)
        self.assertIn("probe=exact-min:18", result.stderr)
        self.assertIn("actual=false", result.stderr)
        self.assertIn("expected=true", result.stderr)

    def test_computed_runtime_constant_is_rejected_before_vm(self) -> None:
        nz_page = self.root / "nz" / "index.html"
        source = nz_page.read_text(encoding="utf-8")
        source = source.replace(
            "const NP_ACC = { rate: 0.0175, cap: 156641 };",
            "const NP_ACC = (() => ({ rate: 0.0175, cap: 156641 }))();",
            1,
        )
        nz_page.write_text(source, encoding="utf-8")

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("RUNTIME_EXTRACTION_FAILED", result.stderr)
        self.assertIn("direct object/array literal", result.stderr)

    def test_nested_computed_literal_is_rejected_before_vm(self) -> None:
        nz_page = self.root / "nz" / "index.html"
        source = nz_page.read_text(encoding="utf-8")
        source = source.replace(
            "const NP_ACC = { rate: 0.0175, cap: 156641 };",
            "const NP_ACC = { rate: 0.0175 + 0, cap: 156641 };",
            1,
        )
        nz_page.write_text(source, encoding="utf-8")

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("RUNTIME_EXTRACTION_FAILED", result.stderr)
        self.assertIn("computed binary + expression", result.stderr)

    def test_manifest_rule_omission_is_rejected(self) -> None:
        manifest = self.read_manifest()
        manifest["targets"][2]["rules"].remove("ei-cap-plateau")
        self.write_manifest(manifest)

        result = self.run_runner()

        self.assertEqual(result.returncode, 1)
        self.assertIn("INVALID_MANIFEST", result.stderr)
        self.assertIn("boundary=ca-tax", result.stderr)

    def test_production_manifest_checks_public_probe_audit(self) -> None:
        production_manifest = self.root / "data" / "boundary-executions.json"
        shutil.copyfile(self.manifest_path, production_manifest)
        claims_path = self.root / "data" / "claims.json"
        claims = json.loads(claims_path.read_text(encoding="utf-8"))
        claims["audit"]["runtimeBindings"]["boundaryProbeCount"] = 142
        claims_path.write_text(json.dumps(claims), encoding="utf-8")

        result = self.run_runner(
            manifest="data/boundary-executions.json",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("PUBLIC_AUDIT_MISMATCH", result.stderr)
        self.assertIn("actual=142", result.stderr)
        self.assertIn("expected=143", result.stderr)


if __name__ == "__main__":
    unittest.main()
