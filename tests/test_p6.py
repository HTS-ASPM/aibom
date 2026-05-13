"""Tests for P6 — diff + ISO 42001 + SBOM-AiBOM unified view."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.compliance import generate_iso_42001_html
from aibom.cyclonedx import build_bom
from aibom.diff import diff_scans, render_diff_html, render_diff_json
from aibom.models import Finding, MatchEvidence, ScanResult, ScanStats
from aibom.sbom_unified import merge_sbom_aibom
from aibom.scanner import scan_path


def _f(rule_id: str, severity: str, path: str = "x.py") -> Finding:
    return Finding(
        finding_id=f"id-{rule_id}-{path}",
        rule_id=rule_id,
        category="provider",
        name=rule_id,
        severity=severity,
        confidence="high",
        path=path,
        detector="d",
        entity_type="provider",
        source_kind="source",
        summary=f"{rule_id} on {path}",
        evidence=[MatchEvidence(line=1, snippet="x", match=rule_id)],
        metadata={},
    )


def _result_with(*findings: Finding) -> ScanResult:
    return ScanResult(root="/tmp", findings=list(findings), stats=ScanStats(files_scanned=1))


class DiffTests(unittest.TestCase):
    def test_added_finding(self) -> None:
        old = _result_with(_f("a", "low"))
        new = _result_with(_f("a", "low"), _f("b", "high"))
        diff = diff_scans(old, new)
        self.assertEqual(len(diff.added), 1)
        self.assertEqual(diff.added[0].rule_id, "b")
        self.assertEqual(len(diff.removed), 0)
        self.assertEqual(diff.unchanged_count, 1)

    def test_removed_finding(self) -> None:
        old = _result_with(_f("a", "low"), _f("b", "high"))
        new = _result_with(_f("a", "low"))
        diff = diff_scans(old, new)
        self.assertEqual(len(diff.removed), 1)
        self.assertEqual(diff.removed[0].rule_id, "b")

    def test_severity_raised(self) -> None:
        old = _result_with(_f("a", "low"))
        new = _result_with(_f("a", "high"))
        diff = diff_scans(old, new)
        self.assertEqual(len(diff.severity_raised), 1)
        old_f, new_f = diff.severity_raised[0]
        self.assertEqual(old_f.severity, "low")
        self.assertEqual(new_f.severity, "high")

    def test_severity_lowered(self) -> None:
        old = _result_with(_f("a", "high"))
        new = _result_with(_f("a", "low"))
        diff = diff_scans(old, new)
        self.assertEqual(len(diff.severity_lowered), 1)

    def test_unchanged_when_identical(self) -> None:
        old = _result_with(_f("a", "low"))
        new = _result_with(_f("a", "low"))
        diff = diff_scans(old, new)
        self.assertEqual(diff.unchanged_count, 1)
        self.assertFalse(diff.added)
        self.assertFalse(diff.removed)
        self.assertFalse(diff.severity_raised)

    def test_render_json_returns_summary(self) -> None:
        diff = diff_scans(_result_with(_f("a", "low")), _result_with(_f("a", "high")))
        text = render_diff_json(diff)
        self.assertIn("severity_raised", text)
        self.assertIn('"unchanged": 0', text)

    def test_render_html_self_contained(self) -> None:
        diff = diff_scans(_result_with(_f("a", "low")), _result_with(_f("b", "high")))
        html_doc = render_diff_html(diff, older_label="commit-A", newer_label="commit-B")
        self.assertIn("AiBOM scan diff", html_doc)
        self.assertIn("commit-A", html_doc)
        self.assertIn("commit-B", html_doc)
        self.assertNotIn("<script", html_doc)


class Iso42001Tests(unittest.TestCase):
    def test_renders_top_groups(self) -> None:
        result = scan_path(Path("/tmp"))
        html_doc = generate_iso_42001_html(result)
        self.assertIn("ISO/IEC 42001", html_doc)
        # No findings -> no group sections, but the header should still render.

    def test_provider_finding_lands_under_a_5(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("from openai import OpenAI\n", encoding="utf-8")
            result = scan_path(root)
            html_doc = generate_iso_42001_html(result)
            self.assertIn("A.5", html_doc)
            self.assertIn("Supplier relationships", html_doc)

    def test_dataset_finding_lands_under_a_8(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "train.py").write_text(
                "from datasets import load_dataset\nload_dataset('squad')\n",
                encoding="utf-8",
            )
            result = scan_path(root)
            html_doc = generate_iso_42001_html(result)
            self.assertIn("A.8", html_doc)
            self.assertIn("Data acquisition for AI systems", html_doc)


class SbomUnifiedTests(unittest.TestCase):
    def test_merges_components_dedupe_by_identity(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "openai", "version": "1.0", "bom-ref": "sbom:openai"},
                {"type": "library", "name": "requests", "version": "2.31", "bom-ref": "sbom:requests"},
            ],
            "services": [],
            "dependencies": [],
        }
        aibom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "openai", "version": "1.0", "bom-ref": "aibom:openai",
                 "modelCard": {"modelParameters": {"task": "text-generation"}}},
            ],
            "services": [],
            "dependencies": [],
        }
        merged = merge_sbom_aibom(sbom, aibom)
        self.assertEqual(merged["specVersion"], "1.6")
        names = sorted(c["name"] for c in merged["components"])
        self.assertEqual(names, ["openai", "requests"])
        # AiBOM version of openai wins (carries modelCard)
        openai = next(c for c in merged["components"] if c["name"] == "openai")
        self.assertIn("modelCard", openai)

    def test_dependencies_union(self) -> None:
        sbom = {
            "components": [], "services": [],
            "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}],
        }
        aibom = {
            "components": [], "services": [],
            "dependencies": [{"ref": "root", "dependsOn": ["b", "c"]}],
        }
        merged = merge_sbom_aibom(sbom, aibom)
        deps = next(d for d in merged["dependencies"] if d["ref"] == "root")
        self.assertEqual(set(deps["dependsOn"]), {"a", "b", "c"})

    def test_tools_carries_both_sources(self) -> None:
        sbom = {
            "metadata": {"tools": {"components": [{"name": "syft", "version": "1.0"}]}},
            "components": [], "services": [], "dependencies": [],
        }
        aibom = {
            "metadata": {"tools": {"components": [{"name": "aibom", "version": "0.1.0"}]}},
            "components": [], "services": [], "dependencies": [],
        }
        merged = merge_sbom_aibom(sbom, aibom)
        names = {t["name"] for t in merged["metadata"]["tools"]["components"]}
        self.assertEqual(names, {"syft", "aibom"})

    def test_serial_number_is_fresh_urn(self) -> None:
        merged = merge_sbom_aibom(
            {"components": [], "services": [], "dependencies": []},
            {"components": [], "services": [], "dependencies": []},
        )
        self.assertTrue(merged["serialNumber"].startswith("urn:uuid:"))


if __name__ == "__main__":
    unittest.main()
