"""Tests for P9 — CLI wiring for compliance reports, dashboard, unified-bom,
asset-graph, asset-graph-diff, scan-diff."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.cli import main


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _scan_root(tmp: str) -> Path:
    """Build a small scan target with at least one detectable AI signal."""
    root = Path(tmp)
    _write(root / "app.py", "from openai import OpenAI\nclient = OpenAI()\n")
    return root


class CliReportCommandTests(unittest.TestCase):
    def test_annex_iv_report(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            out = root / "annex.html"
            rc = main(["report", "--type", "annex-iv", str(root), "--output", str(out)])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertIn("Annex IV", text)
            for n in range(1, 10):
                self.assertIn(f"id='section-{n}'", text)

    def test_nist_rmf_report(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            out = root / "nist.html"
            rc = main(["report", "--type", "nist-rmf", str(root), "--output", str(out)])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertIn("NIST AI RMF", text)
            for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
                self.assertIn(fn, text)

    def test_iso_42001_report(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            out = root / "iso.html"
            rc = main(["report", "--type", "iso-42001", str(root), "--output", str(out)])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertIn("ISO/IEC 42001", text)

    def test_report_missing_target_returns_error(self) -> None:
        rc = main(["report", "--type", "annex-iv", "/nonexistent/path", "--output", "/tmp/x.html"])
        self.assertEqual(rc, 2)


class CliDashboardCommandTests(unittest.TestCase):
    def test_dashboard_renders_kpis(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            out = root / "dash.html"
            rc = main(["dashboard", str(root), "--output", str(out)])
            self.assertEqual(rc, 0)
            text = out.read_text()
            for label in ("Findings", "Files scanned", "AI assets", "Top risk"):
                self.assertIn(label, text)
            self.assertIn("Findings by severity", text)


class CliUnifiedBomCommandTests(unittest.TestCase):
    def test_unified_bom_merges_external_sbom(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            sbom = {
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": "requests", "version": "2.31"},
                    {"type": "library", "name": "openai", "version": "1.0",
                     "bom-ref": "sbom:openai"},
                ],
                "services": [],
                "dependencies": [],
            }
            sbom_path = root / "sbom.cdx.json"
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            out = root / "merged.cdx.json"
            rc = main(["unified-bom", str(sbom_path), str(root), "--output", str(out)])
            self.assertEqual(rc, 0)
            merged = json.loads(out.read_text())
            self.assertEqual(merged["specVersion"], "1.6")
            names = {c["name"] for c in merged["components"]}
            self.assertIn("requests", names)
            tool_names = {t["name"] for t in merged["metadata"]["tools"]["components"]}
            self.assertIn("aibom", tool_names)

    def test_unified_bom_missing_sbom_returns_error(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            rc = main(["unified-bom", "/nonexistent/sbom.json", str(root), "--output", str(Path(tmp) / "x.json")])
            self.assertEqual(rc, 2)

    def test_unified_bom_invalid_sbom_returns_error(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            bad = root / "bad.json"
            bad.write_text("not json")
            rc = main(["unified-bom", str(bad), str(root), "--output", str(Path(tmp) / "x.json")])
            self.assertEqual(rc, 2)


class CliAssetGraphCommandTests(unittest.TestCase):
    def test_asset_graph_emits_json(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            out = root / "graph.json"
            rc = main(["asset-graph", str(root), "--output", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertIn("nodes", payload)
            self.assertIn("edges", payload)
            self.assertGreater(payload["node_count"], 0)

    def test_asset_graph_no_findings_excludes_finding_nodes(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            out = root / "graph.json"
            rc = main(["asset-graph", str(root), "--no-findings", "--output", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertFalse(any(n["type"] == "finding" for n in payload["nodes"]))


class CliAssetGraphDiffTests(unittest.TestCase):
    def test_diff_two_graphs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            g1 = root / "g1.json"
            g2 = root / "g2.json"
            self.assertEqual(main(["asset-graph", str(root), "--no-findings", "--output", str(g1)]), 0)
            (root / "app.py").write_text(
                "from openai import OpenAI\nfrom anthropic import Anthropic\n",
                encoding="utf-8",
            )
            self.assertEqual(main(["asset-graph", str(root), "--no-findings", "--output", str(g2)]), 0)
            out = root / "diff.json"
            rc = main(["asset-graph-diff", str(g1), str(g2), "--output", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertIn("summary", payload)
            self.assertGreaterEqual(payload["summary"]["nodes_added"], 1)


class CliScanDiffTests(unittest.TestCase):
    def test_scan_diff_json(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            j1 = root / "s1.json"
            j2 = root / "s2.json"
            self.assertEqual(main(["scan", str(root), "--format", "json", "--output", str(j1)]), 0)
            (root / "app.py").write_text(
                "from openai import OpenAI\nfrom anthropic import Anthropic\n",
                encoding="utf-8",
            )
            self.assertEqual(main(["scan", str(root), "--format", "json", "--output", str(j2)]), 0)
            out = root / "diff.json"
            rc = main(["scan-diff", str(j1), str(j2), "--format", "json", "--output", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertIn("summary", payload)

    def test_scan_diff_html(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            j1 = root / "s1.json"
            j2 = root / "s2.json"
            main(["scan", str(root), "--format", "json", "--output", str(j1)])
            (root / "app.py").write_text("import openai\nimport anthropic\n", encoding="utf-8")
            main(["scan", str(root), "--format", "json", "--output", str(j2)])
            out = root / "diff.html"
            rc = main([
                "scan-diff", str(j1), str(j2),
                "--format", "html", "--output", str(out),
                "--older-label", "main", "--newer-label", "feature",
            ])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertIn("AiBOM scan diff", text)
            self.assertIn("main", text)
            self.assertIn("feature", text)


if __name__ == "__main__":
    unittest.main()
