"""Tests for P7 — VEX feed + Sigstore signing manifest + asset-graph diff."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.asset_graph import (
    build_asset_graph,
    diff_asset_graphs,
    render_asset_graph_diff_json,
)
from aibom.signing import (
    build_signature_manifest,
    canonicalize_bom,
    hash_bom,
    hash_bom_file,
    invoke_cosign,
)
from aibom.vex import (
    DEFAULT_VEX_FEED,
    cross_reference,
    emit_vex_for_bom,
)
from aibom.vex.cdx_vex import merge_vex_into_bom
from aibom.scanner import scan_path


# --------------------------------------------------------------------------- #
# VEX feed
# --------------------------------------------------------------------------- #

class VexFeedTests(unittest.TestCase):
    def test_default_feed_shape(self) -> None:
        self.assertGreater(len(DEFAULT_VEX_FEED), 0)
        for entry in DEFAULT_VEX_FEED:
            self.assertIn("id", entry)
            self.assertIn("severity", entry)
            self.assertIn("state", entry)
            self.assertIn("match", entry)

    def test_cross_reference_matches_typosquat_name(self) -> None:
        bom = {
            "components": [
                {"type": "library", "name": "anthropc", "bom-ref": "x", "purl": "pkg:pypi/anthropc"},
            ],
            "services": [],
        }
        findings = cross_reference(bom)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.metadata["vex_id"], "AIBOM-VEX-2026-0002")
        self.assertEqual(f.category, "vex")

    def test_cross_reference_matches_purl_substring(self) -> None:
        bom = {
            "components": [{"type": "library", "name": "llama-cpp-python",
                             "purl": "pkg:pypi/llama-cpp-python", "bom-ref": "x"}],
            "services": [],
        }
        findings = cross_reference(bom)
        self.assertTrue(any(f.metadata["vex_id"] == "AIBOM-VEX-2026-0005" for f in findings))

    def test_no_match_no_findings(self) -> None:
        bom = {"components": [{"type": "library", "name": "totally-fine", "bom-ref": "x"}], "services": []}
        self.assertEqual(cross_reference(bom), [])

    def test_emit_vex_produces_cdx_vuln_entries(self) -> None:
        bom = {
            "components": [{"type": "library", "name": "anthropc", "bom-ref": "x"}],
            "services": [],
        }
        vulns = emit_vex_for_bom(bom)
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v["source"]["name"], "aibom-vex-feed")
        self.assertEqual(v["ratings"][0]["severity"], "critical")
        self.assertEqual(v["affects"][0]["ref"], "x")
        self.assertEqual(v["analysis"]["state"], "exploitable")

    def test_merge_vex_into_bom_dedupes_by_id(self) -> None:
        bom = {
            "components": [{"type": "library", "name": "anthropc", "bom-ref": "x"}],
            "services": [],
            "vulnerabilities": [{"id": "AIBOM-VEX-2026-0002", "source": {"name": "manual"}}],
        }
        merged = merge_vex_into_bom(bom)
        ids = [v["id"] for v in merged["vulnerabilities"]]
        self.assertEqual(ids.count("AIBOM-VEX-2026-0002"), 1)


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #

class SigningTests(unittest.TestCase):
    def test_canonicalize_is_deterministic(self) -> None:
        bom_a = {"b": 2, "a": 1}
        bom_b = {"a": 1, "b": 2}
        self.assertEqual(canonicalize_bom(bom_a), canonicalize_bom(bom_b))

    def test_hash_bom_changes_when_content_changes(self) -> None:
        h1 = hash_bom(canonicalize_bom({"x": 1}))
        h2 = hash_bom(canonicalize_bom({"x": 2}))
        self.assertNotEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_build_signature_manifest_includes_cosign_command(self) -> None:
        with TemporaryDirectory() as tmp:
            bom_path = Path(tmp) / "bom.cdx.json"
            bom_path.write_bytes(canonicalize_bom({"bomFormat": "CycloneDX"}))
            manifest = build_signature_manifest(
                bom_path, intended_signer="ci@hts.consulting", key_ref="env://AIBOM_KEY",
            )
            self.assertEqual(len(manifest.sha256), 64)
            self.assertIn("cosign sign-blob", manifest.cosign_command)
            self.assertIn("env://AIBOM_KEY", manifest.cosign_command)
            self.assertEqual(manifest.intended_signer, "ci@hts.consulting")

    def test_invoke_cosign_uses_runner_when_injected(self) -> None:
        with TemporaryDirectory() as tmp:
            bom_path = Path(tmp) / "bom.cdx.json"
            bom_path.write_text("{}")
            captured: dict = {}
            def fake_runner(cmd):
                captured["cmd"] = cmd
                return {"status": 0, "stdout": "ok", "stderr": ""}
            result = invoke_cosign(
                bom_path, key_ref="cosign.key",
                output_signature=Path(tmp) / "bom.sig",
                runner=fake_runner,
            )
            self.assertEqual(result["status"], 0)
            self.assertIn("--key", captured["cmd"])
            self.assertIn("cosign.key", captured["cmd"])
            self.assertIn("--output-signature", captured["cmd"])

    def test_hash_bom_file(self) -> None:
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "bom.cdx.json"
            p.write_bytes(b"hello")
            self.assertEqual(hash_bom_file(p), hash_bom(b"hello"))


# --------------------------------------------------------------------------- #
# Asset graph diff
# --------------------------------------------------------------------------- #

class AssetGraphDiffTests(unittest.TestCase):
    def _scan_two_states(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("from openai import OpenAI\n", encoding="utf-8")
            r1 = scan_path(root)
            g1 = build_asset_graph(r1, include_findings=False)
            (root / "app.py").write_text(
                "from openai import OpenAI\nfrom anthropic import Anthropic\n",
                encoding="utf-8",
            )
            r2 = scan_path(root)
            g2 = build_asset_graph(r2, include_findings=False)
        return g1, g2

    def test_added_node_detected(self) -> None:
        g1, g2 = self._scan_two_states()
        diff = diff_asset_graphs(g1, g2)
        self.assertTrue(any("Anthropic" in n.get("label", "") for n in diff.nodes_added))

    def test_summary_counts(self) -> None:
        g1, g2 = self._scan_two_states()
        diff = diff_asset_graphs(g1, g2)
        summary = diff.to_dict()["summary"]
        self.assertGreaterEqual(summary["nodes_added"], 1)
        self.assertEqual(summary["nodes_removed"], 0)

    def test_render_returns_valid_json(self) -> None:
        g1, g2 = self._scan_two_states()
        text = render_asset_graph_diff_json(g1, g2)
        parsed = json.loads(text)
        self.assertIn("summary", parsed)
        self.assertIn("nodes_added", parsed)

    def test_no_change_returns_empty_diff(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x = 1\n", encoding="utf-8")
            r = scan_path(root)
            g = build_asset_graph(r)
            diff = diff_asset_graphs(g, g)
            summary = diff.to_dict()["summary"]
            self.assertEqual(summary["nodes_added"], 0)
            self.assertEqual(summary["nodes_removed"], 0)
            self.assertEqual(summary["nodes_changed"], 0)


if __name__ == "__main__":
    unittest.main()
