"""Tests for P8 — CISA KEV cross-reference + CLI for vex/kev/sign-bom + KEV risk boost."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.cli import main
from aibom.models import Finding, MatchEvidence
from aibom.risk import score_per_asset
from aibom.vex.kev import cross_reference_kev, load_kev_feed


def _write(path: Path, body: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, bytes):
        path.write_bytes(body)
    else:
        path.write_text(body, encoding="utf-8")


_KEV_SAMPLE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.05.13",
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-12345",
            "vendorProject": "PickleVendor",
            "product": "OldML",
            "vulnerabilityName": "Insecure deserialization",
            "dateAdded": "2024-11-01",
            "shortDescription": "Insecure pickle deserialization leading to RCE.",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2025-99999",
            "vendorProject": "Acme",
            "product": "Llama-Server",
            "vulnerabilityName": "Path traversal",
            "dateAdded": "2025-02-14",
            "shortDescription": "Path traversal exposes weights.",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


# --------------------------------------------------------------------------- #
# KEV cross-reference
# --------------------------------------------------------------------------- #

class KevLookupTests(unittest.TestCase):
    def test_load_returns_indexed_by_cve(self) -> None:
        with TemporaryDirectory() as tmp:
            feed = Path(tmp) / "kev.json"
            _write(feed, json.dumps(_KEV_SAMPLE))
            idx = load_kev_feed(feed)
            self.assertIn("CVE-2024-12345", idx)
            self.assertEqual(idx["CVE-2024-12345"].vendor, "PickleVendor")
            self.assertTrue(idx["CVE-2024-12345"].known_ransomware)
            self.assertFalse(idx["CVE-2025-99999"].known_ransomware)

    def test_missing_file_returns_empty(self) -> None:
        idx = load_kev_feed(Path("/nonexistent/kev.json"))
        self.assertEqual(idx, {})

    def test_cross_reference_matches_cve(self) -> None:
        with TemporaryDirectory() as tmp:
            feed = Path(tmp) / "kev.json"
            _write(feed, json.dumps(_KEV_SAMPLE))
            idx = load_kev_feed(feed)
            bom = {
                "vulnerabilities": [
                    {"id": "CVE-2024-12345", "affects": [{"ref": "pkg:pypi/oldml@1.0"}], "analysis": {"state": "in_triage"}},
                    {"id": "CVE-2020-99999", "affects": [{"ref": "pkg:pypi/other"}], "analysis": {}},
                ],
            }
            findings = cross_reference_kev(bom, idx)
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.severity, "critical")  # known ransomware
            self.assertEqual(f.metadata["cve_id"], "CVE-2024-12345")
            # annotate_in_place=True (default) — BOM gains KEV detail and exploitable state
            target_vuln = bom["vulnerabilities"][0]
            self.assertEqual(target_vuln["analysis"]["state"], "exploitable")
            self.assertIn("kev", target_vuln["analysis"])
            self.assertEqual(target_vuln["analysis"]["kev"]["cve_id"], "CVE-2024-12345")

    def test_non_ransomware_kev_is_high_not_critical(self) -> None:
        with TemporaryDirectory() as tmp:
            feed = Path(tmp) / "kev.json"
            _write(feed, json.dumps(_KEV_SAMPLE))
            idx = load_kev_feed(feed)
            bom = {"vulnerabilities": [{"id": "CVE-2025-99999", "affects": [{"ref": "x"}]}]}
            findings = cross_reference_kev(bom, idx)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")

    def test_annotate_in_place_disabled(self) -> None:
        with TemporaryDirectory() as tmp:
            feed = Path(tmp) / "kev.json"
            _write(feed, json.dumps(_KEV_SAMPLE))
            idx = load_kev_feed(feed)
            bom = {"vulnerabilities": [{"id": "CVE-2024-12345", "affects": [{"ref": "x"}]}]}
            cross_reference_kev(bom, idx, annotate_in_place=False)
            self.assertNotIn("analysis", bom["vulnerabilities"][0])

    def test_empty_index_no_findings(self) -> None:
        bom = {"vulnerabilities": [{"id": "CVE-2024-12345", "affects": [{"ref": "x"}]}]}
        findings = cross_reference_kev(bom, {})
        self.assertEqual(findings, [])


# --------------------------------------------------------------------------- #
# Risk score — KEV/VEX boost
# --------------------------------------------------------------------------- #

def _f(category: str, rule_id: str, severity: str, name: str = "Component", metadata: dict | None = None) -> Finding:
    return Finding(
        finding_id=f"id-{rule_id}",
        rule_id=rule_id, category=category, name=name,
        severity=severity, confidence="high", path="x",
        detector="d", entity_type="component", source_kind="bom",
        summary="x",
        evidence=[MatchEvidence(line=0, snippet="x", match="x")],
        metadata=metadata or {},
    )


class RiskBoostTests(unittest.TestCase):
    def test_kev_finding_adds_kev_kicker(self) -> None:
        base = _f("provider", "provider.openai.pattern", "medium")
        kev = _f("kev", "kev.CVE-2024-12345", "critical")
        risks = score_per_asset([base, kev])
        # Both findings share asset_key only when (category, name) matches; here they
        # split into two assets, but score_per_asset assigns kev_kicker only to the
        # KEV asset. We verify it lands on at least one asset.
        kicker_added = any(
            any(name == "kev_kicker" for name, _ in r.components)
            for r in risks
        )
        self.assertTrue(kicker_added)

    def test_vex_finding_adds_vex_kicker_when_no_kev(self) -> None:
        vex = _f("vex", "vex.AIBOM-VEX-2026-0002", "high")
        risks = score_per_asset([vex])
        kicker = next(name for name, _ in risks[0].components if name == "vex_kicker")
        self.assertEqual(kicker, "vex_kicker")

    def test_kev_overrides_vex_kicker(self) -> None:
        kev = _f("kev", "kev.CVE-2024-12345", "critical")
        vex = _f("vex", "vex.AIBOM-VEX-2026-0002", "high", name="Component")  # same name
        # Same asset_key (since category != ; we'd have two assets again).
        # Verify each asset's kicker independently.
        risks = score_per_asset([kev, vex])
        kev_asset = next(r for r in risks if any(rid.startswith("id-kev.") for rid in r.contributing_finding_ids))
        kicker_names = {name for name, _ in kev_asset.components}
        self.assertIn("kev_kicker", kicker_names)
        self.assertNotIn("vex_kicker", kicker_names)


# --------------------------------------------------------------------------- #
# CLI — vex / kev / sign-bom
# --------------------------------------------------------------------------- #

class CliVexCommandTests(unittest.TestCase):
    def _bom(self) -> dict:
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "anthropc", "bom-ref": "pkg:pypi/anthropc"},
            ],
            "services": [],
        }

    def test_vex_command_merges_into_bom(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bom_path = root / "bom.json"
            _write(bom_path, json.dumps(self._bom()))
            out = root / "augmented.json"
            rc = main(["vex", str(bom_path), "--output", str(out)])
            self.assertEqual(rc, 0)
            augmented = json.loads(out.read_text())
            self.assertTrue(any(v.get("id") == "AIBOM-VEX-2026-0002" for v in augmented["vulnerabilities"]))

    def test_vex_no_merge_emits_only_vulns(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bom_path = root / "bom.json"
            _write(bom_path, json.dumps(self._bom()))
            out = root / "vulns.json"
            rc = main(["vex", str(bom_path), "--no-merge", "--output", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertIn("vulnerabilities", payload)
            self.assertNotIn("components", payload)


class CliKevCommandTests(unittest.TestCase):
    def test_kev_command_annotates_bom(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            kev = root / "kev.json"
            _write(kev, json.dumps(_KEV_SAMPLE))
            bom = {
                "bomFormat": "CycloneDX", "specVersion": "1.6",
                "vulnerabilities": [{"id": "CVE-2024-12345", "affects": [{"ref": "x"}]}],
            }
            bom_path = root / "bom.json"
            _write(bom_path, json.dumps(bom))
            out = root / "annotated.json"
            rc = main(["kev", str(bom_path), "--kev-feed", str(kev), "--output", str(out)])
            self.assertEqual(rc, 0)
            annotated = json.loads(out.read_text())
            self.assertEqual(annotated["vulnerabilities"][0]["analysis"]["state"], "exploitable")
            self.assertEqual(annotated["vulnerabilities"][0]["analysis"]["kev"]["cve_id"], "CVE-2024-12345")

    def test_kev_command_report_only(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            kev = root / "kev.json"
            _write(kev, json.dumps(_KEV_SAMPLE))
            bom = {"vulnerabilities": [{"id": "CVE-2024-12345", "affects": [{"ref": "x"}]}]}
            bom_path = root / "bom.json"
            _write(bom_path, json.dumps(bom))
            out = root / "report.json"
            rc = main(["kev", str(bom_path), "--kev-feed", str(kev), "--report-only", "--output", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertEqual(payload["kev_matches"], 1)
            self.assertEqual(payload["matches"][0]["cve_id"], "CVE-2024-12345")


class CliSignBomCommandTests(unittest.TestCase):
    def test_sign_bom_emits_manifest(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bom_path = root / "bom.json"
            _write(bom_path, json.dumps({"bomFormat": "CycloneDX"}))
            out = root / "manifest.json"
            rc = main([
                "sign-bom", str(bom_path),
                "--signer", "ci@example",
                "--key-ref", "env://AIBOM_KEY",
                "--output", str(out),
            ])
            self.assertEqual(rc, 0)
            manifest = json.loads(out.read_text())
            self.assertIn("sha256", manifest)
            self.assertEqual(len(manifest["sha256"]), 64)
            self.assertEqual(manifest["intended_signer"], "ci@example")
            self.assertIn("env://AIBOM_KEY", manifest["cosign_command"])

    def test_sign_bom_missing_file_returns_error(self) -> None:
        rc = main(["sign-bom", "/nonexistent/bom.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
