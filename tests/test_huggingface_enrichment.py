"""Tests for the P2 Hugging Face provenance enrichment."""

from __future__ import annotations

import unittest

from aibom.connectors import build_huggingface_findings


class HuggingfaceProvenanceTests(unittest.TestCase):
    def test_unknown_license_is_high_severity_finding(self) -> None:
        findings = build_huggingface_findings(
            "owner/some-model",
            {"siblings": [], "tags": [], "license": "unknown"},
        )
        unknown = [f for f in findings if f.rule_id == "hf.license.unknown"]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0].severity, "high")

    def test_missing_license_field_is_flagged(self) -> None:
        findings = build_huggingface_findings("owner/m", {"siblings": [], "tags": []})
        self.assertTrue(any(f.rule_id == "hf.license.unknown" for f in findings))

    def test_safetensors_present_clears_finding(self) -> None:
        findings = build_huggingface_findings(
            "owner/m",
            {
                "license": "apache-2.0",
                "siblings": [
                    {"rfilename": "model.safetensors"},
                    {"rfilename": "config.json"},
                ],
                "tags": [],
            },
        )
        self.assertFalse(any(f.rule_id == "hf.safetensors.absent" for f in findings))
        self.assertFalse(any(f.rule_id == "hf.license.unknown" for f in findings))

    def test_only_pickle_weights_is_high_severity(self) -> None:
        findings = build_huggingface_findings(
            "owner/m",
            {
                "license": "mit",
                "siblings": [
                    {"rfilename": "pytorch_model.bin"},
                    {"rfilename": "config.json"},
                ],
                "tags": [],
            },
        )
        unsafe = [f for f in findings if f.rule_id == "hf.safetensors.absent"]
        self.assertEqual(len(unsafe), 1)
        self.assertEqual(unsafe[0].severity, "high")
        self.assertGreaterEqual(unsafe[0].metadata["unsafe_weight_count"], 1)

    def test_low_downloads_flagged_as_medium(self) -> None:
        findings = build_huggingface_findings(
            "owner/obscure",
            {"license": "mit", "siblings": [{"rfilename": "model.safetensors"}], "tags": [], "downloads": 7},
        )
        low = [f for f in findings if f.rule_id == "hf.popularity.low"]
        self.assertEqual(len(low), 1)
        self.assertEqual(low[0].severity, "medium")
        self.assertEqual(low[0].metadata["downloads"], 7)

    def test_high_downloads_no_popularity_finding(self) -> None:
        findings = build_huggingface_findings(
            "owner/popular",
            {
                "license": "mit",
                "siblings": [{"rfilename": "model.safetensors"}],
                "tags": [],
                "downloads": 5_000_000,
            },
        )
        self.assertFalse(any(f.rule_id == "hf.popularity.low" for f in findings))


if __name__ == "__main__":
    unittest.main()
