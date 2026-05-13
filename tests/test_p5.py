"""Tests for P5 — Annex IV report + NIST AI RMF crosswalk + exec dashboard."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.compliance import generate_annex_iv_html, generate_nist_rmf_html
from aibom.dashboard import generate_executive_dashboard_html
from aibom.scanner import scan_path


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


class AnnexIvReportTests(unittest.TestCase):
    def test_renders_all_nine_sections(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "app.py", "from openai import OpenAI\nclient = OpenAI()\n")
            result = scan_path(root)
            html_doc = generate_annex_iv_html(result)
            for n in range(1, 10):
                self.assertIn(f"id='section-{n}'", html_doc)

    def test_section_7_marked_manual(self) -> None:
        result = scan_path(Path("/tmp"))
        html_doc = generate_annex_iv_html(result)
        # Manual sections (7 = Declaration of Conformity, 8 = Post-market)
        self.assertIn("requires manual completion", html_doc)

    def test_section_2_lists_dataset_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "train.py", 'from datasets import load_dataset\nload_dataset("squad")\n')
            result = scan_path(root)
            html_doc = generate_annex_iv_html(result)
            # The data section should mention the dataset rule
            section_2_start = html_doc.index("id='section-2'")
            section_3_start = html_doc.index("id='section-3'")
            section_2 = html_doc[section_2_start:section_3_start]
            self.assertIn("dataset.huggingface.load", section_2)

    def test_section_4_lists_secret_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "app.py", 'KEY = "sk-1234567890ABCDEFGHIJKLMNOPQR"\n')
            result = scan_path(root)
            html_doc = generate_annex_iv_html(result)
            self.assertIn("secret.ai_key.pattern", html_doc)

    def test_html_is_self_contained(self) -> None:
        result = scan_path(Path("/tmp"))
        html_doc = generate_annex_iv_html(result)
        self.assertNotIn("<script", html_doc)
        self.assertNotIn("<link", html_doc)


class NistRmfTests(unittest.TestCase):
    def test_renders_all_four_functions(self) -> None:
        result = scan_path(Path("/tmp"))
        html_doc = generate_nist_rmf_html(result)
        for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
            self.assertIn(fn, html_doc)

    def test_findings_appear_under_correct_function(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "app.py", "from openai import OpenAI\nclient = OpenAI()\n")
            result = scan_path(root)
            html_doc = generate_nist_rmf_html(result)
            # OpenAI provider rule maps to NIST GV-1.3 + MS-3.3 in owasp_mapping
            self.assertIn("GV-1.3", html_doc)


class ExecutiveDashboardTests(unittest.TestCase):
    def test_renders_kpis(self) -> None:
        result = scan_path(Path("/tmp"))
        html_doc = generate_executive_dashboard_html(result)
        for label in ("Findings", "Files scanned", "AI assets", "Top risk", "Critical findings"):
            self.assertIn(label, html_doc)

    def test_severity_block_present(self) -> None:
        result = scan_path(Path("/tmp"))
        html_doc = generate_executive_dashboard_html(result)
        self.assertIn("Findings by severity", html_doc)

    def test_top_assets_lists_real_components(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "app.py", "from openai import OpenAI\n")
            result = scan_path(root)
            html_doc = generate_executive_dashboard_html(result)
            self.assertIn("Top assets by risk", html_doc)
            self.assertIn("OpenAI", html_doc)

    def test_owasp_coverage_when_findings_have_refs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "app.py", "from openai import OpenAI\n")
            result = scan_path(root)
            html_doc = generate_executive_dashboard_html(result)
            self.assertIn("OWASP LLM Top-10 coverage", html_doc)

    def test_html_is_self_contained(self) -> None:
        result = scan_path(Path("/tmp"))
        html_doc = generate_executive_dashboard_html(result)
        self.assertNotIn("<script", html_doc)
        self.assertNotIn("<link", html_doc)


if __name__ == "__main__":
    unittest.main()
