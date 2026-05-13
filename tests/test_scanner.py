from __future__ import annotations

import unittest
from pathlib import Path

from aibom.reporters import render_cyclonedx, render_sarif
from aibom.scanner import scan_path


FIXTURES = Path(__file__).parent / "fixtures"


class ScannerTestCase(unittest.TestCase):
    def test_python_fixture_detects_manifest_and_code_findings(self) -> None:
        result = scan_path(FIXTURES / "python_app")
        categories = {(finding.category, finding.name) for finding in result.findings}

        self.assertIn(("provider", "OpenAI dependency"), categories)
        self.assertIn(("framework", "LangChain dependency"), categories)
        self.assertIn(("vector_db", "Pinecone dependency"), categories)
        self.assertIn(("provider", "OpenAI usage"), categories)
        self.assertIn(("prompt", "Prompt template or system prompt"), categories)
        self.assertIn(("data_flow", "Possible business data sent to AI flow"), categories)
        self.assertIn(("endpoint", "Possible public AI endpoint"), categories)

    def test_node_fixture_detects_package_json_dependencies(self) -> None:
        result = scan_path(FIXTURES / "node_app")
        categories = {(finding.category, finding.name) for finding in result.findings}

        self.assertIn(("provider", "OpenAI dependency"), categories)
        self.assertIn(("framework", "LangChain dependency"), categories)
        self.assertIn(("vector_db", "Chroma dependency"), categories)

    def test_markdown_files_are_excluded_by_default(self) -> None:
        result = scan_path(FIXTURES / "docs_only")
        self.assertEqual(result.stats.files_scanned, 0)
        self.assertEqual(result.findings, [])

    def test_hardcoded_secret_detection(self) -> None:
        result = scan_path(FIXTURES / "secrets_app")
        categories = {(finding.category, finding.name) for finding in result.findings}
        self.assertIn(("secret", "Possible hardcoded AI secret"), categories)

    def test_sarif_export_contains_rule_and_results(self) -> None:
        result = scan_path(FIXTURES / "python_app")
        sarif = render_sarif(result)

        self.assertIn('"version": "2.1.0"', sarif)
        self.assertIn('"ruleId": "provider.openai.pattern"', sarif)
        self.assertIn('"uri": "app.py"', sarif)

    def test_cyclonedx_export_is_cdx_1_6(self) -> None:
        result = scan_path(FIXTURES / "python_app")
        cyclonedx = render_cyclonedx(result)

        self.assertIn('"bomFormat": "CycloneDX"', cyclonedx)
        self.assertIn('"specVersion": "1.6"', cyclonedx)
        # OpenAI provider appears in services (not components) under 1.6 ML-BOM mapping
        self.assertIn('"name": "OpenAI usage"', cyclonedx)


if __name__ == "__main__":
    unittest.main()
