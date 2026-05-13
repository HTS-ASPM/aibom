from __future__ import annotations

import unittest
from pathlib import Path

from aibom.scanner import scan_path
from aibom.tuning import load_tuning_file


FIXTURES = Path(__file__).parent / "fixtures"


class TuningTestCase(unittest.TestCase):
    def test_tuning_file_changes_scan_behavior(self) -> None:
        tuning = load_tuning_file(str(FIXTURES / "tuning.toml"))
        result = scan_path(FIXTURES / "python_app", tuning=tuning)

        identities = {(finding.rule_id, finding.path, finding.severity, finding.confidence) for finding in result.findings}
        names = {finding.name for finding in result.findings}

        self.assertNotIn("AI SDK or package reference", names)
        self.assertNotIn(("provider.openai.pattern", "app.py", "medium", "high"), identities)
        self.assertIn(("endpoint.public_ai.same_file", "api.py", "medium", "low"), identities)
        self.assertIn(("data_flow.same_file", "app.py", "high", "medium"), identities)

        prompt_findings = [finding for finding in result.findings if finding.rule_id == "prompt.pattern"]
        self.assertTrue(prompt_findings)
        self.assertTrue(prompt_findings[0].metadata.get("baseline_ignore"))


if __name__ == "__main__":
    unittest.main()
