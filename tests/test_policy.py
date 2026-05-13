from __future__ import annotations

import unittest
from pathlib import Path

from aibom.policy import apply_policy, load_policy_file
from aibom.scanner import scan_path


FIXTURES = Path(__file__).parent / "fixtures"


class PolicyTestCase(unittest.TestCase):
    def test_policy_file_loads(self) -> None:
        policy = load_policy_file(str(FIXTURES / "policy.toml"))
        self.assertEqual(policy["approved_providers"], ["openai"])

    def test_policy_override_changes_severity(self) -> None:
        policy = load_policy_file(str(FIXTURES / "policy.toml"))
        result = scan_path(FIXTURES / "python_app")
        updated = apply_policy(result.findings, policy)
        prompt_findings = [item for item in updated if item.rule_id == "prompt.pattern"]
        self.assertTrue(prompt_findings)
        self.assertEqual(prompt_findings[0].severity, "low")

    def test_unapproved_model_becomes_policy_violation(self) -> None:
        fixture = FIXTURES / "policy_app"
        result = scan_path(fixture, policy={"approved_models": ["gpt-4o"]})
        names = {finding.name for finding in result.findings}
        self.assertIn("Model identifier policy violation", names)


if __name__ == "__main__":
    unittest.main()
