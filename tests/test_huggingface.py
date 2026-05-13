from __future__ import annotations

import unittest

from aibom.connectors import scan_huggingface_model


class HuggingFaceTestCase(unittest.TestCase):
    def test_scan_huggingface_model_with_injected_fetcher(self) -> None:
        def fake_fetcher(model_id: str, token: str | None) -> dict:
            self.assertEqual(model_id, "org/demo-model")
            self.assertIsNone(token)
            return {
                "id": model_id,
                "private": False,
                "pipeline_tag": "text-generation",
                "tags": ["llm", "text-generation"],
                "base_model": "mistral-7b",
            }

        result = scan_huggingface_model("org/demo-model", metadata_fetcher=fake_fetcher)
        names = {finding.name for finding in result.findings}
        self.assertEqual(result.root, "huggingface://org/demo-model")
        self.assertIn("Hugging Face model", names)
        self.assertIn("Hugging Face base model", names)
        self.assertIn("Hugging Face generative model usage", names)

    def test_huggingface_policy_violation(self) -> None:
        def fake_fetcher(model_id: str, token: str | None) -> dict:
            return {
                "id": model_id,
                "private": False,
                "pipeline_tag": "text-generation",
                "tags": ["llm", "text-generation"],
                "base_model": "mistral-7b",
            }

        result = scan_huggingface_model(
            "org/demo-model",
            metadata_fetcher=fake_fetcher,
            policy={"approved_models": ["gpt-4o"]},
        )
        names = {finding.name for finding in result.findings}
        self.assertIn("Hugging Face base model policy violation", names)


if __name__ == "__main__":
    unittest.main()
