from __future__ import annotations

import unittest

from aibom.connectors import scan_azure_subscription


class AzureTestCase(unittest.TestCase):
    def test_scan_azure_subscription_with_injected_inventory(self) -> None:
        def fake_fetcher(subscription_id: str) -> dict:
            self.assertEqual(subscription_id, "sub-123")
            return {
                "azure_openai_accounts": [
                    {"name": "team-openai", "location": "eastus", "kind": "OpenAI"},
                ],
                "function_apps": [
                    {"name": "chat-fn", "location": "eastus", "settings": {"AZURE_OPENAI_API_KEY": "@Microsoft.KeyVault(...)"}},
                ],
                "storage_accounts": [
                    {"name": "ragdocumentsstore", "location": "eastus"},
                ],
            }

        result = scan_azure_subscription("dev", "sub-123", inventory_fetcher=fake_fetcher)
        names = {finding.name for finding in result.findings}
        self.assertEqual(result.root, "azure://dev/sub-123")
        self.assertIn("Azure OpenAI account", names)
        self.assertIn("Azure Function AI environment reference", names)
        self.assertIn("Azure Storage AI data account", names)

    def test_azure_policy_violation_on_provider(self) -> None:
        def fake_fetcher(subscription_id: str) -> dict:
            return {
                "azure_openai_accounts": [
                    {"name": "team-openai", "location": "eastus", "kind": "OpenAI"},
                ],
                "function_apps": [],
                "storage_accounts": [],
            }

        result = scan_azure_subscription(
            "prod",
            "sub-123",
            inventory_fetcher=fake_fetcher,
            policy={"approved_providers": ["openai"]},
        )
        names = {finding.name for finding in result.findings}
        self.assertIn("Azure OpenAI account policy violation", names)


if __name__ == "__main__":
    unittest.main()
