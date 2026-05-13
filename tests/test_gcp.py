from __future__ import annotations

import unittest

from aibom.connectors import scan_gcp_project


class GcpTestCase(unittest.TestCase):
    def test_scan_gcp_project_with_injected_inventory(self) -> None:
        def fake_fetcher(project_id: str) -> dict:
            self.assertEqual(project_id, "proj-123")
            return {
                "vertex_endpoints": [
                    {"name": "projects/proj-123/locations/us-central1/endpoints/1", "display_name": "support-bot"},
                ],
                "functions": [
                    {"name": "chat-fn", "environment_variables": {"VERTEX_API_KEY": "secret-ref"}},
                ],
                "buckets": [
                    {"name": "rag-documents-bucket", "location": "US"},
                ],
            }

        result = scan_gcp_project("dev", "proj-123", inventory_fetcher=fake_fetcher)
        names = {finding.name for finding in result.findings}
        self.assertEqual(result.root, "gcp://dev/proj-123")
        self.assertIn("GCP Vertex AI endpoint", names)
        self.assertIn("GCP Function AI environment reference", names)
        self.assertIn("GCP Storage AI data bucket", names)

    def test_gcp_policy_violation_on_provider(self) -> None:
        def fake_fetcher(project_id: str) -> dict:
            return {
                "vertex_endpoints": [
                    {"name": "projects/proj-123/locations/us-central1/endpoints/1", "display_name": "support-bot"},
                ],
                "functions": [],
                "buckets": [],
            }

        result = scan_gcp_project(
            "prod",
            "proj-123",
            inventory_fetcher=fake_fetcher,
            policy={"approved_providers": ["openai"]},
        )
        names = {finding.name for finding in result.findings}
        self.assertIn("GCP Vertex AI endpoint policy violation", names)


if __name__ == "__main__":
    unittest.main()
