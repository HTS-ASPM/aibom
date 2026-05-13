from __future__ import annotations

import unittest

from aibom.connectors import scan_aws_account


class AwsTestCase(unittest.TestCase):
    def test_scan_aws_account_with_injected_inventory(self) -> None:
        def fake_fetcher(region: str, profile: str | None) -> dict:
            self.assertEqual(region, "us-east-1")
            self.assertIsNone(profile)
            return {
                "bedrock_models": [
                    {"modelId": "amazon.titan-text-express-v1", "providerName": "aws-bedrock"},
                ],
                "lambdas": [
                    {"FunctionName": "chat-handler", "Environment": {"Variables": {"OPENAI_API_KEY": "secret-ref"}}},
                ],
                "buckets": [
                    {"Name": "customer-rag-documents"},
                ],
            }

        result = scan_aws_account("dev", "us-east-1", inventory_fetcher=fake_fetcher)
        names = {finding.name for finding in result.findings}
        self.assertEqual(result.root, "aws://dev/us-east-1")
        self.assertIn("AWS Bedrock model access", names)
        self.assertIn("AWS Lambda AI environment reference", names)
        self.assertIn("AWS S3 AI data bucket", names)

    def test_aws_policy_violation_on_provider(self) -> None:
        def fake_fetcher(region: str, profile: str | None) -> dict:
            return {
                "bedrock_models": [
                    {"modelId": "amazon.titan-text-express-v1", "providerName": "aws-bedrock"},
                ],
                "lambdas": [],
                "buckets": [],
            }

        result = scan_aws_account(
            "prod",
            "us-east-1",
            inventory_fetcher=fake_fetcher,
            policy={"approved_providers": ["openai"]},
        )
        names = {finding.name for finding in result.findings}
        self.assertIn("AWS Bedrock model access policy violation", names)


if __name__ == "__main__":
    unittest.main()
