"""Tests for the P3 IaC parsers — Terraform + Helm/K8s."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.cyclonedx import build_bom
from aibom.iac.helm_k8s import scan_helm_k8s
from aibom.iac.terraform import scan_terraform
from aibom.scanner import scan_path


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


class TerraformParserTests(unittest.TestCase):
    def test_aws_bedrock_resource(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "main.tf", '''
resource "aws_bedrock_foundation_model" "claude" {
  model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
}
''')
            findings = scan_terraform(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].metadata["provider"], "aws-bedrock")
            self.assertEqual(findings[0].metadata["resource_type"], "aws_bedrock_foundation_model")

    def test_azure_cognitive_account(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "azure.tf", '''
resource "azurerm_cognitive_account" "openai" {
  kind = "OpenAI"
  public_network_access = "Enabled"
}
''')
            findings = scan_terraform(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].metadata["provider"], "azure-openai")
            self.assertTrue(findings[0].metadata["review_required"])

    def test_vertex_ai_endpoint(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "gcp.tf", '''
resource "google_vertex_ai_endpoint" "ep" {
  display_name = "prod-ep"
}
''')
            findings = scan_terraform(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].metadata["provider"], "gcp-vertex")

    def test_pinecone_resource(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "vec.tf", 'resource "pinecone_index" "main" { dimension = 1536 }')
            findings = scan_terraform(root)
            self.assertEqual(findings[0].metadata["provider"], "pinecone")

    def test_non_ai_resource_ignored(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "vpc.tf", 'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }')
            self.assertEqual(scan_terraform(root), [])

    def test_skips_terraform_state_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / ".terraform" / "modules" / "x.tf", 'resource "aws_bedrock_x" "y" {}')
            self.assertEqual(scan_terraform(root), [])


class HelmK8sParserTests(unittest.TestCase):
    def test_vllm_image_in_values_yaml(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "values.yaml", '''
serving:
  image: vllm/vllm-openai:v0.6.1
  args: ["--model", "meta-llama/Llama-3-8B"]
''')
            findings = scan_helm_k8s(root)
            self.assertTrue(any(f.metadata["provider"] == "vllm" for f in findings))

    def test_tgi_image_in_deployment(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "deploy.yaml", '''
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: tgi
          image: ghcr.io/huggingface/text-generation-inference:2.0
''')
            findings = scan_helm_k8s(root)
            self.assertTrue(any(f.metadata["provider"] == "huggingface-tgi" for f in findings))
            self.assertEqual(findings[0].severity, "high")

    def test_vector_db_images(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "qdrant.yaml", "image: qdrant/qdrant:v1.10")
            _write(root / "weaviate.yaml", "image: weaviate/weaviate:1.25")
            findings = scan_helm_k8s(root)
            providers = {f.metadata["provider"] for f in findings}
            self.assertIn("qdrant", providers)
            self.assertIn("weaviate", providers)

    def test_ignores_github_workflows(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Even though this references vllm in a workflow, it's not a deployment.
            _write(root / ".github" / "workflows" / "ci.yaml", "image: vllm/vllm-openai:v0.6")
            self.assertEqual(scan_helm_k8s(root), [])

    def test_non_ai_image_ignored(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "web.yaml", "image: nginx:1.27")
            self.assertEqual(scan_helm_k8s(root), [])


class ScannerIntegrationTests(unittest.TestCase):
    def test_iac_findings_appear_in_bom(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "infra.tf", 'resource "aws_bedrock_agent" "x" {}')
            _write(root / "values.yaml", "image: vllm/vllm-openai:v0.6")
            result = scan_path(root)
            bom = build_bom(result)
            service_names = [s["name"] for s in bom["services"]]
            self.assertTrue(any("Terraform" in name for name in service_names))
            self.assertTrue(any("Helm/K8s" in name for name in service_names))


if __name__ == "__main__":
    unittest.main()
