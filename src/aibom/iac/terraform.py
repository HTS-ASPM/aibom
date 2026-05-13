"""Terraform parser — flags AI/ML resource declarations in .tf files.

We use a regex layer (no HCL parser dep) because Terraform's resource
declaration syntax is regular enough for top-level discovery:

    resource "aws_bedrock_foundation_model" "x" { ... }
    resource "azurerm_cognitive_account"     "y" { ... }
    resource "google_vertex_ai_endpoint"     "z" { ... }

The body is preserved as evidence so reviewers can spot
public_network_access / no-encryption / wildcard-IAM concerns. Deeper
HCL block analysis lives in a future P4 enrichment.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.models import Finding, MatchEvidence


_RESOURCE_RE = re.compile(
    r'resource\s+"(?P<type>[A-Za-z0-9_]+)"\s+"(?P<name>[A-Za-z0-9_]+)"\s*\{',
    re.IGNORECASE,
)


# Resource-type prefix -> (provider, severity, summary)
_AI_RESOURCE_PREFIXES: dict[str, tuple[str, str, str]] = {
    # AWS
    "aws_bedrock_": ("aws-bedrock", "medium", "Terraform declares an AWS Bedrock resource"),
    "aws_sagemaker_endpoint": ("aws-sagemaker", "medium", "Terraform declares a SageMaker endpoint"),
    "aws_sagemaker_model": ("aws-sagemaker", "medium", "Terraform declares a SageMaker model"),
    "aws_comprehend_": ("aws-comprehend", "low", "Terraform declares an AWS Comprehend resource"),
    "aws_textract_": ("aws-textract", "low", "Terraform declares an AWS Textract resource"),
    "aws_rekognition_": ("aws-rekognition", "low", "Terraform declares an AWS Rekognition resource"),
    "aws_kendra_": ("aws-kendra", "medium", "Terraform declares an AWS Kendra (RAG) resource"),
    # Azure
    "azurerm_cognitive_account": ("azure-openai", "medium", "Terraform declares an Azure Cognitive (often AOAI) account"),
    "azurerm_cognitive_deployment": ("azure-openai", "medium", "Terraform declares an Azure OpenAI deployment"),
    "azurerm_machine_learning_": ("azure-ml", "medium", "Terraform declares an Azure ML resource"),
    "azurerm_search_service": ("azure-search", "medium", "Terraform declares an Azure AI Search (vector) service"),
    "azurerm_ai_services": ("azure-ai", "medium", "Terraform declares an Azure AI Services account"),
    # GCP
    "google_vertex_ai_": ("gcp-vertex", "medium", "Terraform declares a Vertex AI resource"),
    "google_dialogflow_": ("gcp-dialogflow", "low", "Terraform declares a Dialogflow resource"),
    "google_document_ai_": ("gcp-docai", "low", "Terraform declares a Document AI resource"),
    "google_discovery_engine_": ("gcp-discovery", "medium", "Terraform declares a Discovery Engine (RAG) resource"),
    # Vector DBs / SaaS
    "pinecone_": ("pinecone", "medium", "Terraform declares a Pinecone vector resource"),
    "weaviate_": ("weaviate", "medium", "Terraform declares a Weaviate vector resource"),
    # Hugging Face TGI / vLLM commonly via runpod / replicate
    "runpod_": ("runpod", "low", "Terraform declares a RunPod deployment (often LLM serving)"),
    "replicate_": ("replicate", "low", "Terraform declares a Replicate deployment"),
    # OpenAI Terraform provider (community)
    "openai_": ("openai", "medium", "Terraform declares an OpenAI provider resource"),
}


_TF_SUFFIXES = {".tf", ".tf.json"}


def scan_terraform(root: Path) -> list[Finding]:
    if not root.exists():
        return []
    if root.is_file():
        if root.suffix.lower() in _TF_SUFFIXES:
            return _scan_file(root, root.parent)
        return []
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _TF_SUFFIXES:
            continue
        if any(part in {".terraform", ".git", ".venv"} for part in path.parts):
            continue
        findings.extend(_scan_file(path, root))
    return findings


def _scan_file(path: Path, root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    rel_path = _rel(path, root)
    findings: list[Finding] = []
    for match in _RESOURCE_RE.finditer(text):
        resource_type = match.group("type")
        resource_name = match.group("name")
        match_info = _classify_resource(resource_type)
        if not match_info:
            continue
        provider, severity, summary = match_info
        line_no = text.count("\n", 0, match.start()) + 1
        block_body = _extract_block_body(text, match.end())
        findings.append(
            Finding(
                finding_id=f"iac.terraform:{provider}:{rel_path}:{resource_name}",
                rule_id="iac.terraform.ai_resource",
                category="provider",
                name=f"Terraform: {resource_type}.{resource_name}",
                severity=severity,
                confidence="high",
                path=rel_path,
                detector="terraform-parser",
                entity_type="iac",
                source_kind="iac",
                summary=summary,
                evidence=[
                    MatchEvidence(
                        line=line_no,
                        snippet=match.group(0)[:220],
                        match=resource_type,
                    ),
                ] + ([
                    MatchEvidence(line=line_no, snippet=block_body[:220], match="block-body"),
                ] if block_body else []),
                metadata={
                    "provider": provider,
                    "iac_kind": "terraform",
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "review_required": _looks_publicly_exposed(block_body),
                },
            )
        )
    return findings


def _classify_resource(resource_type: str) -> tuple[str, str, str] | None:
    lowered = resource_type.lower()
    for prefix, info in _AI_RESOURCE_PREFIXES.items():
        if lowered.startswith(prefix):
            return info
    return None


def _extract_block_body(text: str, start_idx: int, max_chars: int = 600) -> str:
    """Return the contents of the HCL block opened at start_idx (one '{').
    Tracks brace depth; bails after max_chars to keep evidence small.
    """
    depth = 1
    end = start_idx
    while end < len(text) and (end - start_idx) < max_chars:
        ch = text[end]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start_idx:end].strip()
        end += 1
    return text[start_idx:end].strip()


_PUBLIC_HINTS = re.compile(
    r"(?i)public_network_access\s*=\s*\"?(?:enabled|true)|"
    r"public_access\s*=\s*true|"
    r"is_public\s*=\s*true|"
    r"acl\s*=\s*\"?public-read|"
    r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"'
)


def _looks_publicly_exposed(block_body: str) -> bool:
    return bool(_PUBLIC_HINTS.search(block_body))


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
