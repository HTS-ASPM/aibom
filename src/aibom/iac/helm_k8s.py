"""Helm chart + Kubernetes manifest parser for AI workloads.

Detects AI-serving deployments by looking at the container image
reference inside Helm `values.yaml` files and K8s `Deployment` /
`StatefulSet` manifests:

  ghcr.io/huggingface/text-generation-inference   -> TGI
  vllm/vllm-openai                                -> vLLM
  nvcr.io/nvidia/tritonserver                     -> Triton
  ollama/ollama                                   -> Ollama
  ghcr.io/llmware-ai/...                          -> LLMWare
  ray-project/ray                                 -> Ray Serve
  langchain-ai/langserve                          -> LangServe

Pure regex over the raw text — no PyYAML dependency. We intentionally
err on detection-only rather than building a full K8s object model.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.models import Finding, MatchEvidence


_AI_IMAGE_PREFIXES: dict[str, tuple[str, str, str]] = {
    # image-prefix substring -> (label, severity, summary)
    "huggingface/text-generation-inference": (
        "huggingface-tgi", "high",
        "Helm/K8s deploys Hugging Face Text Generation Inference (TGI) — verify auth + rate limits",
    ),
    "vllm/vllm-openai": (
        "vllm", "high",
        "Helm/K8s deploys vLLM OpenAI-compatible server — verify auth + tenant isolation",
    ),
    "nvidia/tritonserver": (
        "triton", "medium",
        "Helm/K8s deploys NVIDIA Triton Inference Server",
    ),
    "ollama/ollama": (
        "ollama", "medium",
        "Helm/K8s deploys Ollama — typically internal LLM serving",
    ),
    "ghcr.io/llmware-ai/": (
        "llmware", "medium",
        "Helm/K8s deploys an LLMWare component",
    ),
    "rayproject/ray": (
        "ray", "low",
        "Helm/K8s deploys Ray (often Ray Serve for ML inference)",
    ),
    "langchain-ai/langserve": (
        "langserve", "medium",
        "Helm/K8s deploys LangServe — likely an agent/RAG endpoint",
    ),
    "berriai/litellm": (
        "litellm", "medium",
        "Helm/K8s deploys LiteLLM proxy — central LLM gateway",
    ),
    "qdrant/qdrant": (
        "qdrant", "medium",
        "Helm/K8s deploys Qdrant vector DB",
    ),
    "weaviate/weaviate": (
        "weaviate", "medium",
        "Helm/K8s deploys Weaviate vector DB",
    ),
    "milvusdb/milvus": (
        "milvus", "medium",
        "Helm/K8s deploys Milvus vector DB",
    ),
    "chromadb/chroma": (
        "chroma", "medium",
        "Helm/K8s deploys Chroma vector DB",
    ),
    "pinecone/pinecone-ts-client": (
        "pinecone", "low",
        "Helm/K8s references a Pinecone client image",
    ),
}


_IMAGE_LINE_RE = re.compile(
    r'^\s*(image|repository|imageRepository)\s*:\s*["\']?([^\s"\'#]+)',
    re.MULTILINE,
)


_YAML_SUFFIXES = {".yaml", ".yml"}


def scan_helm_k8s(root: Path) -> list[Finding]:
    if not root.exists():
        return []
    if root.is_file():
        if root.suffix.lower() in _YAML_SUFFIXES:
            return _scan_file(root, root.parent)
        return []
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _YAML_SUFFIXES:
            continue
        if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
            continue
        # Skip CI workflows — they're not deployments
        if ".github/workflows" in str(path).replace("\\", "/"):
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
    seen: set[str] = set()
    for match in _IMAGE_LINE_RE.finditer(text):
        image = match.group(2).strip()
        match_info = _classify_image(image)
        if not match_info:
            continue
        label, severity, summary = match_info
        if label in seen:
            continue
        seen.add(label)
        line_no = text.count("\n", 0, match.start()) + 1
        findings.append(
            Finding(
                finding_id=f"iac.helm_k8s:{label}:{rel_path}",
                rule_id="iac.helm_k8s.ai_image",
                category="provider",
                name=f"Helm/K8s: {label}",
                severity=severity,
                confidence="high",
                path=rel_path,
                detector="helm-k8s-parser",
                entity_type="iac",
                source_kind="iac",
                summary=summary,
                evidence=[
                    MatchEvidence(line=line_no, snippet=image[:220], match=label),
                ],
                metadata={
                    "provider": label,
                    "iac_kind": "helm-k8s",
                    "image": image,
                },
            )
        )
    return findings


def _classify_image(image: str) -> tuple[str, str, str] | None:
    lowered = image.lower()
    for prefix, info in _AI_IMAGE_PREFIXES.items():
        if prefix in lowered:
            return info
    return None


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
