"""CycloneDX 1.6 ML-BOM emitter.

Translates an aibom ScanResult into a valid CycloneDX 1.6 BOM document
with proper AI/ML component types:

  provider       -> service (LLM/API provider, with endpoint + outbound data flow)
  model          -> machine-learning-model (with modelCard)
  embedding      -> library (the SDK reference) — embedding *models* discovered
                    later become machine-learning-model with task = embedding
  framework      -> library (orchestration / agent framework)
  package        -> library (generic AI SDK / dependency)
  vector_db      -> service
  endpoint       -> service
  rag            -> data (data component, classification = retrieval)
  prompt         -> data (data component, classification = prompt-template)
  data_flow      -> data (data component, classification = business-data)

Findings whose category is `env_var` or `secret` are *not* emitted as
BOM components — they're security observations on the root component
and are attached via properties so the receiving ASPM can link them.

Findings are grouped by (category, name) so multiple evidence occurrences
across files attach to a single component as `evidence.occurrences[]`.

Spec references:
  - https://cyclonedx.org/docs/1.6/json/
  - https://cyclonedx.org/capabilities/mlbom/
  - https://cyclonedx.org/use-cases/ai-models-and-model-cards/
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aibom import __version__
from aibom.models import Finding, ScanResult


CDX_SPEC_VERSION = "1.6"


# CDX 1.6 component.type values used by this emitter — kept here for
# readability. The full enum is much larger; we deliberately only emit
# types that map cleanly to detected AI artifacts.
COMPONENT_TYPES = {
    "service": "service",
    "library": "library",
    "data": "data",
    "ml_model": "machine-learning-model",
    "application": "application",
}


# Per-category routing into CDX component shapes. Categories that map to
# `service` produce entries in the `services` array; everything else goes
# into `components`. `_SUPPRESSED` categories are not emitted as components
# (still attached as root properties for ASPM linkage).
_CATEGORY_ROUTING = {
    "provider": "service",
    "vector_db": "service",
    "endpoint": "service",
    "model": "ml_model",
    "model_artifact": "ml_model",
    "framework": "library",
    "embedding": "library",
    "package": "library",
    "rag": "data",
    "prompt": "data",
    "prompt_risk": "data",
    "data_flow": "data",
    "dataset": "data",
}

_SUPPRESSED_CATEGORIES = {"env_var", "secret"}


# Severity → CDX vulnerability rating severity (CDX uses lowercase)
_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def render_cyclonedx(result: ScanResult) -> str:
    """Public entry point — returns a JSON string of a CycloneDX 1.6 BOM."""
    return json.dumps(build_bom(result), indent=2)


def build_bom(result: ScanResult) -> dict[str, Any]:
    """Build the CycloneDX 1.6 BOM dict from a ScanResult.

    Exposed separately so callers (and tests) can inspect / mutate the
    structure before serializing.
    """
    components: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    suppressed_findings: list[Finding] = []

    grouped = _group_findings(result.findings)
    for (category, name), findings in grouped.items():
        if category in _SUPPRESSED_CATEGORIES:
            suppressed_findings.extend(findings)
            continue

        target = _CATEGORY_ROUTING.get(category)
        if target is None:
            # Unknown category — model as a generic data component
            components.append(_build_data_component(category, name, findings))
            continue

        if target == "service":
            services.append(_build_service(category, name, findings))
        elif target == "ml_model":
            components.append(_build_ml_model(category, name, findings))
        elif target == "library":
            components.append(_build_library(category, name, findings))
        elif target == "data":
            components.append(_build_data_component(category, name, findings))

    root_component = _build_root_component(result)
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "serialNumber": _serial_number(result.root),
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "aibom",
                        "version": __version__,
                        "publisher": "HTS Consulting",
                        "externalReferences": [
                            {"type": "vcs", "url": "https://github.com/HTS-ASPM/aibom"},
                        ],
                    }
                ],
            },
            "component": root_component,
            "properties": _root_properties(result, suppressed_findings),
        },
        "components": components,
        "services": services,
        "dependencies": _dependencies(root_component, components, services),
    }
    return bom


# --------------------------------------------------------------------------- #
# Grouping
# --------------------------------------------------------------------------- #

def _group_findings(findings: list[Finding]) -> dict[tuple[str, str], list[Finding]]:
    grouped: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.category, finding.name)].append(finding)
    return grouped


# --------------------------------------------------------------------------- #
# Component builders
# --------------------------------------------------------------------------- #

def _build_root_component(result: ScanResult) -> dict[str, Any]:
    name = Path(result.root).name or "scan-target"
    return {
        "type": "application",
        "bom-ref": _bom_ref("application", name),
        "name": name,
        "version": "0.0.0",
    }


def _build_ml_model(category: str, name: str, findings: list[Finding]) -> dict[str, Any]:
    primary = findings[0]
    provider = _provider_hint(primary)
    model_id = _model_identifier(primary)
    component: dict[str, Any] = {
        "type": COMPONENT_TYPES["ml_model"],
        "bom-ref": _bom_ref(category, name),
        "name": model_id or name,
        "version": "detected",
        "scope": "required",
        "description": primary.summary,
        "modelCard": {
            "bom-ref": _bom_ref("modelcard", name),
            "modelParameters": _model_parameters(primary, model_id),
            "considerations": {
                "useCases": [primary.summary],
            },
            "properties": [
                {"name": "aibom:source", "value": "static-detection"},
                {"name": "aibom:confidence", "value": primary.confidence},
            ],
        },
        "evidence": _evidence(findings),
        "properties": _component_properties(primary),
    }
    # Artifact-inspector findings carry a real file hash — surface it as
    # the canonical CDX evidence.identity record + component.hashes.
    sha = primary.metadata.get("sha256")
    if isinstance(sha, str) and sha:
        component["hashes"] = [{"alg": "SHA-256", "content": sha}]
        component["evidence"].setdefault("identity", []).append(
            {
                "field": "hash",
                "confidence": 1.0,
                "methods": [
                    {"technique": "filename", "confidence": 1.0, "value": primary.path}
                ],
            }
        )
        fmt = primary.metadata.get("format")
        if isinstance(fmt, str):
            component["properties"].append({"name": "aibom:artifact_format", "value": fmt})
    if provider:
        component["supplier"] = {"name": provider}
        component["publisher"] = provider
    purl = _purl_for_model(provider, model_id)
    if purl:
        component["purl"] = purl
    return component


def _build_service(category: str, name: str, findings: list[Finding]) -> dict[str, Any]:
    primary = findings[0]
    provider = _provider_hint(primary) or name
    service: dict[str, Any] = {
        "bom-ref": _bom_ref(category, name),
        "provider": {"name": provider},
        "name": name,
        "description": primary.summary,
        "x-trust-boundary": True,
        "authenticated": True,
        "data": [
            {
                "flow": "outbound",
                "classification": "potentially-sensitive",
            }
        ],
        "properties": _component_properties(primary),
    }
    endpoint = _endpoint_for(primary)
    if endpoint:
        service["endpoints"] = [endpoint]
    return service


def _build_library(category: str, name: str, findings: list[Finding]) -> dict[str, Any]:
    primary = findings[0]
    component: dict[str, Any] = {
        "type": COMPONENT_TYPES["library"],
        "bom-ref": _bom_ref(category, name),
        "name": name,
        "version": "detected",
        "scope": "required",
        "description": primary.summary,
        "evidence": _evidence(findings),
        "properties": _component_properties(primary),
    }
    purl = _purl_for_library(primary)
    if purl:
        component["purl"] = purl
    return component


def _build_data_component(category: str, name: str, findings: list[Finding]) -> dict[str, Any]:
    primary = findings[0]
    classification = {
        "rag": "retrieval-context",
        "prompt": "prompt-template",
        "data_flow": "business-data",
        "dataset": _dataset_classification(primary),
    }.get(category, "ai-related")
    data_type = "dataset" if category == "dataset" else "configuration"
    return {
        "type": COMPONENT_TYPES["data"],
        "bom-ref": _bom_ref(category, name),
        "name": name,
        "description": primary.summary,
        "data": [
            {
                "type": data_type,
                "name": name,
                "classification": classification,
            }
        ],
        "evidence": _evidence(findings),
        "properties": _component_properties(primary),
    }


def _dataset_classification(finding: Finding) -> str:
    source = finding.metadata.get("source") or ""
    if source in {"aws-s3", "gcp-gcs", "azure-blob"}:
        return "object-store"
    if source == "warehouse":
        return "warehouse"
    if source == "lakehouse":
        return "lakehouse"
    if source == "huggingface-datasets":
        return "huggingface-hub"
    if source in {"dvc", "lakefs"}:
        return "versioned"
    return "tabular"


# --------------------------------------------------------------------------- #
# Sub-builders
# --------------------------------------------------------------------------- #

def _model_parameters(finding: Finding, model_id: str | None) -> dict[str, Any]:
    """Best-effort modelCard.modelParameters from a static detection.

    P0: minimal — task is inferred, architecture is left for P1 enrichment
    via Hugging Face metadata.
    """
    task = "text-generation"
    if model_id and "embedding" in model_id.lower():
        task = "text-embedding"
    return {
        "approach": {"type": "supervised"},
        "task": task,
        "datasets": [],
        "inputs": [{"format": "text"}],
        "outputs": [{"format": "text"}],
    }


def _evidence(findings: list[Finding]) -> dict[str, Any]:
    occurrences: list[dict[str, Any]] = []
    for finding in findings:
        for item in finding.evidence[:3]:
            occurrences.append(
                {
                    "location": finding.path,
                    "line": item.line,
                }
            )
    return {"occurrences": occurrences}


def _component_properties(finding: Finding) -> list[dict[str, str]]:
    props: list[dict[str, str]] = [
        {"name": "aibom:category", "value": finding.category},
        {"name": "aibom:rule_id", "value": finding.rule_id},
        {"name": "aibom:entity_type", "value": finding.entity_type},
        {"name": "aibom:source_kind", "value": finding.source_kind},
        {"name": "aibom:severity", "value": finding.severity},
        {"name": "aibom:confidence", "value": finding.confidence},
        {"name": "aibom:path", "value": finding.path},
    ]
    for framework_key in ("owasp_llm", "owasp_mcp", "mitre_atlas", "nist_ai_rmf"):
        values = finding.metadata.get(framework_key)
        if isinstance(values, list):
            for v in values:
                props.append({"name": f"aibom:framework:{framework_key}", "value": str(v)})
    for key, value in sorted(finding.metadata.items()):
        if key in {"owasp_llm", "owasp_mcp", "mitre_atlas", "nist_ai_rmf"}:
            continue  # surfaced as framework properties above
        props.append({"name": f"aibom:meta:{key}", "value": _stringify(value)})
    return props


def _root_properties(result: ScanResult, suppressed: list[Finding]) -> list[dict[str, str]]:
    props = [
        {"name": "aibom:files_scanned", "value": str(result.stats.files_scanned)},
        {"name": "aibom:files_skipped", "value": str(result.stats.files_skipped)},
        {"name": "aibom:bytes_scanned", "value": str(result.stats.bytes_scanned)},
    ]
    for finding in suppressed:
        props.append(
            {
                "name": f"aibom:observation:{finding.category}:{finding.rule_id}",
                "value": f"{finding.path} — {finding.summary}",
            }
        )
    return props


def _dependencies(
    root: dict[str, Any],
    components: list[dict[str, Any]],
    services: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Root depends on every emitted component and service."""
    refs = [c["bom-ref"] for c in components] + [s["bom-ref"] for s in services]
    return [
        {"ref": root["bom-ref"], "dependsOn": refs},
    ]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_PROVIDER_KEYWORDS = {
    "OpenAI": ("openai", "gpt-4", "text-embedding-3"),
    "Anthropic": ("anthropic", "claude"),
    "Google": ("gemini", "vertexai", "palm"),
    "Microsoft": ("azure_openai", "azureopenai", "azure-openai"),
    "Amazon": ("bedrock",),
    "Cohere": ("cohere", "command-r"),
    "Mistral": ("mistral", "mixtral"),
    "Hugging Face": ("huggingface", "hf-"),
}


def _provider_hint(finding: Finding) -> str | None:
    explicit = finding.metadata.get("provider")
    if isinstance(explicit, str) and explicit:
        return _normalize_provider(explicit)
    haystack = f"{finding.name} {finding.summary}".lower()
    for label, keywords in _PROVIDER_KEYWORDS.items():
        if any(k in haystack for k in keywords):
            return label
    return None


def _normalize_provider(value: str) -> str:
    table = {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "google": "Google",
        "azure-openai": "Microsoft",
        "azureopenai": "Microsoft",
        "aws-bedrock": "Amazon",
        "cohere-or-mistral": "Cohere",
        "huggingface": "Hugging Face",
    }
    return table.get(value.lower(), value)


_MODEL_ID_RE = re.compile(
    r"\b(?P<id>(?:gpt-4o|gpt-4\.1(?:-mini)?|claude-[\w.-]+|gemini-[\w.-]+|"
    r"text-embedding-3-[\w-]+|mistral-[\w.-]+|mixtral-[\w.-]+|command-r[\w.-]*))\b",
    re.IGNORECASE,
)


def _model_identifier(finding: Finding) -> str | None:
    for ev in finding.evidence:
        match = _MODEL_ID_RE.search(ev.snippet)
        if match:
            return match.group("id")
    match = _MODEL_ID_RE.search(finding.summary)
    return match.group("id") if match else None


def _purl_for_model(provider: str | None, model_id: str | None) -> str | None:
    if not model_id:
        return None
    if provider == "Hugging Face":
        return f"pkg:huggingface/{model_id}"
    if provider == "OpenAI":
        return f"pkg:openai/{model_id}"
    if provider == "Anthropic":
        return f"pkg:anthropic/{model_id}"
    if provider == "Google":
        return f"pkg:google/{model_id}"
    return f"pkg:generic/{model_id}"


_PYPI_NAMES = {
    "openai", "anthropic", "langchain", "langgraph", "llamaindex",
    "crewai", "autogen", "transformers", "sentence-transformers",
    "boto3", "huggingface_hub", "pinecone", "weaviate", "chromadb",
    "faiss-cpu", "qdrant-client", "milvus",
}


def _purl_for_library(finding: Finding) -> str | None:
    haystack = f"{finding.name} {finding.summary}".lower()
    for pkg in _PYPI_NAMES:
        if pkg in haystack:
            return f"pkg:pypi/{pkg}"
    return None


def _endpoint_for(finding: Finding) -> str | None:
    name = (finding.metadata.get("provider") or finding.name).lower()
    table = {
        "openai": "https://api.openai.com",
        "anthropic": "https://api.anthropic.com",
        "azure-openai": "https://*.openai.azure.com",
        "aws-bedrock": "https://bedrock-runtime.*.amazonaws.com",
        "google": "https://generativelanguage.googleapis.com",
        "huggingface": "https://api-inference.huggingface.co",
        "cohere-or-mistral": "https://api.cohere.com",
    }
    for key, url in table.items():
        if key in name:
            return url
    return None


def _bom_ref(category: str, name: str) -> str:
    digest = hashlib.sha256(f"{category}|{name}".encode("utf-8")).hexdigest()[:16]
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", name).strip("-").lower() or "anon"
    return f"aibom:{category}:{slug}:{digest}"


def _serial_number(root: str) -> str:
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, root)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stringify(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)
