"""OWASP LLM Top-10 (2025) + MITRE ATLAS + NIST AI RMF reference mapping
for every aibom rule_id we currently emit.

Why a static table: the mapping is normative — auditors and ASPM
consumers expect each finding to declare which control framework it
satisfies. Keeping it in one file makes the mapping reviewable.

References:
  OWASP LLM Top-10 2025         https://genai.owasp.org/llm-top-10/
  OWASP MCP Top-10 2026         https://langsight.dev/blog/owasp-mcp-top-10-guide/
  MITRE ATLAS                   https://atlas.mitre.org/
  NIST AI RMF (GAI profile)     https://www.nist.gov/itl/ai-risk-management-framework
"""

from __future__ import annotations


# rule_id -> {owasp_llm, owasp_mcp, mitre_atlas, nist_ai_rmf}
RULE_REFERENCES: dict[str, dict[str, list[str]]] = {
    # --- providers (excessive agency / supply chain) ---
    "provider.openai.pattern": {
        "owasp_llm": ["LLM05-supply-chain", "LLM06-sensitive-info-disclosure"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3", "MS-3.3"],
    },
    "provider.anthropic.pattern": {
        "owasp_llm": ["LLM05-supply-chain", "LLM06-sensitive-info-disclosure"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3", "MS-3.3"],
    },
    "provider.google.pattern": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },
    "provider.azure_openai.pattern": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },
    "provider.bedrock.pattern": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },
    "provider.cohere_mistral.pattern": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },

    # --- secrets / env vars ---
    "secret.ai_key.pattern": {
        "owasp_llm": ["LLM06-sensitive-info-disclosure", "LLM02-insecure-output-handling"],
        "mitre_atlas": ["AML.T0006-Active-Scanning"],
        "nist_ai_rmf": ["MP-2.3", "MS-2.7"],
    },
    "env_var.ai.pattern": {
        "owasp_llm": ["LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MP-2.3"],
    },

    # --- prompts / data flow ---
    "prompt.pattern": {
        "owasp_llm": ["LLM01-prompt-injection", "LLM07-system-prompt-leakage"],
        "mitre_atlas": ["AML.T0051-LLM-Prompt-Injection"],
        "nist_ai_rmf": ["MS-2.10"],
    },
    "data_flow.same_file": {
        "owasp_llm": ["LLM02-insecure-output-handling", "LLM06-sensitive-info-disclosure"],
        "mitre_atlas": ["AML.T0048-External-Harms"],
        "nist_ai_rmf": ["MS-3.4"],
    },
    "endpoint.ai.pattern": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },

    # --- frameworks / packages / vector_db / embedding ---
    "framework.agent.pattern": {
        "owasp_llm": ["LLM08-excessive-agency", "LLM05-supply-chain"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["GV-3.2"],
    },
    "vector_db.pattern": {
        "owasp_llm": ["LLM03-training-data-poisoning", "LLM06-sensitive-info-disclosure"],
        "mitre_atlas": ["AML.T0020-Poison-Training-Data"],
        "nist_ai_rmf": ["MS-2.6"],
    },
    "package.ai_sdk.pattern": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },
    "embedding.pattern": {
        "owasp_llm": ["LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MS-3.3"],
    },

    # --- model identifier ---
    "model.pattern": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },

    # --- model artifacts (P1) ---
    "model_artifact.format": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise", "AML.T0011-User-Execution"],
        "nist_ai_rmf": ["MS-2.6", "MS-2.7"],
    },
    "model_artifact.modelscan": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0011-User-Execution"],
        "nist_ai_rmf": ["MS-2.6"],
    },

    # --- datasets (P1) ---
    "dataset.huggingface.load": {
        "owasp_llm": ["LLM03-training-data-poisoning", "LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0020-Poison-Training-Data"],
        "nist_ai_rmf": ["MS-2.6"],
    },
    "dataset.s3.uri": {
        "owasp_llm": ["LLM03-training-data-poisoning", "LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MP-2.3"],
    },
    "dataset.gcs.uri": {
        "owasp_llm": ["LLM03-training-data-poisoning", "LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MP-2.3"],
    },
    "dataset.azure_blob.uri": {
        "owasp_llm": ["LLM03-training-data-poisoning", "LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MP-2.3"],
    },
    "dataset.bigquery.table": {
        "owasp_llm": ["LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MP-2.3"],
    },
    "dataset.snowflake.client": {
        "owasp_llm": ["LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MP-2.3"],
    },

    # --- prompt risk (P2) ---
    "prompt_risk.secret_leak": {
        "owasp_llm": ["LLM06-sensitive-info-disclosure", "LLM07-system-prompt-leakage"],
        "mitre_atlas": ["AML.T0024-Exfiltration-via-ML-Inference-API"],
        "nist_ai_rmf": ["MS-2.7"],
    },
    "prompt_risk.jailbreak": {
        "owasp_llm": ["LLM01-prompt-injection"],
        "mitre_atlas": ["AML.T0051-LLM-Prompt-Injection", "AML.T0054-LLM-Jailbreak"],
        "nist_ai_rmf": ["MS-2.10"],
    },
    "prompt_risk.role_override": {
        "owasp_llm": ["LLM01-prompt-injection", "LLM07-system-prompt-leakage"],
        "mitre_atlas": ["AML.T0051-LLM-Prompt-Injection"],
        "nist_ai_rmf": ["MS-2.10"],
    },
    "prompt_risk.excessive_agency": {
        "owasp_llm": ["LLM08-excessive-agency"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["GV-3.2", "MS-2.10"],
    },
    "prompt_risk.pii_collection": {
        "owasp_llm": ["LLM06-sensitive-info-disclosure"],
        "mitre_atlas": [],
        "nist_ai_rmf": ["MP-4.1"],
    },

    # --- HF enrichment (P2) ---
    "hf.license.unknown": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },
    "hf.safetensors.absent": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0011-User-Execution"],
        "nist_ai_rmf": ["MS-2.6"],
    },
    "hf.popularity.low": {
        "owasp_llm": ["LLM05-supply-chain"],
        "mitre_atlas": ["AML.T0010-ML-Supply-Chain-Compromise"],
        "nist_ai_rmf": ["GV-1.3"],
    },
}


def references_for(rule_id: str) -> dict[str, list[str]]:
    """Return the framework reference dict for a rule_id (empty if unknown)."""
    return RULE_REFERENCES.get(rule_id, {"owasp_llm": [], "mitre_atlas": [], "nist_ai_rmf": []})


def annotate_finding_metadata(rule_id: str, metadata: dict) -> dict:
    """Merge framework references into a Finding's metadata dict, in place."""
    refs = references_for(rule_id)
    if refs.get("owasp_llm"):
        metadata["owasp_llm"] = refs["owasp_llm"]
    if refs.get("owasp_mcp"):
        metadata["owasp_mcp"] = refs["owasp_mcp"]
    if refs.get("mitre_atlas"):
        metadata["mitre_atlas"] = refs["mitre_atlas"]
    if refs.get("nist_ai_rmf"):
        metadata["nist_ai_rmf"] = refs["nist_ai_rmf"]
    return metadata
