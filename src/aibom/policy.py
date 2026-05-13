from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json
import tomllib

from aibom.models import Finding


def load_policy_file(path: str | None) -> dict:
    if not path:
        return {}
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if file_path.suffix.lower() == ".json":
        return json.loads(text)
    return tomllib.loads(text)


def apply_policy(findings: list[Finding], policy: dict) -> list[Finding]:
    if not policy:
        return findings

    approved_providers = set(policy.get("approved_providers", []))
    approved_models = set(policy.get("approved_models", []))
    severity_overrides = policy.get("severity_overrides", {})

    updated: list[Finding] = []
    for finding in findings:
        metadata = dict(finding.metadata)
        severity = severity_overrides.get(finding.rule_id, finding.severity)
        name = finding.name
        summary = finding.summary

        if finding.category == "provider":
            provider = str(metadata.get("provider", "")).lower()
            if approved_providers and provider and provider not in approved_providers:
                severity = "high"
                name = f"{finding.name} policy violation"
                summary = f"{finding.summary} Provider `{provider}` is not in the approved provider policy."
                metadata["policy_violation"] = True
                metadata["policy_field"] = "approved_providers"

        if finding.category == "model":
            matched_model = first_evidence_match(finding)
            if approved_models and matched_model and matched_model not in approved_models:
                severity = "high"
                name = f"{finding.name} policy violation"
                summary = f"{finding.summary} Model `{matched_model}` is not in the approved model policy."
                metadata["policy_violation"] = True
                metadata["policy_field"] = "approved_models"

        updated.append(
            replace(
                finding,
                severity=severity,
                name=name,
                summary=summary,
                metadata=metadata,
            )
        )
    return updated


def first_evidence_match(finding: Finding) -> str:
    if not finding.evidence:
        return ""
    return finding.evidence[0].match.lower()
