from __future__ import annotations

from dataclasses import replace
from fnmatch import fnmatch
from pathlib import Path
import json
import tomllib

from aibom.models import Finding


def load_tuning_file(path: str | None) -> dict:
    if not path:
        return {}
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if file_path.suffix.lower() == ".json":
        return json.loads(text)
    return tomllib.loads(text)


def merge_exclude_patterns(defaults: list[str], tuning: dict) -> list[str]:
    extra = tuning.get("exclude_patterns", [])
    if not isinstance(extra, list):
        return list(defaults)
    return list(defaults) + [str(item) for item in extra]


def apply_tuning(findings: list[Finding], tuning: dict) -> list[Finding]:
    if not tuning:
        return findings

    suppressed_rules = {str(item) for item in tuning.get("suppress_rule_ids", [])}
    path_suppressions = tuning.get("path_suppressions", [])
    severity_overrides = tuning.get("severity_overrides", {})
    confidence_overrides = tuning.get("confidence_overrides", {})
    baseline_ignore = tuning.get("baseline_ignore_rule_ids", [])

    updated: list[Finding] = []
    for finding in findings:
        if finding.rule_id in suppressed_rules:
            continue
        if should_suppress_by_path(finding, path_suppressions):
            continue

        metadata = dict(finding.metadata)
        if finding.rule_id in baseline_ignore:
            metadata["baseline_ignore"] = True

        updated.append(
            replace(
                finding,
                severity=str(severity_overrides.get(finding.rule_id, finding.severity)),
                confidence=str(confidence_overrides.get(finding.rule_id, finding.confidence)),
                metadata=metadata,
            )
        )
    return updated


def should_suppress_by_path(finding: Finding, path_suppressions: object) -> bool:
    if not isinstance(path_suppressions, list):
        return False
    for item in path_suppressions:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id", ""))
        pattern = str(item.get("path", ""))
        if rule_id and rule_id != finding.rule_id:
            continue
        if pattern and fnmatch(finding.path, pattern):
            return True
    return False
