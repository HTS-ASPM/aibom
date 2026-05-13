from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import uuid

from aibom import __version__
from aibom.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_pretty_json(payload: object) -> str:
    return json.dumps(payload, indent=2)


def render_sarif(result: ScanResult) -> str:
    rules = []
    seen_rules: set[str] = set()
    results = []

    level_map = {
        "high": "error",
        "medium": "warning",
        "low": "note",
    }

    for finding in result.findings:
        if finding.rule_id not in seen_rules:
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.name,
                    "shortDescription": {"text": finding.name},
                    "fullDescription": {"text": finding.summary},
                    "properties": {
                        "category": finding.category,
                        "entityType": finding.entity_type,
                        "sourceKind": finding.source_kind,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                    },
                }
            )
            seen_rules.add(finding.rule_id)

        locations = []
        if finding.evidence:
            for item in finding.evidence[:3]:
                locations.append(
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": item.line,
                                "snippet": {"text": item.snippet},
                            },
                        }
                    }
                )
        else:
            locations.append({"physicalLocation": {"artifactLocation": {"uri": finding.path}}})

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level_map.get(finding.severity, "warning"),
                "message": {"text": finding.summary},
                "locations": locations,
                "properties": {
                    "findingId": finding.finding_id,
                    "category": finding.category,
                    "entityType": finding.entity_type,
                    "sourceKind": finding.source_kind,
                    "confidence": finding.confidence,
                    "metadata": finding.metadata,
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AiBOM",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "artifacts": [{"location": {"uri": path}} for path in sorted({finding.path for finding in result.findings})],
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def render_cyclonedx(result: ScanResult) -> str:
    serial = uuid.uuid5(uuid.NAMESPACE_URL, result.root)
    components = []
    seen_components: set[tuple[str, str, str]] = set()

    type_map = {
        "provider": "service",
        "framework": "library",
        "vector_db": "service",
        "embedding": "library",
        "model": "machine-learning-model",
        "package": "library",
        "prompt": "data",
        "endpoint": "service",
        "rag": "data",
        "env_var": "data",
        "data_flow": "data",
    }

    for finding in result.findings:
        key = (finding.category, finding.name, finding.path)
        if key in seen_components:
            continue
        seen_components.add(key)
        component_ref = f"{finding.category}:{finding.name}:{finding.path}"
        components.append(
            {
                "type": type_map.get(finding.category, "data"),
                "bom-ref": component_ref,
                "name": finding.name,
                "version": "detected",
                "scope": "required",
                "description": finding.summary,
                "properties": [
                    {"name": "aibom:category", "value": finding.category},
                    {"name": "aibom:rule_id", "value": finding.rule_id},
                    {"name": "aibom:entity_type", "value": finding.entity_type},
                    {"name": "aibom:source_kind", "value": finding.source_kind},
                    {"name": "aibom:severity", "value": finding.severity},
                    {"name": "aibom:confidence", "value": finding.confidence},
                    {"name": "aibom:path", "value": finding.path},
                ]
                + [
                    {"name": f"aibom:meta:{key}", "value": stringify_value(value)}
                    for key, value in sorted(finding.metadata.items())
                ],
                "evidence": {
                    "occurrences": [
                        {
                            "location": finding.path,
                            "line": item.line,
                        }
                        for item in finding.evidence[:3]
                    ]
                },
            }
        )

    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": "1970-01-01T00:00:00Z",
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "AiBOM",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": Path(result.root).name or "scan-target",
                "version": "unspecified",
            },
            "properties": [
                {"name": "aibom:files_scanned", "value": str(result.stats.files_scanned)},
                {"name": "aibom:files_skipped", "value": str(result.stats.files_skipped)},
                {"name": "aibom:bytes_scanned", "value": str(result.stats.bytes_scanned)},
            ],
        },
        "components": components,
    }
    return json.dumps(payload, indent=2)


def render_markdown(result: ScanResult) -> str:
    counts = Counter(item.category for item in result.findings)
    lines = [
        "# AiBOM Scan Report",
        "",
        f"- Root: `{result.root}`",
        f"- Files scanned: `{result.stats.files_scanned}`",
        f"- Files skipped: `{result.stats.files_skipped}`",
        f"- Findings: `{len(result.findings)}`",
        "",
        "## Categories",
        "",
    ]

    if counts:
        for category, count in sorted(counts.items()):
            lines.append(f"- `{category}`: {count}")
    else:
        lines.append("- No findings")

    lines.extend(["", "## Findings", ""])

    if not result.findings:
        lines.append("No AI-related artifacts detected.")
        return "\n".join(lines)

    for finding in result.findings:
        lines.append(f"### {finding.name}")
        lines.append(f"- Category: `{finding.category}`")
        lines.append(f"- Severity: `{finding.severity}`")
        lines.append(f"- Confidence: `{finding.confidence}`")
        lines.append(f"- Rule ID: `{finding.rule_id}`")
        lines.append(f"- Entity Type: `{finding.entity_type}`")
        lines.append(f"- Source Kind: `{finding.source_kind}`")
        lines.append(f"- File: `{finding.path}`")
        lines.append(f"- Detector: `{finding.detector}`")
        lines.append(f"- Summary: {finding.summary}")
        if finding.metadata:
            for key, value in sorted(finding.metadata.items()):
                lines.append(f"- {key}: `{value}`")
        if finding.evidence:
            lines.append("- Evidence:")
            for item in finding.evidence[:3]:
                snippet = item.snippet.strip().replace("`", "'")
                lines.append(f"  - line {item.line}: `{snippet}`")
        lines.append("")

    return "\n".join(lines)


def stringify_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)
