from __future__ import annotations

import json
from collections import Counter

from aibom import __version__
from aibom.cyclonedx import render_cyclonedx
from aibom.models import ScanResult

__all__ = [
    "render_json",
    "render_pretty_json",
    "render_sarif",
    "render_cyclonedx",
    "render_markdown",
    "stringify_value",
]


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
