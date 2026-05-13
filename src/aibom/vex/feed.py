"""VEX/VDR feed — curated known-bad AI component registry + cross-reference.

A feed entry has the shape:

  {
    "id": "AIBOM-VEX-2026-0001",
    "match": {
        "purl_substring": "pkg:huggingface/<owner>/<model>",
        "name_substring": "...",
        "model_id": "exact match"
    },
    "severity": "critical" | "high" | "medium" | "low",
    "state": "exploitable" | "in_triage" | "resolved" | "not_affected",
    "sources": ["https://...", "..."],
    "summary": "one-line reason"
  }

The default feed bundles entries derived from public 2025-2026 reporting
(JFrog malicious-HF advisories, ProtectAI scan results, typosquat
disclosures). Deployers override via:

    AIBOM_VEX_FEED=/path/to/custom-feed.json
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aibom.models import Finding, MatchEvidence


# Curated default feed. Keep small + well-attributed; large blocklists
# belong in an externally maintained feed.
DEFAULT_VEX_FEED: list[dict[str, Any]] = [
    {
        "id": "AIBOM-VEX-2026-0001",
        "match": {"name_substring": "openai-python-secure"},
        "severity": "critical",
        "state": "exploitable",
        "sources": ["https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/"],
        "summary": "Typosquat of openai SDK previously found to ship a reverse-shell payload.",
    },
    {
        "id": "AIBOM-VEX-2026-0002",
        "match": {"name_substring": "anthropc"},
        "severity": "critical",
        "state": "exploitable",
        "sources": ["typosquat-pattern"],
        "summary": "Single-letter typosquat of 'anthropic' — pip install anthropc has been observed.",
    },
    {
        "id": "AIBOM-VEX-2026-0003",
        "match": {"name_substring": "huggingfac-hub"},
        "severity": "critical",
        "state": "exploitable",
        "sources": ["typosquat-pattern"],
        "summary": "Typosquat of huggingface_hub.",
    },
    {
        "id": "AIBOM-VEX-2026-0004",
        "match": {"purl_substring": "pkg:huggingface/baai/aquila-7b"},
        "severity": "high",
        "state": "in_triage",
        "sources": ["protectai-scan-flag"],
        "summary": "Pickle-format weights flagged by ProtectAI scanner historically — verify safetensors variant.",
    },
    {
        "id": "AIBOM-VEX-2026-0005",
        "match": {"purl_substring": "pkg:pypi/llama-cpp-python"},
        "severity": "medium",
        "state": "in_triage",
        "sources": ["wheel-rebuild-required"],
        "summary": "Pre-built wheels historically lagged upstream CVE fixes; pin and rebuild from source.",
    },
]


@dataclass(frozen=True, slots=True)
class VexEntry:
    id: str
    severity: str
    state: str
    sources: list[str]
    summary: str
    match: dict[str, str]


_VERDICT_TO_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def load_feed(path: Path | None = None) -> list[dict[str, Any]]:
    """Load feed from explicit path or AIBOM_VEX_FEED env var; fall back to bundled default."""
    candidate = path or _env_feed_path()
    if candidate is None:
        return list(DEFAULT_VEX_FEED)
    try:
        text = candidate.read_text(encoding="utf-8")
    except OSError:
        return list(DEFAULT_VEX_FEED)
    try:
        loaded = json.loads(text)
        if isinstance(loaded, list):
            return loaded
    except json.JSONDecodeError:
        pass
    return list(DEFAULT_VEX_FEED)


def cross_reference(bom: dict[str, Any], feed: list[dict[str, Any]] | None = None) -> list[Finding]:
    """Emit findings for any BOM component matched by the feed.

    `bom` is the dict produced by aibom.cyclonedx.build_bom (or an
    equivalent CDX 1.6 shape). Components and services are both walked.
    """
    feed_entries = feed if feed is not None else load_feed()
    findings: list[Finding] = []
    for component in (bom.get("components") or []) + (bom.get("services") or []):
        match = _find_match(component, feed_entries)
        if match is None:
            continue
        sev = _VERDICT_TO_SEV.get(str(match.get("severity", "medium")).lower(), "medium")
        findings.append(_finding_for(component, match, severity=sev))
    return findings


# --------------------------------------------------------------------------- #

def _find_match(component: dict[str, Any], feed: list[dict[str, Any]]) -> dict[str, Any] | None:
    name = (component.get("name") or "").lower()
    purl = (component.get("purl") or "").lower()
    for entry in feed:
        m = entry.get("match") or {}
        if "model_id" in m and component.get("name") == m["model_id"]:
            return entry
        if "name_substring" in m and m["name_substring"].lower() in name:
            return entry
        if "purl_substring" in m and m["purl_substring"].lower() in purl:
            return entry
    return None


def _finding_for(component: dict[str, Any], entry: dict[str, Any], *, severity: str) -> Finding:
    name = component.get("name", "")
    bom_ref = component.get("bom-ref", name)
    return Finding(
        finding_id=f"vex:{entry['id']}:{bom_ref}",
        rule_id=f"vex.{entry['id']}",
        category="vex",
        name=f"VEX match: {name}",
        severity=severity,
        confidence="high",
        path=str(component.get("purl") or name),
        detector="vex-feed",
        entity_type="component",
        source_kind="bom",
        summary=str(entry.get("summary", "")),
        evidence=[
            MatchEvidence(line=0, snippet=str(entry.get("sources", [""])[0]), match=entry["id"]),
        ],
        metadata={
            "vex_id": entry["id"],
            "vex_state": str(entry.get("state", "in_triage")),
            "vex_sources": list(entry.get("sources") or []),
            "bom_ref": bom_ref,
        },
    )


def _env_feed_path() -> Path | None:
    val = os.environ.get("AIBOM_VEX_FEED")
    return Path(val) if val else None
