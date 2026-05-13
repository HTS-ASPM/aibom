"""Normalized 0-100 risk score per AI asset.

Combines the per-finding signal into a single number so HTS-ASPM and
downstream dashboards have a comparable axis across very different
detector kinds (regex hit vs binary artifact hash vs IaC posture).

Score components (weights chosen for interpretability, not formal calibration):

    base_severity_weight  : 30
        critical=30, high=20, medium=10, low=5, info=2
    confidence_multiplier : 0.5..1.0
        high=1.0, medium=0.75, low=0.5
    framework_boost       : up to 25
        +5 per OWASP-LLM Top-10 ref (cap 15)
        +5 per MITRE ATLAS ref     (cap 10)
    provenance_penalty    : up to 15
        unsigned/unknown publisher / pickle-only weights / low downloads
    secret_kicker         : 25 if any in-bundle secret finding
    public_exposure       : 10 if Terraform / Helm declared public_*
    blast_radius          : up to 10 from cross-skill collusion / shared MCP

Capped at 100. Per-asset score is the max across that asset's findings,
plus the per-finding contributions of the asset's other findings (so
many-finding assets score higher than single-finding assets).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from aibom.models import Finding


_SEVERITY_BASE = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 2}
_CONFIDENCE_MUL = {"high": 1.0, "medium": 0.75, "low": 0.5}


@dataclass(frozen=True, slots=True)
class AssetRisk:
    asset_key: str
    score: int
    components: tuple[tuple[str, int], ...]
    contributing_finding_ids: tuple[str, ...]


def score_per_asset(findings: list[Finding]) -> list[AssetRisk]:
    """Group findings by asset (component name + path) and emit one AssetRisk per group."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        key = _asset_key(f)
        groups.setdefault(key, []).append(f)
    return [_score_group(key, group) for key, group in groups.items()]


def score_for_finding(finding: Finding) -> int:
    """Stand-alone per-finding score (used for tagging individual findings)."""
    return min(100, _base_for(finding))


# --------------------------------------------------------------------------- #

def _asset_key(finding: Finding) -> str:
    # Use category + canonical name; component-style assets group cleanly.
    return f"{finding.category}::{finding.name}"


def _score_group(key: str, group: list[Finding]) -> AssetRisk:
    contributions: list[tuple[str, int]] = []
    total = 0

    # 1. base from highest-severity finding
    top = max(group, key=lambda f: _SEVERITY_BASE.get(f.severity, 2))
    base = _base_for(top)
    contributions.append(("base_severity", base))
    total += base

    # 2. each additional finding in the group adds half its individual base
    for f in group:
        if f is top:
            continue
        contributions.append((f"additional:{f.rule_id}", _base_for(f) // 2))
        total += _base_for(f) // 2

    # 3. framework boost
    boost = _framework_boost(group)
    if boost:
        contributions.append(("framework_boost", boost))
        total += boost

    # 4. provenance penalty
    prov = _provenance_penalty(group)
    if prov:
        contributions.append(("provenance_penalty", prov))
        total += prov

    # 5. secret kicker
    if any(f.category == "secret" for f in group):
        contributions.append(("secret_kicker", 25))
        total += 25

    # 6. public exposure
    if any(f.metadata.get("review_required") and f.detector == "terraform-parser" for f in group):
        contributions.append(("public_exposure", 10))
        total += 10

    # 7. blast radius
    if any(f.category == "collusion" for f in group):
        contributions.append(("blast_radius", 10))
        total += 10

    score = min(100, total)
    return AssetRisk(
        asset_key=key,
        score=score,
        components=tuple(contributions),
        contributing_finding_ids=tuple(f.finding_id for f in group),
    )


def _base_for(finding: Finding) -> int:
    base = _SEVERITY_BASE.get(finding.severity, 2)
    mul = _CONFIDENCE_MUL.get(finding.confidence, 0.75)
    return int(base * mul)


def _framework_boost(group: list[Finding]) -> int:
    owasp_refs: set[str] = set()
    atlas_refs: set[str] = set()
    for f in group:
        for ref in _list_metadata(f, "owasp_llm"):
            owasp_refs.add(ref)
        for ref in _list_metadata(f, "mitre_atlas"):
            atlas_refs.add(ref)
    return min(15, 5 * len(owasp_refs)) + min(10, 5 * len(atlas_refs))


def _provenance_penalty(group: list[Finding]) -> int:
    penalty = 0
    rule_ids = {f.rule_id for f in group}
    if "hf.license.unknown" in rule_ids:
        penalty += 5
    if "hf.safetensors.absent" in rule_ids:
        penalty += 5
    if "hf.popularity.low" in rule_ids:
        penalty += 5
    return min(15, penalty)


def _list_metadata(finding: Finding, key: str) -> Iterable[str]:
    val = finding.metadata.get(key)
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val]
    return []
