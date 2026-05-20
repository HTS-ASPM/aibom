"""HTS-ASPM ingest payload builder.

This module defines the *integration contract* between AiBOM and the
sibling HTS-ASPM product. HTS-ASPM developers implement an ingest
endpoint that accepts the JSON document produced by
:func:`build_aspm_payload`.

Payload contract (schema_version = "1.0")
-----------------------------------------

::

    {
      "schema_version": "1.0",
      "scanner": {"name": "aibom", "version": "<__version__>"},
      "scan_root": "<str>",
      "scan_id":   "urn:uuid:<uuid5(scan_root + scanned_at)>",
      "scanned_at": "<ISO 8601 UTC, e.g. 2026-05-20T11:22:33Z>",
      "bom":           <CycloneDX 1.6 ML-BOM JSON>,
      "asset_graph":   <asset graph JSON, include_findings=False>,
      "findings_summary": {
        "by_severity": {"critical": N, "high": N, "medium": N,
                        "low": N, "info": N},
        "by_category": {"provider": N, "model": N, ...},
        "by_framework": {
          "owasp_llm":    {"LLM01-prompt-injection": N, ...},
          "mitre_atlas":  {"AML.T0010-...":           N, ...},
          "nist_ai_rmf":  {"GV-1.3":                  N, ...}
        },
        "total": N
      },
      "top_findings": [
        # up to 50 findings, sorted by (severity desc, risk_score desc,
        # finding_id asc). Each entry is the Finding.to_dict() shape.
        ...
      ],
      "risk_scores": [
        {
          "asset_key":  "<category>::<name>",
          "score":      0..100,
          "components": [["base_severity", 30], ["framework_boost", 5], ...]
        }, ...
      ],
      "vex":          [<CycloneDX vulnerabilities[] from emit_vex_for_bom>],
      "kev_matches":  [<KEV-cross-referenced Finding dicts>],   # [] when no KEV feed
      "signature_manifest": {                                   # optional
        "artifact_path":   "<inline:bom.json>",
        "sha256":          "<hex>",
        "intended_signer": "<email>",
        "rekor_log_url":   "<url>",
        "cosign_command":  "<suggested shell command>"
      }
    }

Determinism guarantees
----------------------

The builder uses sorted dict keys at every level and a single ISO 8601
UTC timestamp captured once per build, so two runs over identical inputs
produce identical *canonical* bytes. Use :func:`canonical_json_bytes`
to obtain those bytes for hashing / signing.

Versioning policy
-----------------

``schema_version`` follows semver-style major versioning. Additive,
backwards-compatible changes (new top-level keys, new nested keys) keep
the same major version. Breaking changes — removing keys, changing
existing keys' meaning, changing nesting — bump the major version
(e.g. 1.0 → 2.0). The wire header ``X-Aibom-Schema-Version`` mirrors
this constant so receivers can route on it.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aibom import __version__
from aibom.asset_graph import build_asset_graph
from aibom.cyclonedx import build_bom
from aibom.models import Finding, ScanResult
from aibom.risk import score_per_asset
from aibom.signing import SignatureManifest, canonicalize_bom, hash_bom
from aibom.vex import (
    cross_reference_kev,
    emit_vex_for_bom,
    load_feed,
    load_kev_feed,
)


SCHEMA_VERSION = "1.0"
ASPM_CONTENT_TYPE = "application/vnd.aibom+json"

# Severity ordering for "top findings" sort (higher index == more severe).
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_TOP_FINDINGS_LIMIT = 50


@dataclass(frozen=True, slots=True)
class _BuildContext:
    """Internal carrier for the scan_id / scanned_at pair so the payload
    builder, signature manifest, and outgoing HTTP headers all agree."""

    scan_id: str
    scanned_at: str


def build_aspm_payload(
    result: ScanResult,
    *,
    include_vex: bool = True,
    include_kev: bool = True,
    kev_feed: Any = None,
    vex_feed: list[dict[str, Any]] | None = None,
    signer: str | None = None,
    key_ref: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the HTS-ASPM ingest envelope for a scan result.

    Parameters
    ----------
    result:
        The scan output to wrap.
    include_vex:
        When True (default) populate the ``vex`` array from the AiBOM
        VEX feed.
    include_kev:
        When True (default) populate ``kev_matches`` from a cached CISA
        KEV catalog. Pass a path via ``kev_feed`` or rely on the
        ``AIBOM_KEV_FEED`` env var; otherwise the array stays empty.
    kev_feed:
        Optional path (``pathlib.Path`` or ``str``) to a cached KEV JSON.
    vex_feed:
        Optional pre-loaded VEX feed list (skips disk read).
    signer / key_ref:
        When ``signer`` is provided the payload includes a
        ``signature_manifest`` covering the inlined BOM bytes. Useful for
        environments where the ASPM receiver verifies provenance.
    now:
        Override the timestamp source — used by tests. Defaults to
        ``datetime.now(timezone.utc)``.

    Returns
    -------
    dict
        The serializable payload. Pass through :func:`canonical_json_bytes`
        for a stable byte representation.
    """
    ctx = _build_context(result.root, now)
    bom = build_bom(result)
    asset_graph = build_asset_graph(result, include_findings=False)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scanner": {"name": "aibom", "version": __version__},
        "scan_root": result.root,
        "scan_id": ctx.scan_id,
        "scanned_at": ctx.scanned_at,
        "bom": bom,
        "asset_graph": asset_graph,
        "findings_summary": _summarize_findings(result.findings),
        "top_findings": _top_findings(result.findings),
        "risk_scores": _risk_scores(result.findings),
        "vex": _vex_entries(bom, include_vex, vex_feed),
        "kev_matches": _kev_matches(bom, include_kev, kev_feed),
    }

    if signer:
        payload["signature_manifest"] = _inline_signature_manifest(
            bom, intended_signer=signer, key_ref=key_ref,
        )

    return payload


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Stable, deterministic JSON encoding of the payload.

    Same input always produces the same bytes — important for signature
    reproducibility and for receivers that hash for idempotency.
    """
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# internals

def _build_context(scan_root: str, now: datetime | None) -> _BuildContext:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)
    scanned_at = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    seed = f"{scan_root}|{scanned_at}"
    scan_uuid = uuid.uuid5(uuid.NAMESPACE_URL, seed)
    return _BuildContext(scan_id=f"urn:uuid:{scan_uuid}", scanned_at=scanned_at)


def _summarize_findings(findings: list[Finding]) -> dict[str, Any]:
    by_severity: dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    by_category: dict[str, int] = {}
    by_framework: dict[str, dict[str, int]] = {
        "owasp_llm": {},
        "mitre_atlas": {},
        "nist_ai_rmf": {},
    }
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
        for framework in ("owasp_llm", "mitre_atlas", "nist_ai_rmf"):
            value = f.metadata.get(framework)
            if not value:
                continue
            refs = value if isinstance(value, list) else [value]
            for ref in refs:
                ref_key = str(ref)
                by_framework[framework][ref_key] = (
                    by_framework[framework].get(ref_key, 0) + 1
                )

    # Sort inner dicts for determinism.
    return {
        "by_severity": {k: by_severity[k] for k in sorted(by_severity)},
        "by_category": {k: by_category[k] for k in sorted(by_category)},
        "by_framework": {
            framework: {k: counts[k] for k in sorted(counts)}
            for framework, counts in sorted(by_framework.items())
        },
        "total": len(findings),
    }


def _top_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    if not findings:
        return []
    score_by_id: dict[str, int] = {}
    for asset in score_per_asset(findings):
        for fid in asset.contributing_finding_ids:
            score_by_id[fid] = max(score_by_id.get(fid, 0), asset.score)

    def _sort_key(f: Finding) -> tuple:
        severity_rank = _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else -1
        # Negate for descending; finding_id ascending as tiebreaker.
        return (-severity_rank, -score_by_id.get(f.finding_id, 0), f.finding_id)

    return [f.to_dict() for f in sorted(findings, key=_sort_key)[:_TOP_FINDINGS_LIMIT]]


def _risk_scores(findings: list[Finding]) -> list[dict[str, Any]]:
    rows = [
        {
            "asset_key": asset.asset_key,
            "score": asset.score,
            "components": [list(item) for item in asset.components],
            "contributing_finding_ids": list(asset.contributing_finding_ids),
        }
        for asset in score_per_asset(findings)
    ]
    rows.sort(key=lambda row: (-int(row["score"]), str(row["asset_key"])))
    return rows


def _vex_entries(
    bom: dict[str, Any],
    include_vex: bool,
    vex_feed: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if not include_vex:
        return []
    feed = vex_feed if vex_feed is not None else load_feed()
    return emit_vex_for_bom(bom, feed=feed)


def _kev_matches(
    bom: dict[str, Any],
    include_kev: bool,
    kev_feed: Any,
) -> list[dict[str, Any]]:
    if not include_kev:
        return []
    # Avoid mutating the caller's BOM here — KEV cross-ref annotates in place
    # by default. We pass a shallow-copied BOM so the canonical payload's
    # `bom` stays a function of build_bom(result) only.
    bom_copy = json.loads(json.dumps(bom))
    from pathlib import Path

    if kev_feed is None:
        index = load_kev_feed()
    elif isinstance(kev_feed, dict):
        index = kev_feed
    else:
        index = load_kev_feed(Path(str(kev_feed)))
    findings = cross_reference_kev(bom_copy, index, annotate_in_place=False)
    return [f.to_dict() for f in findings]


def _inline_signature_manifest(
    bom: dict[str, Any],
    *,
    intended_signer: str,
    key_ref: str | None,
) -> dict[str, Any]:
    bom_bytes = canonicalize_bom(bom)
    digest = hash_bom(bom_bytes)
    cosign_cmd = (
        "cosign sign-blob --yes"
        + (f" --key {key_ref}" if key_ref else "")
        + " --output-signature bom.json.sig"
        + " --output-certificate bom.json.cert bom.json"
    )
    manifest = SignatureManifest(
        artifact_path="inline:bom.json",
        sha256=digest,
        intended_signer=intended_signer,
        rekor_log_url="https://rekor.sigstore.dev",
        cosign_command=cosign_cmd,
    )
    return manifest.to_dict()


__all__ = [
    "ASPM_CONTENT_TYPE",
    "SCHEMA_VERSION",
    "build_aspm_payload",
    "canonical_json_bytes",
]
