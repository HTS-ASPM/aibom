"""Emit a CycloneDX 1.6 `vulnerabilities` array (the BOM-VEX shape).

Spec: https://cyclonedx.org/docs/1.6/json/#vulnerabilities

Each VEX feed match becomes one CDX vulnerability entry:

  {
    "id":          "AIBOM-VEX-2026-0001",
    "source":      {"name": "aibom-vex-feed"},
    "ratings":     [{"severity": "critical", "method": "OTHER"}],
    "description": "<entry summary>",
    "advisories":  [{"url": "<each source>"}],
    "affects":     [{"ref": "<bom-ref>"}],
    "analysis":    {"state": "exploitable", "justification": "..."}
  }

The output is a *fragment* — it can be merged into an existing BOM's
`vulnerabilities` array, or emitted standalone for review.
"""

from __future__ import annotations

from typing import Any

from aibom.vex.feed import VexEntry, _find_match, load_feed  # type: ignore


_STATE_TO_DETAIL = {
    "exploitable": "Component matches a known-malicious entry in the AiBOM VEX feed.",
    "in_triage":   "Component matches a feed entry pending verification; treat as untrusted until reviewed.",
    "resolved":    "Component matches a feed entry whose risk has been mitigated by an upstream fix.",
    "not_affected": "Component matches a feed entry but is not affected in this configuration.",
}


def emit_vex_for_bom(bom: dict[str, Any], *, feed: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    feed_entries = feed if feed is not None else load_feed()
    out: list[dict[str, Any]] = []
    for component in (bom.get("components") or []) + (bom.get("services") or []):
        entry = _find_match(component, feed_entries)
        if entry is None:
            continue
        out.append(_to_cdx_vuln(component, entry))
    return out


def merge_vex_into_bom(bom: dict[str, Any], *, feed: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return a copy of `bom` with `.vulnerabilities` populated from the feed."""
    vulns = emit_vex_for_bom(bom, feed=feed)
    if not vulns:
        return bom
    merged = dict(bom)
    existing = list(merged.get("vulnerabilities") or [])
    seen_ids = {v.get("id") for v in existing}
    for v in vulns:
        if v["id"] in seen_ids:
            continue
        existing.append(v)
        seen_ids.add(v["id"])
    merged["vulnerabilities"] = existing
    return merged


# --------------------------------------------------------------------------- #

def _to_cdx_vuln(component: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    state = str(entry.get("state", "in_triage"))
    severity = str(entry.get("severity", "medium")).lower()
    bom_ref = component.get("bom-ref", component.get("name", ""))
    return {
        "id": str(entry["id"]),
        "source": {"name": "aibom-vex-feed"},
        "ratings": [{"severity": severity, "method": "OTHER"}],
        "description": str(entry.get("summary", "")),
        "advisories": [{"url": str(url)} for url in entry.get("sources", []) if isinstance(url, str)],
        "affects": [{"ref": str(bom_ref)}],
        "analysis": {
            "state": state,
            "justification": _STATE_TO_DETAIL.get(state, ""),
            "detail": str(entry.get("summary", "")),
        },
    }
