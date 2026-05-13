"""Unified SBOM + AiBOM CDX 1.6 view.

Consumes a CycloneDX 1.6 SBOM produced by the existing HTS-ASPM SBOM
module (or any CDX-emitting tool — Trivy, Syft, cdxgen) and merges it
with the AiBOM CDX 1.6 BOM, producing a single document HTS-ASPM can
render as one inventory.

Merge semantics:
  - Components & services are deduplicated by (type, name, version) when
    both inputs share an identifier — preferring the AiBOM version
    (which carries modelCard / framework refs / risk score).
  - Dependencies are unioned.
  - Top-level metadata.tools.components carries both source tools so
    auditors can see which scanner produced what.

Both inputs must be CDX 1.6+ (SBOM and AiBOM CDX). Older specs are
upgraded best-effort by lifting unknown fields verbatim.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


def merge_sbom_aibom(sbom: dict[str, Any], aibom: dict[str, Any]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    seen_components: set[tuple[str, str, str]] = set()

    # AiBOM components win on duplicates (richer metadata).
    for source in (aibom, sbom):
        for component in source.get("components", []) or []:
            key = (
                component.get("type", ""),
                component.get("name", ""),
                component.get("version", ""),
            )
            if key in seen_components:
                continue
            seen_components.add(key)
            components.append(component)

    services: list[dict[str, Any]] = []
    seen_services: set[tuple[str, str]] = set()
    for source in (aibom, sbom):
        for service in source.get("services", []) or []:
            key = (service.get("name", ""), service.get("provider", {}).get("name", "") if isinstance(service.get("provider"), dict) else "")
            if key in seen_services:
                continue
            seen_services.add(key)
            services.append(service)

    # Tools — keep both source tool entries so consumers know provenance.
    aibom_tools = (aibom.get("metadata", {}) or {}).get("tools", {}) or {}
    sbom_tools = (sbom.get("metadata", {}) or {}).get("tools", {}) or {}
    tool_components: list[dict[str, Any]] = []
    seen_tool_names: set[str] = set()
    for tools in (aibom_tools, sbom_tools):
        for entry in tools.get("components", []) or []:
            name = entry.get("name", "")
            if name and name not in seen_tool_names:
                seen_tool_names.add(name)
                tool_components.append(entry)

    # Dependencies union (by ref).
    deps: dict[str, set[str]] = {}
    for source in (aibom, sbom):
        for dep in source.get("dependencies", []) or []:
            ref = dep.get("ref")
            if not ref:
                continue
            existing = deps.setdefault(ref, set())
            for child in dep.get("dependsOn", []) or []:
                existing.add(child)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": tool_components},
            "component": _root_component(aibom, sbom),
            "properties": [
                {"name": "aibom:unified", "value": "true"},
                {"name": "aibom:source_aibom_serial", "value": str(aibom.get("serialNumber", ""))},
                {"name": "aibom:source_sbom_serial", "value": str(sbom.get("serialNumber", ""))},
            ],
        },
        "components": components,
        "services": services,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(children)}
            for ref, children in sorted(deps.items())
        ],
    }


def merge_files(sbom_path: str, aibom_path: str, *, output_path: str | None = None) -> dict[str, Any]:
    with open(sbom_path, encoding="utf-8") as fh:
        sbom = json.load(fh)
    with open(aibom_path, encoding="utf-8") as fh:
        aibom = json.load(fh)
    merged = merge_sbom_aibom(sbom, aibom)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, indent=2)
    return merged


def _root_component(aibom: dict[str, Any], sbom: dict[str, Any]) -> dict[str, Any]:
    aibom_root = (aibom.get("metadata", {}) or {}).get("component") or {}
    sbom_root = (sbom.get("metadata", {}) or {}).get("component") or {}
    if aibom_root.get("name"):
        return aibom_root
    if sbom_root.get("name"):
        return sbom_root
    return {"type": "application", "name": "unified", "version": "0.0.0"}
