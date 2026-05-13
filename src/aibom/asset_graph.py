"""Asset graph builder — exports the BOM as a graph the HTS-ASPM
dashboard can render directly without reimplementing CDX parsing.

Nodes:
  - root application
  - providers (services in CDX)
  - models (machine-learning-model)
  - datasets (data)
  - libraries (frameworks, SDKs)
  - iac (terraform / helm declarations)
  - findings (one node per finding when keep_findings=True)

Edges:
  - root depends_on -> all components/services
  - dataset feeds  -> model (when dataset and model share a path / file)
  - finding affects -> any component matching its (category, name)
  - finding maps_to -> framework reference (OWASP / ATLAS / NIST)

Output is a small JSON shape designed to be diffable across scans.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aibom.models import Finding, ScanResult
from aibom.risk import score_per_asset


@dataclass(frozen=True, slots=True)
class GraphNode:
    id: str
    type: str
    label: str
    properties: dict[str, Any]


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    kind: str


def build_asset_graph(result: ScanResult, *, include_findings: bool = True) -> dict[str, Any]:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen_node_ids: set[str] = set()

    # 1. root application
    root_id = "asset:application:root"
    nodes.append(GraphNode(id=root_id, type="application", label=result.root, properties={}))
    seen_node_ids.add(root_id)

    # 2. asset nodes from grouped findings
    asset_risks = {ar.asset_key: ar for ar in score_per_asset(result.findings)}
    grouped: dict[str, list[Finding]] = {}
    for f in result.findings:
        grouped.setdefault(f"{f.category}::{f.name}", []).append(f)

    for key, group in grouped.items():
        asset_id = "asset:" + key.replace(" ", "_")
        if asset_id in seen_node_ids:
            continue
        seen_node_ids.add(asset_id)
        risk = asset_risks.get(key)
        nodes.append(GraphNode(
            id=asset_id,
            type=group[0].category,
            label=group[0].name,
            properties={
                "rule_ids": sorted({f.rule_id for f in group}),
                "max_severity": _max_severity(group),
                "occurrences": sum(1 for _ in group),
                "risk_score": risk.score if risk else 0,
            },
        ))
        edges.append(GraphEdge(source=root_id, target=asset_id, kind="depends_on"))

    # 3. dataset → model edges (best-effort: shared file path)
    dataset_assets = [n for n in nodes if n.type == "dataset"]
    model_assets = [n for n in nodes if n.type in {"model", "model_artifact"}]
    paths_by_asset = {n.id: _paths_for_asset(grouped[_strip_prefix(n.id)]) for n in dataset_assets + model_assets if _strip_prefix(n.id) in grouped}
    for ds in dataset_assets:
        for m in model_assets:
            if paths_by_asset.get(ds.id) and paths_by_asset.get(m.id) and paths_by_asset[ds.id] & paths_by_asset[m.id]:
                edges.append(GraphEdge(source=ds.id, target=m.id, kind="feeds"))

    # 4. finding nodes
    if include_findings:
        for f in result.findings:
            fid = f"finding:{f.finding_id}"
            nodes.append(GraphNode(
                id=fid,
                type="finding",
                label=f.name,
                properties={
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "path": f.path,
                    "owasp_llm": _list_metadata(f, "owasp_llm"),
                    "mitre_atlas": _list_metadata(f, "mitre_atlas"),
                    "score": _score_for(f),
                },
            ))
            asset_id = "asset:" + f"{f.category}::{f.name}".replace(" ", "_")
            edges.append(GraphEdge(source=fid, target=asset_id, kind="affects"))

    return {
        "scan_root": result.root,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": [_node_to_dict(n) for n in nodes],
        "edges": [{"source": e.source, "target": e.target, "kind": e.kind} for e in edges],
    }


def render_asset_graph_json(result: ScanResult, *, include_findings: bool = True) -> str:
    return json.dumps(build_asset_graph(result, include_findings=include_findings), indent=2)


# --------------------------------------------------------------------------- #
# Graph diff (P7)
# --------------------------------------------------------------------------- #

@dataclass
class AssetGraphDiff:
    nodes_added: list[dict[str, Any]] = field(default_factory=list)
    nodes_removed: list[dict[str, Any]] = field(default_factory=list)
    nodes_changed: list[dict[str, Any]] = field(default_factory=list)
    edges_added: list[dict[str, Any]] = field(default_factory=list)
    edges_removed: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "nodes_added": len(self.nodes_added),
                "nodes_removed": len(self.nodes_removed),
                "nodes_changed": len(self.nodes_changed),
                "edges_added": len(self.edges_added),
                "edges_removed": len(self.edges_removed),
            },
            "nodes_added": self.nodes_added,
            "nodes_removed": self.nodes_removed,
            "nodes_changed": self.nodes_changed,
            "edges_added": self.edges_added,
            "edges_removed": self.edges_removed,
        }


def diff_asset_graphs(older: dict[str, Any], newer: dict[str, Any]) -> AssetGraphDiff:
    """Compute the difference between two asset-graph dicts (build_asset_graph output)."""
    old_nodes = {n["id"]: n for n in (older.get("nodes") or [])}
    new_nodes = {n["id"]: n for n in (newer.get("nodes") or [])}

    diff = AssetGraphDiff()
    for nid, node in new_nodes.items():
        if nid not in old_nodes:
            diff.nodes_added.append(node)
        elif _node_changed(old_nodes[nid], node):
            diff.nodes_changed.append({"id": nid, "before": old_nodes[nid], "after": node})
    for nid, node in old_nodes.items():
        if nid not in new_nodes:
            diff.nodes_removed.append(node)

    old_edges = {(e["source"], e["target"], e["kind"]): e for e in (older.get("edges") or [])}
    new_edges = {(e["source"], e["target"], e["kind"]): e for e in (newer.get("edges") or [])}
    for key, edge in new_edges.items():
        if key not in old_edges:
            diff.edges_added.append(edge)
    for key, edge in old_edges.items():
        if key not in new_edges:
            diff.edges_removed.append(edge)

    return diff


def render_asset_graph_diff_json(older: dict[str, Any], newer: dict[str, Any]) -> str:
    return json.dumps(diff_asset_graphs(older, newer).to_dict(), indent=2)


def _node_changed(old: dict[str, Any], new: dict[str, Any]) -> bool:
    """A node 'changed' when its properties differ — labels and ids are
    excluded from the comparison so a label tweak alone doesn't churn."""
    return (old.get("properties") or {}) != (new.get("properties") or {})


# --------------------------------------------------------------------------- #

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _max_severity(group: list[Finding]) -> str:
    return max(group, key=lambda f: _SEVERITY_RANK.get(f.severity, 0)).severity


def _node_to_dict(node: GraphNode) -> dict[str, Any]:
    return {"id": node.id, "type": node.type, "label": node.label, "properties": node.properties}


def _paths_for_asset(group: list[Finding]) -> set[str]:
    return {f.path for f in group if f.path}


def _strip_prefix(asset_id: str) -> str:
    return asset_id.removeprefix("asset:").replace("_", " ")


def _list_metadata(finding: Finding, key: str) -> list[str]:
    val = finding.metadata.get(key)
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val]
    return []


def _score_for(finding: Finding) -> int:
    from aibom.risk import score_for_finding
    return score_for_finding(finding)
