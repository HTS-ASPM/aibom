"""ISO/IEC 42001:2023 — AI management system control crosswalk.

42001 defines an AI Management System (AIMS) with Annex A controls
across nine groups. We map our rule_ids to the most directly relevant
control(s); the report renders a per-control summary similar to the
NIST RMF crosswalk.

Annex A control groups:
  A.4  Context of the organization
  A.5  Leadership
  A.6  Planning (incl. AI risk + impact assessment)
  A.7  Support  (resources, competence, awareness, communication)
  A.8  Operation (operational planning + control)
  A.9  Performance evaluation (monitoring, measurement, audit)
  A.10 Improvement (corrective action)

The mapping is intentionally curated rather than exhaustive — the
goal is auditor traceability, not an attempt to assert formal
conformity (which only the AIMS itself can do).
"""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime, timezone

from aibom.models import Finding, ScanResult


# rule_id -> list of (control_id, short title)
_RULE_TO_42001: dict[str, list[tuple[str, str]]] = {
    # A.6 Planning — AI risk + impact assessment
    "secret.ai_key.pattern": [("A.6.2.6", "AI risk treatment")],
    "env_var.ai.pattern": [("A.6.2.6", "AI risk treatment")],
    "data_flow.same_file": [("A.6.2.5", "AI system impact assessment")],
    "prompt_risk.secret_leak": [("A.6.2.6", "AI risk treatment")],
    "prompt_risk.jailbreak": [("A.6.2.6", "AI risk treatment")],
    "prompt_risk.role_override": [("A.6.2.6", "AI risk treatment")],
    "prompt_risk.excessive_agency": [("A.6.2.5", "AI system impact assessment")],
    "prompt_risk.pii_collection": [("A.6.2.5", "AI system impact assessment")],

    # A.7 Support — resources / competence
    "framework.agent.pattern": [("A.7.4", "Communication")],
    "package.ai_sdk.pattern": [("A.7.4", "Communication")],
    "vector_db.pattern": [("A.7.4", "Communication")],

    # A.8 Operation — operational planning and control
    "model.pattern": [("A.8.2", "AI system operation control")],
    "endpoint.ai.pattern": [("A.8.2", "AI system operation control")],
    "iac.terraform.ai_resource": [("A.8.2", "AI system operation control")],
    "iac.helm_k8s.ai_image": [("A.8.2", "AI system operation control")],
    "model_artifact.format": [("A.8.4", "Data acquisition for AI systems"), ("A.8.2", "AI system operation control")],
    "model_artifact.modelscan": [("A.8.2", "AI system operation control")],
    "dataset.huggingface.load": [("A.8.4", "Data acquisition for AI systems")],
    "dataset.s3.uri": [("A.8.4", "Data acquisition for AI systems")],
    "dataset.gcs.uri": [("A.8.4", "Data acquisition for AI systems")],
    "dataset.azure_blob.uri": [("A.8.4", "Data acquisition for AI systems")],
    "dataset.bigquery.table": [("A.8.4", "Data acquisition for AI systems")],
    "dataset.snowflake.client": [("A.8.4", "Data acquisition for AI systems")],

    # A.9 Performance evaluation — monitoring + audit
    "evidence.mlflow.run": [("A.9.1", "Monitoring, measurement, analysis"), ("A.10.2", "Continual improvement")],
    "gha.model.publish": [("A.9.1", "Monitoring, measurement, analysis")],
    "gha.dataset.upload": [("A.9.1", "Monitoring, measurement, analysis")],
    "gha.runner.gpu": [("A.9.1", "Monitoring, measurement, analysis")],
    "gha.training.entrypoint": [("A.9.1", "Monitoring, measurement, analysis")],

    # A.5 Leadership — supplier governance
    "hf.license.unknown": [("A.5.4", "Supplier relationships")],
    "hf.safetensors.absent": [("A.5.4", "Supplier relationships"), ("A.6.2.6", "AI risk treatment")],
    "hf.popularity.low": [("A.5.4", "Supplier relationships")],
    "provider.openai.pattern": [("A.5.4", "Supplier relationships")],
    "provider.anthropic.pattern": [("A.5.4", "Supplier relationships")],
    "provider.google.pattern": [("A.5.4", "Supplier relationships")],
    "provider.azure_openai.pattern": [("A.5.4", "Supplier relationships")],
    "provider.bedrock.pattern": [("A.5.4", "Supplier relationships")],
    "provider.cohere_mistral.pattern": [("A.5.4", "Supplier relationships")],
}


def generate_iso_42001_html(result: ScanResult) -> str:
    grouped = _group(result.findings)
    return _render(result, grouped)


# --------------------------------------------------------------------------- #

def _group(findings: list[Finding]) -> dict[str, dict[str, list[Finding]]]:
    """{ group_prefix (A.4..A.10): { control_id: [findings] } }."""
    out: dict[str, dict[str, list[Finding]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        for control_id, _title in _RULE_TO_42001.get(f.rule_id, ()):
            prefix = control_id.rsplit(".", control_id.count(".") - 1)[0] if "." in control_id else control_id
            # We want only the top-level "A.5", "A.6", ... grouping
            top = ".".join(control_id.split(".")[:2])
            out[top][control_id].append(f)
    return out


def _render(result: ScanResult, grouped: dict[str, dict[str, list[Finding]]]) -> str:
    parts: list[str] = [_HTML_HEAD]
    parts.append("<header>")
    parts.append("<h1>ISO/IEC 42001 — AIMS Annex A Crosswalk</h1>")
    parts.append(f"<p class='meta'>Generated {_now()} · Scan root <code>{html.escape(result.root)}</code></p>")
    parts.append(f"<p class='meta'>Findings: {len(result.findings)}</p>")
    parts.append("</header><main>")

    for top in sorted(grouped):
        controls = grouped[top]
        finding_count = sum(len(v) for v in controls.values())
        parts.append(f"<section id='group-{top}'>")
        parts.append(f"<h2>{html.escape(top)} <span class='count'>({finding_count} findings)</span></h2>")
        parts.append("<table><thead><tr>"
                     "<th>Control</th><th>Title</th><th>Findings</th><th>Highest severity</th>"
                     "</tr></thead><tbody>")
        for control_id in sorted(controls):
            findings = controls[control_id]
            title = _title_for(control_id)
            highest = _highest(findings)
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(control_id)}</code></td>"
                f"<td>{html.escape(title)}</td>"
                f"<td>{len(findings)}</td>"
                f"<td class='sev sev-{highest}'>{highest}</td>"
                "</tr>"
            )
        parts.append("</tbody></table></section>")

    parts.append("</main>" + _HTML_FOOT)
    return "".join(parts)


def _title_for(control_id: str) -> str:
    for entries in _RULE_TO_42001.values():
        for cid, title in entries:
            if cid == control_id:
                return title
    return ""


def _highest(findings: list[Finding]) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return max(findings, key=lambda f: rank.get(f.severity, 0)).severity


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


_HTML_HEAD = """<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<title>ISO/IEC 42001 Crosswalk</title>
<style>
  body { font-family: -apple-system, system-ui, Segoe UI, sans-serif; margin: 2em auto; max-width: 1100px; color: #1a1a1a; }
  header { border-bottom: 2px solid #333; padding-bottom: 1em; margin-bottom: 2em; }
  h1 { margin: 0; font-size: 1.6em; }
  .meta { color: #555; font-size: 0.9em; margin: 0.3em 0; }
  section { margin-bottom: 2em; }
  h2 { font-size: 1.15em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
  .count { color: #888; font-weight: normal; font-size: 0.85em; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th, td { text-align: left; padding: 0.45em 0.6em; border-bottom: 1px solid #eee; }
  th { background: #f6f6f6; }
  code { font-size: 0.85em; background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }
  .sev { font-weight: 600; text-transform: uppercase; font-size: 0.78em; }
  .sev-critical { color: #b71c1c; } .sev-high { color: #d84315; }
  .sev-medium { color: #ef6c00; } .sev-low { color: #689f38; }
  .sev-info { color: #455a64; }
</style></head><body>
"""

_HTML_FOOT = "</body></html>"
