"""EU AI Act Annex IV technical-file report generator.

Annex IV defines the technical documentation that providers of high-risk
AI systems must keep on file. We map every detected finding to the
relevant section. Sections we cannot infer from a static scan (notably
section 7 — Declaration of Conformity, a legal document) are left
explicitly marked AS \"requires manual completion\" so reviewers know
where the gap is.

Sections (per EU 2024/1689 Annex IV):

  1. General description (intended purpose, dev info, version)
  2. Detailed description (data, training, compute, model card)
  3. Monitoring / functioning / control (human oversight)
  4. Risk management system (identified risks + mitigations)
  5. Changes through lifecycle
  6. Standards / specifications applied
  7. Declaration of conformity                  -- LEGAL, manual
  8. Post-market monitoring plan                -- runtime, manual
  9. List of standards used

The output is self-contained HTML (no external CSS/JS) so it can be
attached to a regulator submission unchanged.
"""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from aibom.models import Finding, ScanResult
from aibom.risk import score_per_asset


# Each rule_id is mapped to the Annex IV section(s) it informs.
# Rule -> tuple of section numbers it speaks to.
_RULE_TO_SECTIONS: dict[str, tuple[int, ...]] = {
    # Section 2 — datasets / training / model card
    "dataset.huggingface.load": (2,),
    "dataset.huggingface.hub_path": (2,),
    "dataset.s3.uri": (2,),
    "dataset.gcs.uri": (2,),
    "dataset.azure_blob.uri": (2,),
    "dataset.bigquery.table": (2,),
    "dataset.snowflake.client": (2,),
    "dataset.parquet.read": (2,),
    "dataset.delta.uri": (2,),
    "dataset.dvc": (2, 5),
    "dataset.lakefs.uri": (2, 5),
    "dataset.csv.read": (2,),
    "model_artifact.format": (2, 6),
    "model_artifact.modelscan": (2, 6),
    "evidence.mlflow.run": (2, 5),

    # Section 3 — operation / monitoring
    "endpoint.ai.pattern": (3,),
    "iac.terraform.ai_resource": (3,),
    "iac.helm_k8s.ai_image": (3,),

    # Section 4 — risk management
    "secret.ai_key.pattern": (4,),
    "env_var.ai.pattern": (4,),
    "data_flow.same_file": (4,),
    "prompt.pattern": (4,),
    "prompt_risk.secret_leak": (4,),
    "prompt_risk.jailbreak": (4,),
    "prompt_risk.role_override": (4,),
    "prompt_risk.excessive_agency": (4,),
    "prompt_risk.pii_collection": (4,),
    "hf.license.unknown": (4, 6),
    "hf.safetensors.absent": (4,),
    "hf.popularity.low": (4,),

    # Section 5 — changes through lifecycle
    "evidence.mlflow.run": (2, 5),
    "gha.model.publish": (5,),
    "gha.dataset.upload": (5,),

    # Section 6 — standards / specifications
    "package.ai_sdk.pattern": (6,),
    "framework.agent.pattern": (6,),
    "vector_db.pattern": (6,),

    # Section 1 — general description (model identifiers)
    "model.pattern": (1,),
    "provider.openai.pattern": (1,),
    "provider.anthropic.pattern": (1,),
    "provider.google.pattern": (1,),
    "provider.azure_openai.pattern": (1,),
    "provider.bedrock.pattern": (1,),
    "provider.cohere_mistral.pattern": (1,),
}


_SECTION_TITLES = {
    1: "General description",
    2: "Detailed description (data, training, compute, model card)",
    3: "Monitoring, functioning, and control",
    4: "Risk management system",
    5: "Changes through the lifecycle",
    6: "Standards and specifications applied",
    7: "EU Declaration of Conformity (manual — legal document)",
    8: "Post-market monitoring plan (manual — requires runtime data)",
    9: "List of harmonised standards applied",
}


def generate_annex_iv_html(result: ScanResult) -> str:
    sections = _bucket_findings_by_section(result.findings)
    asset_risks = {ar.asset_key: ar.score for ar in score_per_asset(result.findings)}
    return _render_html(result, sections, asset_risks)


# --------------------------------------------------------------------------- #

def _bucket_findings_by_section(findings: Iterable[Finding]) -> dict[int, list[Finding]]:
    out: dict[int, list[Finding]] = defaultdict(list)
    for f in findings:
        for section in _RULE_TO_SECTIONS.get(f.rule_id, ()):
            out[section].append(f)
    return out


def _render_html(result: ScanResult, sections: dict[int, list[Finding]], asset_risks: dict[str, int]) -> str:
    parts: list[str] = []
    parts.append(_HTML_HEAD)
    parts.append(f"<header><h1>EU AI Act — Annex IV Technical File</h1>")
    parts.append(f"<p class='meta'>Generated {_now()} · Scan root <code>{html.escape(result.root)}</code></p>")
    parts.append(f"<p class='meta'>Findings: {len(result.findings)} · Files scanned: {result.stats.files_scanned}</p>")
    parts.append("</header>")
    parts.append("<main>")

    for section_id, title in _SECTION_TITLES.items():
        parts.append(f"<section id='section-{section_id}'>")
        parts.append(f"<h2>Section {section_id}. {html.escape(title)}</h2>")
        if section_id in {7, 8}:
            parts.append("<p class='manual'>This section requires manual completion — no static-scan signals can establish it.</p>")
            parts.append("</section>")
            continue
        section_findings = sections.get(section_id, [])
        if not section_findings:
            parts.append("<p class='empty'>No findings detected for this section.</p>")
            parts.append("</section>")
            continue
        parts.append(_render_section_table(section_findings, asset_risks))
        parts.append("</section>")

    parts.append("</main>")
    parts.append(_HTML_FOOT)
    return "".join(parts)


def _render_section_table(findings: list[Finding], asset_risks: dict[str, int]) -> str:
    rows = []
    rows.append("<table><thead><tr>"
                "<th>Severity</th><th>Risk</th><th>Rule</th><th>Asset</th><th>File</th><th>Summary</th>"
                "</tr></thead><tbody>")
    sorted_findings = sorted(findings, key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    for f in sorted_findings:
        asset_key = f"{f.category}::{f.name}"
        risk = asset_risks.get(asset_key, 0)
        rows.append(
            "<tr>"
            f"<td class='sev sev-{html.escape(f.severity)}'>{html.escape(f.severity)}</td>"
            f"<td class='risk'>{risk}</td>"
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td>{html.escape(f.name)}</td>"
            f"<td><code>{html.escape(f.path)}</code></td>"
            f"<td>{html.escape(f.summary)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "".join(rows)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


_HTML_HEAD = """<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<title>EU AI Act — Annex IV Technical File</title>
<style>
  body { font-family: -apple-system, system-ui, Segoe UI, sans-serif; margin: 2em auto; max-width: 1100px; color: #1a1a1a; }
  header { border-bottom: 2px solid #333; padding-bottom: 1em; margin-bottom: 2em; }
  h1 { margin: 0; font-size: 1.6em; }
  .meta { color: #555; font-size: 0.9em; margin: 0.3em 0; }
  section { margin-bottom: 2em; }
  h2 { font-size: 1.15em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th, td { text-align: left; padding: 0.45em 0.6em; border-bottom: 1px solid #eee; vertical-align: top; }
  th { background: #f6f6f6; font-weight: 600; }
  code { font-size: 0.85em; background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }
  .sev { font-weight: 600; text-transform: uppercase; font-size: 0.78em; }
  .sev-critical { color: #b71c1c; }
  .sev-high     { color: #d84315; }
  .sev-medium   { color: #ef6c00; }
  .sev-low      { color: #689f38; }
  .sev-info     { color: #455a64; }
  .risk { font-weight: 600; text-align: right; }
  .empty, .manual { color: #777; font-style: italic; }
</style></head><body>
"""

_HTML_FOOT = "</body></html>"
