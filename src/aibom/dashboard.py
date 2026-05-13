"""Executive HTML dashboard for AiBOM scans.

A single self-contained page summarising the scan: KPIs, top assets by
risk, severity distribution, OWASP-LLM-Top-10 coverage. No external
CSS/JS — drops into any HTTP server or local file viewer.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone

from aibom.models import ScanResult
from aibom.risk import score_per_asset


def generate_executive_dashboard_html(result: ScanResult) -> str:
    parts: list[str] = [_HEAD]
    parts.append("<header>")
    parts.append("<h1>AiBOM — Executive Dashboard</h1>")
    parts.append(f"<p class='meta'>Generated {_now()} · Scan root <code>{html.escape(result.root)}</code></p>")
    parts.append("</header>")

    parts.append("<section class='kpis'>")
    parts.append(_kpi_card("Findings", len(result.findings)))
    parts.append(_kpi_card("Files scanned", result.stats.files_scanned))
    asset_risks = score_per_asset(result.findings)
    parts.append(_kpi_card("AI assets", len(asset_risks)))
    top_score = max((ar.score for ar in asset_risks), default=0)
    parts.append(_kpi_card("Top risk", top_score))
    crit_count = sum(1 for f in result.findings if f.severity == "critical")
    parts.append(_kpi_card("Critical findings", crit_count))
    parts.append("</section>")

    parts.append(_severity_block(result))
    parts.append(_top_assets_block(asset_risks))
    parts.append(_owasp_coverage_block(result))
    parts.append(_iac_runtime_block(result))

    parts.append(_FOOT)
    return "".join(parts)


# --------------------------------------------------------------------------- #

def _kpi_card(label: str, value) -> str:
    return f"<div class='kpi'><div class='kpi-value'>{html.escape(str(value))}</div><div class='kpi-label'>{html.escape(label)}</div></div>"


def _severity_block(result: ScanResult) -> str:
    counts = Counter(f.severity for f in result.findings)
    total = sum(counts.values()) or 1
    bars = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = counts.get(sev, 0)
        pct = (count / total) * 100
        bars.append(
            f"<div class='bar-row'>"
            f"<span class='bar-label sev-{sev}'>{sev}</span>"
            f"<div class='bar'><div class='bar-fill sev-{sev}-bg' style='width:{pct:.1f}%'></div></div>"
            f"<span class='bar-count'>{count}</span>"
            f"</div>"
        )
    return "<section><h2>Findings by severity</h2>" + "".join(bars) + "</section>"


def _top_assets_block(asset_risks) -> str:
    sorted_risks = sorted(asset_risks, key=lambda ar: ar.score, reverse=True)[:10]
    if not sorted_risks:
        return "<section><h2>Top assets by risk</h2><p class='empty'>No assets scored.</p></section>"
    rows = ["<section><h2>Top assets by risk</h2>"
            "<table><thead><tr><th>Asset</th><th>Risk score</th><th>Top contributors</th></tr></thead><tbody>"]
    for ar in sorted_risks:
        contribs = ", ".join(f"{name}:+{val}" for name, val in ar.components[:4])
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(ar.asset_key)}</code></td>"
            f"<td class='risk'>{ar.score}</td>"
            f"<td class='small'>{html.escape(contribs)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></section>")
    return "".join(rows)


def _owasp_coverage_block(result: ScanResult) -> str:
    counts: Counter[str] = Counter()
    for f in result.findings:
        for ref in f.metadata.get("owasp_llm", []) or []:
            counts[str(ref)] += 1
    if not counts:
        return ""
    rows = ["<section><h2>OWASP LLM Top-10 coverage</h2>"
            "<table><thead><tr><th>Control</th><th>Findings</th></tr></thead><tbody>"]
    for control, count in sorted(counts.items()):
        rows.append(f"<tr><td><code>{html.escape(control)}</code></td><td>{count}</td></tr>")
    rows.append("</tbody></table></section>")
    return "".join(rows)


def _iac_runtime_block(result: ScanResult) -> str:
    iac = [f for f in result.findings if f.entity_type == "iac"]
    ci = [f for f in result.findings if f.entity_type in {"ci", "training_run"}]
    if not iac and not ci:
        return ""
    rows = ["<section><h2>Deployment + CI evidence</h2>"
            "<table><thead><tr><th>Kind</th><th>Count</th></tr></thead><tbody>"]
    rows.append(f"<tr><td>IaC declarations (Terraform / Helm / K8s)</td><td>{len(iac)}</td></tr>")
    rows.append(f"<tr><td>CI / training-run evidence</td><td>{len(ci)}</td></tr>")
    rows.append("</tbody></table></section>")
    return "".join(rows)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


_HEAD = """<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<title>AiBOM — Executive Dashboard</title>
<style>
  body { font-family: -apple-system, system-ui, Segoe UI, sans-serif; margin: 2em auto; max-width: 1100px; color: #1a1a1a; }
  header { border-bottom: 2px solid #333; padding-bottom: 1em; margin-bottom: 2em; }
  h1 { margin: 0; font-size: 1.6em; }
  .meta { color: #555; font-size: 0.9em; margin: 0.3em 0; }
  section { margin-bottom: 2em; }
  h2 { font-size: 1.15em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
  .kpis { display: flex; gap: 1em; flex-wrap: wrap; }
  .kpi { flex: 1; min-width: 140px; padding: 1em; border: 1px solid #ddd; border-radius: 6px; background: #fafafa; text-align: center; }
  .kpi-value { font-size: 1.8em; font-weight: 700; color: #1a1a1a; }
  .kpi-label { font-size: 0.85em; color: #666; margin-top: 0.3em; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
  th, td { text-align: left; padding: 0.45em 0.6em; border-bottom: 1px solid #eee; }
  th { background: #f6f6f6; }
  td.risk { font-weight: 700; text-align: right; }
  td.small { font-size: 0.82em; color: #555; }
  code { font-size: 0.85em; background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }
  .bar-row { display: flex; align-items: center; gap: 0.6em; margin: 0.3em 0; }
  .bar-label { display: inline-block; width: 80px; font-size: 0.85em; text-transform: uppercase; font-weight: 600; }
  .bar { flex: 1; height: 14px; background: #f0f0f0; border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; }
  .bar-count { width: 50px; text-align: right; font-variant-numeric: tabular-nums; color: #555; }
  .sev-critical-bg { background: #b71c1c; } .sev-critical { color: #b71c1c; }
  .sev-high-bg     { background: #d84315; } .sev-high     { color: #d84315; }
  .sev-medium-bg   { background: #ef6c00; } .sev-medium   { color: #ef6c00; }
  .sev-low-bg      { background: #689f38; } .sev-low      { color: #689f38; }
  .sev-info-bg     { background: #607d8b; } .sev-info     { color: #455a64; }
  .empty { color: #777; font-style: italic; }
</style></head><body>
"""

_FOOT = "</body></html>"
