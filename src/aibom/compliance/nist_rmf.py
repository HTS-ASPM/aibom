"""NIST AI RMF (GAI profile) crosswalk.

Buckets every finding by which RMF Function it informs (GOVERN, MAP,
MEASURE, MANAGE). Findings already carry an `nist_ai_rmf` metadata
list (populated in P2 by aibom.owasp_mapping); this module groups by
the prefix of those control IDs:

  GV-x.y -> GOVERN
  MP-x.y -> MAP
  MS-x.y -> MEASURE
  MG-x.y -> MANAGE
"""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from aibom.models import Finding, ScanResult


_FUNCTIONS = {
    "GV": "GOVERN — Cultivate a culture of risk management",
    "MP": "MAP — Establish context to identify and frame AI risks",
    "MS": "MEASURE — Analyze, assess, benchmark, and monitor AI risk",
    "MG": "MANAGE — Allocate resources to mapped/measured risks",
}


def generate_nist_rmf_html(result: ScanResult) -> str:
    grouped = _group_by_function(result.findings)
    return _render(result, grouped)


# --------------------------------------------------------------------------- #

def _group_by_function(findings: Iterable[Finding]) -> dict[str, dict[str, list[Finding]]]:
    """Returns { function_code: { control_id: [findings] } }."""
    out: dict[str, dict[str, list[Finding]]] = {fn: defaultdict(list) for fn in _FUNCTIONS}
    for f in findings:
        refs = f.metadata.get("nist_ai_rmf")
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if not isinstance(ref, str):
                continue
            prefix = ref.split("-", 1)[0].upper()
            if prefix in out:
                out[prefix][ref].append(f)
    return out


def _render(result: ScanResult, grouped: dict[str, dict[str, list[Finding]]]) -> str:
    parts: list[str] = [_HTML_HEAD]
    parts.append("<header><h1>NIST AI RMF — Generative AI Profile Crosswalk</h1>")
    parts.append(f"<p class='meta'>Generated {_now()} · Scan root <code>{html.escape(result.root)}</code></p>")
    parts.append(f"<p class='meta'>Findings: {len(result.findings)}</p>")
    parts.append("</header><main>")
    for fn_code, fn_title in _FUNCTIONS.items():
        controls = grouped.get(fn_code, {})
        finding_count = sum(len(v) for v in controls.values())
        parts.append(f"<section id='fn-{fn_code}'>")
        parts.append(f"<h2>{html.escape(fn_title)} <span class='count'>({finding_count} findings)</span></h2>")
        if not controls:
            parts.append("<p class='empty'>No findings mapped to this function.</p></section>")
            continue
        parts.append("<table><thead><tr>"
                     "<th>Control</th><th>Findings</th><th>Highest severity</th><th>Example</th>"
                     "</tr></thead><tbody>")
        for control_id in sorted(controls):
            findings = controls[control_id]
            highest = _highest(findings)
            example = findings[0]
            parts.append(
                "<tr>"
                f"<td><code>{html.escape(control_id)}</code></td>"
                f"<td>{len(findings)}</td>"
                f"<td class='sev sev-{highest}'>{highest}</td>"
                f"<td>{html.escape(example.summary[:160])}</td>"
                "</tr>"
            )
        parts.append("</tbody></table></section>")
    parts.append("</main>" + _HTML_FOOT)
    return "".join(parts)


def _highest(findings: list[Finding]) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return max(findings, key=lambda f: rank.get(f.severity, 0)).severity


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


_HTML_HEAD = """<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<title>NIST AI RMF — Crosswalk</title>
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
  .empty { color: #777; font-style: italic; }
</style></head><body>
"""

_HTML_FOOT = "</body></html>"
