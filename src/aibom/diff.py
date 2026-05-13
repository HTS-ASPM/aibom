"""Scan-to-scan diff — what's new, what's gone, what got worse.

Complements the existing `aibom diff-scans` CLI in store.py (which
diffs two persisted scans). This module operates on in-memory
ScanResult objects and emits a richer, structured diff that the HTS-
ASPM dashboard can render directly:

  added            — finding present in newer, absent in older
  removed          — finding present in older, absent in newer
  severity_raised  — same finding key, severity went up
  severity_lowered — same finding key, severity went down
  unchanged_count  — kept for KPI display, not enumerated

Identity = (rule_id, path) — same identity used by store.dedupe and the
existing diff command, so the two views are consistent.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Iterable

from aibom.models import Finding, ScanResult


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class FindingDiff:
    added: list[Finding] = field(default_factory=list)
    removed: list[Finding] = field(default_factory=list)
    severity_raised: list[tuple[Finding, Finding]] = field(default_factory=list)
    severity_lowered: list[tuple[Finding, Finding]] = field(default_factory=list)
    unchanged_count: int = 0

    def to_dict(self) -> dict:
        return {
            "added": [f.to_dict() for f in self.added],
            "removed": [f.to_dict() for f in self.removed],
            "severity_raised": [
                {"older": old.to_dict(), "newer": new.to_dict()}
                for old, new in self.severity_raised
            ],
            "severity_lowered": [
                {"older": old.to_dict(), "newer": new.to_dict()}
                for old, new in self.severity_lowered
            ],
            "unchanged_count": self.unchanged_count,
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "severity_raised": len(self.severity_raised),
                "severity_lowered": len(self.severity_lowered),
                "unchanged": self.unchanged_count,
            },
        }


def diff_scans(older: ScanResult, newer: ScanResult) -> FindingDiff:
    older_index = _index(older.findings)
    newer_index = _index(newer.findings)
    diff = FindingDiff()
    for key, finding in newer_index.items():
        if key not in older_index:
            diff.added.append(finding)
            continue
        old = older_index[key]
        old_rank = _SEV_RANK.get(old.severity, 0)
        new_rank = _SEV_RANK.get(finding.severity, 0)
        if new_rank > old_rank:
            diff.severity_raised.append((old, finding))
        elif new_rank < old_rank:
            diff.severity_lowered.append((old, finding))
        else:
            diff.unchanged_count += 1
    for key, finding in older_index.items():
        if key not in newer_index:
            diff.removed.append(finding)
    return diff


def render_diff_json(diff: FindingDiff, *, indent: int = 2) -> str:
    return json.dumps(diff.to_dict(), indent=indent)


def render_diff_html(diff: FindingDiff, *, older_label: str = "older", newer_label: str = "newer") -> str:
    parts: list[str] = [_HTML_HEAD]
    parts.append("<header>")
    parts.append("<h1>AiBOM scan diff</h1>")
    parts.append(f"<p class='meta'>{html.escape(older_label)} → {html.escape(newer_label)}</p>")
    parts.append("</header>")

    summary = diff.to_dict()["summary"]
    parts.append("<section class='kpis'>")
    parts.append(_kpi("Added", summary["added"], "kpi-add"))
    parts.append(_kpi("Removed", summary["removed"], "kpi-rm"))
    parts.append(_kpi("Raised", summary["severity_raised"], "kpi-up"))
    parts.append(_kpi("Lowered", summary["severity_lowered"], "kpi-down"))
    parts.append(_kpi("Unchanged", summary["unchanged"], "kpi-flat"))
    parts.append("</section>")

    parts.append(_findings_table("Added findings", diff.added))
    parts.append(_findings_table("Removed findings", diff.removed))
    parts.append(_change_table("Severity raised", diff.severity_raised))
    parts.append(_change_table("Severity lowered", diff.severity_lowered))

    parts.append(_HTML_FOOT)
    return "".join(parts)


# --------------------------------------------------------------------------- #

def _index(findings: Iterable[Finding]) -> dict[tuple[str, str], Finding]:
    out: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.path)
        # Prefer the highest-severity instance when duplicates exist.
        existing = out.get(key)
        if existing is None or _SEV_RANK.get(f.severity, 0) > _SEV_RANK.get(existing.severity, 0):
            out[key] = f
    return out


def _kpi(label: str, value, css_class: str) -> str:
    return (
        f"<div class='kpi {html.escape(css_class)}'>"
        f"<div class='kpi-value'>{html.escape(str(value))}</div>"
        f"<div class='kpi-label'>{html.escape(label)}</div></div>"
    )


def _findings_table(title: str, findings: list[Finding]) -> str:
    if not findings:
        return f"<section><h2>{html.escape(title)}</h2><p class='empty'>None.</p></section>"
    rows = [f"<section><h2>{html.escape(title)}</h2>",
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Path</th><th>Summary</th></tr></thead><tbody>"]
    for f in sorted(findings, key=lambda x: _SEV_RANK.get(x.severity, 0), reverse=True):
        rows.append(
            "<tr>"
            f"<td class='sev sev-{html.escape(f.severity)}'>{html.escape(f.severity)}</td>"
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td><code>{html.escape(f.path)}</code></td>"
            f"<td>{html.escape(f.summary[:160])}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></section>")
    return "".join(rows)


def _change_table(title: str, changes: list[tuple[Finding, Finding]]) -> str:
    if not changes:
        return f"<section><h2>{html.escape(title)}</h2><p class='empty'>None.</p></section>"
    rows = [f"<section><h2>{html.escape(title)}</h2>",
            "<table><thead><tr><th>Rule</th><th>Path</th><th>Older</th><th>Newer</th></tr></thead><tbody>"]
    for old, new in changes:
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(old.rule_id)}</code></td>"
            f"<td><code>{html.escape(old.path)}</code></td>"
            f"<td class='sev sev-{html.escape(old.severity)}'>{html.escape(old.severity)}</td>"
            f"<td class='sev sev-{html.escape(new.severity)}'>{html.escape(new.severity)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></section>")
    return "".join(rows)


_HTML_HEAD = """<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<title>AiBOM scan diff</title>
<style>
  body { font-family: -apple-system, system-ui, Segoe UI, sans-serif; margin: 2em auto; max-width: 1100px; color: #1a1a1a; }
  header { border-bottom: 2px solid #333; padding-bottom: 1em; margin-bottom: 2em; }
  h1 { margin: 0; font-size: 1.6em; }
  .meta { color: #555; font-size: 0.9em; margin: 0.3em 0; }
  section { margin-bottom: 2em; }
  h2 { font-size: 1.15em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
  .kpis { display: flex; gap: 1em; flex-wrap: wrap; margin-bottom: 1.5em; }
  .kpi { flex: 1; min-width: 120px; padding: 0.8em; border: 1px solid #ddd; border-radius: 6px; text-align: center; background: #fafafa; }
  .kpi-add  { border-color: #2e7d32; }
  .kpi-rm   { border-color: #607d8b; }
  .kpi-up   { border-color: #c62828; }
  .kpi-down { border-color: #689f38; }
  .kpi-flat { border-color: #9e9e9e; }
  .kpi-value { font-size: 1.8em; font-weight: 700; }
  .kpi-label { font-size: 0.85em; color: #666; margin-top: 0.3em; }
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
