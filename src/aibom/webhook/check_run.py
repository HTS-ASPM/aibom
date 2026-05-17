"""GitHub Check Run API integration.

POST https://api.github.com/repos/{owner}/{repo}/check-runs

Builds a 'completed' check from an AiBOM ScanResult:

  conclusion = failure if any critical/high finding else neutral
  output.title    = short summary
  output.summary  = markdown finding table
  output.annotations = up to 50 inline annotations (file + line + level)

Annotations let GitHub render findings as inline review comments on
the PR diff — the same channel used by Code Scanning / SARIF uploads
but without requiring repository Advanced Security to be enabled.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any

from aibom.models import Finding, ScanResult
from aibom.pr_comment._http import PrCommentError, Requester, post_json


_LEVEL_MAP = {
    "critical": "failure",
    "high": "failure",
    "medium": "warning",
    "low": "notice",
    "info": "notice",
}


def build_check_run_body(
    result: ScanResult,
    *,
    name: str = "aibom",
    head_sha: str,
    details_url: str | None = None,
) -> dict[str, Any]:
    counts = Counter(f.severity for f in result.findings)
    critical_or_high = sum(counts[k] for k in ("critical", "high"))
    conclusion = "failure" if critical_or_high else ("neutral" if result.findings else "success")
    title = (
        f"{critical_or_high} critical/high finding(s)"
        if critical_or_high
        else f"{len(result.findings)} finding(s) — no critical/high"
    )
    summary_lines = [
        "**aibom scan summary**",
        "",
        " · ".join(f"**{k}**: {v}" for k, v in counts.most_common()) or "_no findings_",
        "",
        f"_Scan root: `{result.root}` — files scanned: {result.stats.files_scanned}_",
    ]
    body: dict[str, Any] = {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": "\n".join(summary_lines),
            "annotations": _build_annotations(result.findings),
        },
    }
    if details_url:
        body["details_url"] = details_url
    return body


def post_check_run(
    repo: str,
    body: dict[str, Any],
    *,
    token_env: str = "GITHUB_TOKEN",
    api_base: str = "https://api.github.com",
    requester: Requester | None = None,
) -> dict[str, Any]:
    token = os.environ.get(token_env)
    if not token:
        raise PrCommentError(f"missing token in env {token_env}")
    if "/" not in repo:
        raise PrCommentError("repo must be in owner/repo form")
    url = f"{api_base.rstrip('/')}/repos/{repo}/check-runs"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "aibom-check-run",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return post_json(url, body, headers=headers, requester=requester)


# --------------------------------------------------------------------------- #

def _build_annotations(findings: list[Finding], *, cap: int = 50) -> list[dict[str, Any]]:
    """GitHub caps annotations at 50 per Check Run update; we trim and prioritize critical/high."""
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sorted_findings = sorted(findings, key=lambda f: rank.get(f.severity, 0), reverse=True)
    out: list[dict[str, Any]] = []
    for f in sorted_findings[:cap]:
        line = _first_evidence_line(f) or 1
        annotation = {
            "path": f.path,
            "start_line": line,
            "end_line": line,
            "annotation_level": _LEVEL_MAP.get(f.severity, "notice"),
            "title": f.name[:80],
            "message": f.summary[:600] or f.rule_id,
            "raw_details": f"rule_id: {f.rule_id}\nseverity: {f.severity}\nconfidence: {f.confidence}",
        }
        out.append(annotation)
    return out


def _first_evidence_line(finding: Finding) -> int | None:
    for ev in finding.evidence:
        if getattr(ev, "line", None):
            return int(ev.line)
    return None
