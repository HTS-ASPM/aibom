"""git-diff scoped scanning — only re-process files that actually changed.

Two entry points:

  changed_files(repo_root, base, head)        list[str] of relative paths
                                              changed between two refs.
                                              Uses `git diff --name-only`
                                              via subprocess. Tests inject
                                              a runner so no real git is
                                              required.

  scan_diff(repo_root, base, head)            ScanResult containing only
                                              findings whose `path` is in
                                              the changed-file set. Runs a
                                              full scan_path then filters
                                              — this is correct vs. tree-
                                              level detectors (artifacts,
                                              IaC, CI evidence) which need
                                              whole-tree context. The
                                              filter is on findings, not
                                              on file walking.

The "changed" set includes Added (A), Modified (M), Renamed (R; new path),
Copied (C; new path). Deletions (D) are excluded because there's no file
to scan.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from aibom.models import Finding, ScanResult, ScanStats
from aibom.scanner import scan_path


GitRunner = Callable[[list[str], Path], "subprocess.CompletedProcess[str]"]


@dataclass(frozen=True, slots=True)
class GitDiffScope:
    repo_root: Path
    base: str
    head: str
    files: tuple[str, ...]


class GitNotAvailableError(RuntimeError):
    pass


def changed_files(
    repo_root: Path,
    base: str,
    head: str = "HEAD",
    *,
    runner: GitRunner | None = None,
) -> list[str]:
    """Return repo-relative paths changed between base..head."""
    proc = _git(
        ["diff", "--name-status", "--no-renames", f"{base}..{head}"],
        repo_root,
        runner=runner,
    )
    out: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        status, path = parts[0], parts[1]
        if status.startswith("D"):
            continue
        out.append(path)
    return sorted(set(out))


def diff_scope(
    repo_root: Path,
    base: str,
    head: str = "HEAD",
    *,
    runner: GitRunner | None = None,
) -> GitDiffScope:
    files = changed_files(repo_root, base, head, runner=runner)
    return GitDiffScope(repo_root=repo_root, base=base, head=head, files=tuple(files))


def scan_diff(
    repo_root: Path,
    base: str,
    head: str = "HEAD",
    *,
    runner: GitRunner | None = None,
    max_file_size: int = 512_000,
    policy: dict | None = None,
    tuning: dict | None = None,
) -> ScanResult:
    """Run scan_path then keep only findings whose path is in the diff."""
    scope = diff_scope(repo_root, base, head, runner=runner)
    full = scan_path(
        repo_root,
        max_file_size=max_file_size,
        policy=policy,
        tuning=tuning,
    )
    allowed = {_normalize(p) for p in scope.files}
    filtered = [f for f in full.findings if _normalize(f.path) in allowed]
    return ScanResult(
        root=f"git-diff://{base}..{head}@{repo_root}",
        findings=filtered,
        stats=ScanStats(
            files_scanned=full.stats.files_scanned,
            files_skipped=full.stats.files_skipped,
            bytes_scanned=full.stats.bytes_scanned,
        ),
    )


# --------------------------------------------------------------------------- #

def _git(
    args: list[str],
    repo_root: Path,
    *,
    runner: GitRunner | None = None,
) -> "subprocess.CompletedProcess[str]":
    cmd = ["git", "-C", str(repo_root), *args]
    if runner is not None:
        return runner(cmd, repo_root)
    git_path = shutil.which("git")
    if git_path is None:
        raise GitNotAvailableError("git not found on PATH — install git or inject a runner for tests")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    if proc.returncode != 0:
        raise GitNotAvailableError(
            f"git {' '.join(args)} failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )
    return proc


def _normalize(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")
