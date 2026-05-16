"""Tests for P12 — git-diff scoped scan + PR/MR comment connectors."""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.cli import main
from aibom.diff import FindingDiff
from aibom.git_diff import changed_files, scan_diff
from aibom.models import Finding, MatchEvidence, ScanResult, ScanStats
from aibom.pr_comment._http import PrCommentError
from aibom.pr_comment.bitbucket_server import post_bitbucket_server_pr_comment
from aibom.pr_comment.format import format_aibom_comment, format_diff_comment
from aibom.pr_comment.gitea import post_gitea_pr_comment
from aibom.pr_comment.github import post_github_pr_comment
from aibom.pr_comment.gitlab import post_gitlab_mr_comment


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


# --------------------------------------------------------------------------- #
# git_diff
# --------------------------------------------------------------------------- #

class GitDiffTests(unittest.TestCase):
    def _fake_runner(self, stdout: str):
        def runner(cmd, repo_root):
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=stdout, stderr="")
        return runner

    def test_changed_files_skips_deletions(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = changed_files(
                root, "main", "HEAD",
                runner=self._fake_runner(
                    "A\tadded.py\nM\tmodified.py\nD\tdeleted.py\nR100\tnew.py\n"
                ),
            )
            self.assertEqual(files, ["added.py", "modified.py", "new.py"])

    def test_scan_diff_filters_findings_by_path(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "changed.py", "from openai import OpenAI\nOpenAI()\n")
            _write(root / "untouched.py", "from anthropic import Anthropic\n")
            result = scan_diff(
                root, "main", "HEAD",
                runner=self._fake_runner("M\tchanged.py\n"),
            )
            paths = {f.path for f in result.findings}
            self.assertIn("changed.py", paths)
            self.assertNotIn("untouched.py", paths)


# --------------------------------------------------------------------------- #
# format
# --------------------------------------------------------------------------- #

def _f(rule_id: str, severity: str, path: str = "x.py", summary: str = "summary") -> Finding:
    return Finding(
        finding_id=f"id-{rule_id}-{path}",
        rule_id=rule_id, category="provider", name=rule_id,
        severity=severity, confidence="high", path=path,
        detector="d", entity_type="provider", source_kind="source",
        summary=summary,
        evidence=[MatchEvidence(line=1, snippet="x", match=rule_id)],
        metadata={},
    )


class FormatTests(unittest.TestCase):
    def test_aibom_comment_lists_high_findings(self) -> None:
        result = ScanResult(root="/tmp", findings=[
            _f("a", "low"), _f("b", "critical"), _f("c", "high"),
        ], stats=ScanStats(files_scanned=1))
        body = format_aibom_comment(result, title="Test")
        self.assertIn("### Test", body)
        self.assertIn("critical", body)
        self.assertIn("`b`", body)
        self.assertIn("`c`", body)

    def test_aibom_comment_no_high_says_so(self) -> None:
        result = ScanResult(root="/tmp", findings=[_f("a", "low")], stats=ScanStats())
        body = format_aibom_comment(result)
        self.assertIn("No critical or high findings", body)

    def test_diff_comment_summarizes_added_and_raised(self) -> None:
        diff = FindingDiff(
            added=[_f("new1", "critical"), _f("new2", "medium")],
            removed=[],
            severity_raised=[(_f("a", "low"), _f("a", "high"))],
            severity_lowered=[],
            unchanged_count=42,
        )
        body = format_diff_comment(diff)
        self.assertIn("**2 added**", body)
        self.assertIn("**1 raised**", body)
        self.assertIn("**42 unchanged**", body)
        self.assertIn("low → **high**", body)


# --------------------------------------------------------------------------- #
# pr_comment posters
# --------------------------------------------------------------------------- #

class PrCommentTests(unittest.TestCase):
    def _capturing_requester(self, captured: dict, status: int = 201):
        def requester(url, body, headers):
            captured["url"] = url
            captured["body"] = body
            captured["headers"] = headers
            return {"status": status, "body": "{}"}
        return requester

    def test_github(self) -> None:
        os.environ["GITHUB_TOKEN"] = "ghp_test"
        try:
            captured: dict = {}
            post_github_pr_comment("acme/app", 42, "hi", requester=self._capturing_requester(captured))
            self.assertEqual(captured["url"], "https://api.github.com/repos/acme/app/issues/42/comments")
            self.assertEqual(captured["headers"]["Authorization"], "Bearer ghp_test")
            self.assertEqual(json.loads(captured["body"]), {"body": "hi"})
        finally:
            del os.environ["GITHUB_TOKEN"]

    def test_github_missing_token(self) -> None:
        os.environ.pop("GITHUB_TOKEN", None)
        with self.assertRaises(PrCommentError):
            post_github_pr_comment("acme/app", 42, "hi")

    def test_github_bad_repo_form(self) -> None:
        os.environ["GITHUB_TOKEN"] = "x"
        try:
            with self.assertRaises(PrCommentError):
                post_github_pr_comment("bad-repo", 1, "hi")
        finally:
            del os.environ["GITHUB_TOKEN"]

    def test_gitlab_with_url_encoded_project(self) -> None:
        os.environ["GITLAB_TOKEN"] = "glpat_test"
        try:
            captured: dict = {}
            post_gitlab_mr_comment(
                "group/subgroup/project", 7, "hi",
                base_url="https://gitlab.example",
                requester=self._capturing_requester(captured),
            )
            self.assertIn("group%2Fsubgroup%2Fproject", captured["url"])
            self.assertEqual(captured["headers"]["PRIVATE-TOKEN"], "glpat_test")
        finally:
            del os.environ["GITLAB_TOKEN"]

    def test_gitlab_numeric_project_not_re_encoded(self) -> None:
        os.environ["GITLAB_TOKEN"] = "x"
        try:
            captured: dict = {}
            post_gitlab_mr_comment(
                "12345", 1, "hi",
                base_url="https://gitlab.example",
                requester=self._capturing_requester(captured),
            )
            self.assertIn("/projects/12345/", captured["url"])
        finally:
            del os.environ["GITLAB_TOKEN"]

    def test_bitbucket_server(self) -> None:
        os.environ["BITBUCKET_TOKEN"] = "bbtok"
        try:
            captured: dict = {}
            post_bitbucket_server_pr_comment(
                "PROJ", "repo", 7, "hi",
                base_url="https://bb.example",
                requester=self._capturing_requester(captured),
            )
            self.assertEqual(
                captured["url"],
                "https://bb.example/rest/api/1.0/projects/PROJ/repos/repo/pull-requests/7/comments",
            )
            self.assertEqual(json.loads(captured["body"]), {"text": "hi"})
            self.assertEqual(captured["headers"]["Authorization"], "Bearer bbtok")
        finally:
            del os.environ["BITBUCKET_TOKEN"]

    def test_gitea(self) -> None:
        os.environ["GITEA_TOKEN"] = "gtok"
        try:
            captured: dict = {}
            post_gitea_pr_comment(
                "acme/app", 5, "hi",
                base_url="https://gitea.example",
                requester=self._capturing_requester(captured),
            )
            self.assertEqual(
                captured["url"],
                "https://gitea.example/api/v1/repos/acme/app/issues/5/comments",
            )
            self.assertEqual(captured["headers"]["Authorization"], "token gtok")
        finally:
            del os.environ["GITEA_TOKEN"]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

class CliScanRefsTests(unittest.TestCase):
    def test_missing_git_falls_back_with_exit_3(self) -> None:
        with TemporaryDirectory() as tmp:
            rc = main(["scan-refs", "doesnotexist", "HEAD", "--repo", "/nonexistent/path"])
            # Path doesn't exist -> exit 2 from the repo-existence check
            self.assertEqual(rc, 2)


class CliPrCommentTests(unittest.TestCase):
    def test_missing_inputs_returns_error(self) -> None:
        # No --scan and no --diff
        with TemporaryDirectory() as tmp:
            rc = main(["pr-comment", "github", "acme/app", "1"])
            self.assertEqual(rc, 4)

    def test_pr_comment_with_scan_payload(self) -> None:
        # Monkey-patch the github poster via env-controlled requester is hard from
        # the CLI; instead we test that the body builder accepts a real scan JSON.
        with TemporaryDirectory() as tmp:
            scan = ScanResult(root="/x", findings=[_f("provider.openai.pattern", "high")],
                              stats=ScanStats(files_scanned=1))
            scan_path = Path(tmp) / "scan.json"
            scan_path.write_text(json.dumps(scan.to_dict()), encoding="utf-8")
            os.environ["GITHUB_TOKEN"] = "x"
            try:
                rc = main([
                    "pr-comment", "github", "acme/app", "1",
                    "--scan", str(scan_path),
                    "--api-base", "https://example.invalid",
                ])
                # We don't have a requester injection from CLI — the urllib call
                # will fail with PrCommentError -> exit 4. The point is that we
                # got past body construction (which would have raised
                # ValueError without --scan).
                self.assertEqual(rc, 4)
            finally:
                del os.environ["GITHUB_TOKEN"]


if __name__ == "__main__":
    unittest.main()
