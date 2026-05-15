"""Tests for P10 — incremental cache + GitHub App handoff + GitLab/Bitbucket connectors."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aibom.cache import (
    clear_all,
    fingerprint_text,
    lookup,
    open_cache,
    prune_other_versions,
    relabel_findings_path,
    stats_for_version,
    store,
)
from aibom.cli import main
from aibom.code_hosts import (
    BitbucketRepoRef,
    GitLabRepoRef,
    describe_github_app_token_handoff,
    github_app_installation_token_from_env,
    parse_bitbucket_ref,
    parse_gitlab_ref,
    scan_bitbucket_repo,
    scan_gitlab_repo,
)
from aibom.models import Finding, MatchEvidence
from aibom.scanner import scan_path


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _scan_root(tmp: str) -> Path:
    root = Path(tmp)
    _write(root / "app.py", "from openai import OpenAI\nclient = OpenAI()\n")
    return root


# --------------------------------------------------------------------------- #
# Cache primitives
# --------------------------------------------------------------------------- #

def _f(rel_path: str = "x.py") -> Finding:
    return Finding(
        finding_id="id-1",
        rule_id="provider.openai.pattern",
        category="provider",
        name="OpenAI usage",
        severity="medium",
        confidence="high",
        path=rel_path,
        detector="d",
        entity_type="provider",
        source_kind="source",
        summary="x",
        evidence=[MatchEvidence(line=1, snippet="x", match="x")],
        metadata={},
    )


class CacheUnitTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        with TemporaryDirectory() as tmp:
            conn = open_cache(Path(tmp) / "cache.db")
            sha = fingerprint_text("hello")
            store(conn, content_sha256=sha, rel_path="x.py", findings=[_f()])
            cached = lookup(conn, content_sha256=sha, rel_path="x.py")
            self.assertIsNotNone(cached)
            self.assertEqual(cached[0].rule_id, "provider.openai.pattern")
            conn.close()

    def test_lookup_miss_returns_none(self) -> None:
        with TemporaryDirectory() as tmp:
            conn = open_cache(Path(tmp) / "cache.db")
            self.assertIsNone(lookup(conn, content_sha256="ffff", rel_path="x.py"))
            conn.close()

    def test_clear_all_removes_rows(self) -> None:
        with TemporaryDirectory() as tmp:
            conn = open_cache(Path(tmp) / "cache.db")
            store(conn, content_sha256="a", rel_path="x.py", findings=[_f()])
            removed = clear_all(conn)
            self.assertGreaterEqual(removed, 1)
            self.assertIsNone(lookup(conn, content_sha256="a", rel_path="x.py"))
            conn.close()

    def test_prune_drops_old_versions(self) -> None:
        with TemporaryDirectory() as tmp:
            conn = open_cache(Path(tmp) / "cache.db")
            store(conn, content_sha256="a", rel_path="x.py", findings=[_f()], scanner_version="0.0.1")
            store(conn, content_sha256="b", rel_path="y.py", findings=[_f()])  # current __version__
            removed = prune_other_versions(conn)
            self.assertEqual(removed, 1)
            conn.close()

    def test_stats_returns_row_count(self) -> None:
        with TemporaryDirectory() as tmp:
            conn = open_cache(Path(tmp) / "cache.db")
            store(conn, content_sha256="a", rel_path="x.py", findings=[_f(), _f()])
            stats = stats_for_version(conn)
            self.assertEqual(stats["rows"], 1)
            conn.close()

    def test_relabel_changes_path(self) -> None:
        relabeled = relabel_findings_path([_f("old.py")], "new.py")
        self.assertEqual(relabeled[0].path, "new.py")


# --------------------------------------------------------------------------- #
# Scanner uses cache transparently
# --------------------------------------------------------------------------- #

class ScannerCacheIntegrationTests(unittest.TestCase):
    def test_second_scan_hits_cache(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            conn = open_cache(Path(tmp) / "c.db")
            r1 = scan_path(root, cache_conn=conn)
            self.assertGreater(len(r1.findings), 0)

            stats_after_first = stats_for_version(conn)
            self.assertGreaterEqual(stats_after_first["rows"], 1)

            # Wipe an unrelated tracking table, run again — same content,
            # cache hit. Findings still appear.
            r2 = scan_path(root, cache_conn=conn)
            self.assertEqual({f.rule_id for f in r2.findings}, {f.rule_id for f in r1.findings})
            conn.close()

    def test_modified_file_invalidates_its_slice(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            conn = open_cache(Path(tmp) / "c.db")
            scan_path(root, cache_conn=conn)
            # Modify the file — content fingerprint changes.
            _write(root / "app.py", "from anthropic import Anthropic\nAnthropic()\n")
            r2 = scan_path(root, cache_conn=conn)
            providers = {f.metadata.get("provider") for f in r2.findings}
            # Anthropic now appears (was OpenAI before); cache didn't pin
            # the old finding to the new content.
            self.assertIn("anthropic", providers)
            conn.close()


# --------------------------------------------------------------------------- #
# Code-host parsing
# --------------------------------------------------------------------------- #

class CodeHostParseTests(unittest.TestCase):
    def test_parse_gitlab_ref(self) -> None:
        ref = parse_gitlab_ref("group%2Fsubgroup%2Fproject", "main")
        self.assertEqual(ref.project, "group%2Fsubgroup%2Fproject")
        self.assertEqual(ref.ref, "main")
        self.assertEqual(ref.base_url, "https://gitlab.com")

    def test_parse_gitlab_self_hosted_strips_trailing_slash(self) -> None:
        ref = parse_gitlab_ref("123", "main", base_url="https://gitlab.example/")
        self.assertEqual(ref.base_url, "https://gitlab.example")

    def test_parse_bitbucket_ref(self) -> None:
        ref = parse_bitbucket_ref("acme/app", "develop")
        self.assertEqual(ref.workspace, "acme")
        self.assertEqual(ref.repo, "app")
        self.assertEqual(ref.slug, "acme/app")

    def test_parse_bitbucket_rejects_bad_form(self) -> None:
        with self.assertRaises(ValueError):
            parse_bitbucket_ref("badformat", "main")


# --------------------------------------------------------------------------- #
# GitLab / Bitbucket end-to-end with injected fetcher
# --------------------------------------------------------------------------- #

class GitLabFetchTests(unittest.TestCase):
    def test_scan_with_fake_archive(self) -> None:
        import tarfile

        with TemporaryDirectory() as tmp:
            # Build a tiny tar.gz archive that the connector will extract + scan.
            staging = Path(tmp) / "staging"
            (staging / "repo-root").mkdir(parents=True)
            (staging / "repo-root" / "app.py").write_text(
                "from openai import OpenAI\n", encoding="utf-8",
            )
            archive = Path(tmp) / "archive.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                tf.add(staging / "repo-root", arcname="repo-root")

            def fake_fetcher(repo_ref: GitLabRepoRef, dest: Path, token: str | None) -> None:
                shutil_copy = __import__("shutil").copyfile
                shutil_copy(archive, dest)

            result = scan_gitlab_repo(
                "123", ref="main", token="t",
                archive_fetcher=fake_fetcher,
            )
            self.assertTrue(result.root.startswith("gitlab://123@main"))
            self.assertGreater(len(result.findings), 0)


class BitbucketFetchTests(unittest.TestCase):
    def test_scan_with_fake_archive(self) -> None:
        import zipfile

        with TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging" / "acme-app"
            staging.mkdir(parents=True)
            (staging / "app.py").write_text("from openai import OpenAI\n", encoding="utf-8")
            archive = Path(tmp) / "archive.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.write(staging / "app.py", arcname="acme-app/app.py")

            def fake_fetcher(repo_ref: BitbucketRepoRef, dest: Path, token: str | None) -> None:
                shutil_copy = __import__("shutil").copyfile
                shutil_copy(archive, dest)

            result = scan_bitbucket_repo(
                "acme/app", ref="main", token="t",
                archive_fetcher=fake_fetcher,
            )
            self.assertTrue(result.root.startswith("bitbucket://acme/app@main"))
            self.assertGreater(len(result.findings), 0)


# --------------------------------------------------------------------------- #
# GitHub App handoff helpers (no JWT signing inside AiBOM)
# --------------------------------------------------------------------------- #

class GitHubAppHelperTests(unittest.TestCase):
    def test_token_from_env(self) -> None:
        import os
        os.environ["GITHUB_APP_INSTALLATION_TOKEN"] = "ghs_test"
        try:
            self.assertEqual(github_app_installation_token_from_env(), "ghs_test")
        finally:
            del os.environ["GITHUB_APP_INSTALLATION_TOKEN"]

    def test_describe_handoff_includes_steps(self) -> None:
        steps = describe_github_app_token_handoff(app_id="42", installation_id="99")
        self.assertIn("step_1_jwt", steps)
        self.assertIn("99", steps["step_2_token_exchange"])
        self.assertEqual(steps["app_id"], "42")


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

class CliCacheCommandTests(unittest.TestCase):
    def test_scan_use_cache_flag(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            cache_db = root / "c.db"
            out = root / "scan1.json"
            rc = main([
                "scan", str(root),
                "--use-cache", "--cache-db", str(cache_db),
                "--format", "json", "--output", str(out),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(cache_db.exists())

    def test_cache_stats_subcommand(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            cache_db = root / "c.db"
            main(["scan", str(root), "--use-cache", "--cache-db", str(cache_db),
                  "--format", "json", "--output", str(root / "x.json")])
            # Capture stdout via a pipe-like approach: run command, then verify
            # exit code only — content rendering is exercised by the cache unit tests.
            self.assertEqual(main(["cache", "stats", "--cache-db", str(cache_db)]), 0)

    def test_cache_clear_subcommand(self) -> None:
        with TemporaryDirectory() as tmp:
            root = _scan_root(tmp)
            cache_db = root / "c.db"
            main(["scan", str(root), "--use-cache", "--cache-db", str(cache_db),
                  "--format", "json", "--output", str(root / "x.json")])
            self.assertEqual(main(["cache", "clear", "--cache-db", str(cache_db)]), 0)


if __name__ == "__main__":
    unittest.main()
