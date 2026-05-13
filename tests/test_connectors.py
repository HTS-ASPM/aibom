from __future__ import annotations

import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from aibom.connectors import build_github_headers, parse_github_repo_ref, scan_github_repo


FIXTURES = Path(__file__).parent / "fixtures"


class ConnectorTestCase(unittest.TestCase):
    def test_parse_github_repo_ref(self) -> None:
        repo = parse_github_repo_ref("openai/openai-python", "main")
        self.assertEqual(repo.owner, "openai")
        self.assertEqual(repo.repo, "openai-python")
        self.assertEqual(repo.ref, "main")

    def test_build_github_headers_includes_token_when_present(self) -> None:
        headers = build_github_headers("abc123")
        self.assertEqual(headers["Authorization"], "Bearer abc123")

    def test_scan_github_repo_with_injected_archive_fetcher(self) -> None:
        def fake_fetcher(repo_ref, destination: Path, token: str | None) -> None:
            self.assertEqual(repo_ref.slug, "acme/sample")
            self.assertEqual(repo_ref.ref, "main")
            self.assertIsNone(token)
            with TemporaryDirectory(prefix="aibom-fixture-") as source_dir:
                source_root = Path(source_dir) / "sample-main"
                shutil.copytree(FIXTURES / "python_app", source_root)
                with zipfile.ZipFile(destination, "w") as archive:
                    for path in source_root.rglob("*"):
                        archive.write(path, path.relative_to(Path(source_dir)))

        result = scan_github_repo("acme/sample", archive_fetcher=fake_fetcher, tuning={"suppress_rule_ids": ["package.ai_sdk.pattern"]})
        categories = {(finding.category, finding.name) for finding in result.findings}
        self.assertTrue(result.root.startswith("github://acme/sample@main"))
        self.assertIn(("provider", "OpenAI usage"), categories)
        self.assertNotIn(("package", "AI SDK or package reference"), categories)


if __name__ == "__main__":
    unittest.main()
