"""Additional code-host connectors and GitHub App auth helpers.

GitLab and Bitbucket Cloud / Server connectors mirror the existing
GitHub one in aibom.connectors: download the repo archive, extract
locally, run scan_path, label the result with a host:// scheme.

GitHub App support is **bring-your-own-token**: AiBOM does not depend
on the `cryptography` package required for RS256 JWT signing. Instead:

  1. Caller produces a JWT for the GitHub App (e.g. via a 5-line gh
     wrapper, the upstream `pyjwt[crypto]` library, or the `gh` CLI).
  2. Caller exchanges JWT -> installation access token via
     POST /app/installations/<id>/access_tokens.
  3. Caller exports the resulting `ghs_*` token to GITHUB_APP_INSTALLATION_TOKEN
     and runs `aibom scan-github` with `--github-token-env GITHUB_APP_INSTALLATION_TOKEN`.

This keeps AiBOM dep-free while still working with org-wide GitHub App
installs.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError, URLError

from aibom.scanner import scan_path
from aibom.models import ScanResult


# --------------------------------------------------------------------------- #
# GitHub App auth — informational helper (no JWT signing inside AiBOM)
# --------------------------------------------------------------------------- #

def github_app_installation_token_from_env() -> str | None:
    """Return the installation token if the user has pre-exchanged it."""
    return os.environ.get("GITHUB_APP_INSTALLATION_TOKEN")


def describe_github_app_token_handoff(app_id: str | None = None, installation_id: str | None = None) -> dict:
    """Document the recommended pre-exchange flow for the user / runbook."""
    return {
        "step_1_jwt": (
            "Mint an RS256 JWT for the GitHub App "
            "(use pyjwt[crypto], gh-cli, or any RS256 signer)."
        ),
        "step_2_token_exchange": (
            "POST https://api.github.com/app/installations/"
            f"{installation_id or '<INSTALLATION_ID>'}/access_tokens "
            "with Authorization: Bearer <JWT>"
        ),
        "step_3_export": (
            "export GITHUB_APP_INSTALLATION_TOKEN=<ghs_...>"
        ),
        "step_4_scan": (
            "aibom scan-github <owner>/<repo> "
            "--github-token-env GITHUB_APP_INSTALLATION_TOKEN"
        ),
        "app_id": app_id,
        "installation_id": installation_id,
    }


# --------------------------------------------------------------------------- #
# GitLab
# --------------------------------------------------------------------------- #

@dataclass(slots=True)
class GitLabRepoRef:
    project: str   # numeric id OR url-encoded full path (e.g. group%2Fsubgroup%2Fproject)
    ref: str
    base_url: str = "https://gitlab.com"


def parse_gitlab_ref(project: str, ref: str, *, base_url: str = "https://gitlab.com") -> GitLabRepoRef:
    if not project.strip():
        raise ValueError("GitLab project must be the numeric id or URL-encoded path")
    return GitLabRepoRef(project=project, ref=ref, base_url=base_url.rstrip("/"))


def scan_gitlab_repo(
    project: str,
    ref: str = "main",
    token: str | None = None,
    *,
    base_url: str = "https://gitlab.com",
    max_file_size: int = 512_000,
    exclude_patterns: list[str] | None = None,
    policy: dict | None = None,
    tuning: dict | None = None,
    archive_fetcher=None,
) -> ScanResult:
    repo_ref = parse_gitlab_ref(project, ref, base_url=base_url)
    fetcher = archive_fetcher or fetch_gitlab_archive
    with TemporaryDirectory(prefix="aibom-gitlab-") as temp_dir:
        temp = Path(temp_dir)
        archive_path = temp / "archive.tar.gz"
        fetcher(repo_ref, archive_path, token)
        extracted = _extract_tar_gz(archive_path, temp / "repo")
        result = scan_path(
            extracted,
            max_file_size=max_file_size,
            exclude_patterns=exclude_patterns,
            policy=policy,
            tuning=tuning,
        )
        result.root = f"gitlab://{repo_ref.project}@{repo_ref.ref}"
        return result


def fetch_gitlab_archive(repo_ref: GitLabRepoRef, destination: Path, token: str | None) -> None:
    from urllib.request import Request, urlopen
    url = f"{repo_ref.base_url}/api/v4/projects/{repo_ref.project}/repository/archive.tar.gz?sha={repo_ref.ref}"
    headers = {"User-Agent": "aibom-scanner"}
    if token:
        headers["PRIVATE-TOKEN"] = token
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=60) as resp, destination.open("wb") as fh:  # noqa: S310
            shutil.copyfileobj(resp, fh)
    except HTTPError as exc:
        raise RuntimeError(f"GitLab archive fetch failed: {exc.code} {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"GitLab archive fetch failed: {exc.reason}") from exc


# --------------------------------------------------------------------------- #
# Bitbucket
# --------------------------------------------------------------------------- #

@dataclass(slots=True)
class BitbucketRepoRef:
    workspace: str
    repo: str
    ref: str
    base_url: str = "https://api.bitbucket.org"

    @property
    def slug(self) -> str:
        return f"{self.workspace}/{self.repo}"


def parse_bitbucket_ref(repo: str, ref: str, *, base_url: str = "https://api.bitbucket.org") -> BitbucketRepoRef:
    parts = repo.strip().split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("Bitbucket repo must be in the form workspace/repo")
    return BitbucketRepoRef(workspace=parts[0], repo=parts[1], ref=ref, base_url=base_url.rstrip("/"))


def scan_bitbucket_repo(
    repo: str,
    ref: str = "main",
    token: str | None = None,
    *,
    base_url: str = "https://api.bitbucket.org",
    max_file_size: int = 512_000,
    exclude_patterns: list[str] | None = None,
    policy: dict | None = None,
    tuning: dict | None = None,
    archive_fetcher=None,
) -> ScanResult:
    repo_ref = parse_bitbucket_ref(repo, ref, base_url=base_url)
    fetcher = archive_fetcher or fetch_bitbucket_archive
    with TemporaryDirectory(prefix="aibom-bitbucket-") as temp_dir:
        temp = Path(temp_dir)
        archive_path = temp / "archive.zip"
        fetcher(repo_ref, archive_path, token)
        extracted = _extract_zip_first_dir(archive_path, temp / "repo")
        result = scan_path(
            extracted,
            max_file_size=max_file_size,
            exclude_patterns=exclude_patterns,
            policy=policy,
            tuning=tuning,
        )
        result.root = f"bitbucket://{repo_ref.slug}@{repo_ref.ref}"
        return result


def fetch_bitbucket_archive(repo_ref: BitbucketRepoRef, destination: Path, token: str | None) -> None:
    from urllib.request import Request, urlopen
    url = (
        f"{repo_ref.base_url}/2.0/repositories/{repo_ref.workspace}/{repo_ref.repo}/"
        f"src/{repo_ref.ref}/?format=zip"
    )
    headers = {"User-Agent": "aibom-scanner"}
    if token:
        # Bitbucket app passwords / repo access tokens use Bearer too.
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=60) as resp, destination.open("wb") as fh:  # noqa: S310
            shutil.copyfileobj(resp, fh)
    except HTTPError as exc:
        raise RuntimeError(f"Bitbucket archive fetch failed: {exc.code} {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"Bitbucket archive fetch failed: {exc.reason}") from exc


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _extract_tar_gz(archive_path: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extractall(destination_dir)  # noqa: S202 — same trust model as GitHub fetcher
    children = [p for p in destination_dir.iterdir() if p.is_dir()]
    if not children:
        # Some hosts emit a flat archive with files at the root.
        return destination_dir
    return children[0]


def _extract_zip_first_dir(archive_path: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(destination_dir)
    children = [p for p in destination_dir.iterdir() if p.is_dir()]
    if not children:
        return destination_dir
    return children[0]
