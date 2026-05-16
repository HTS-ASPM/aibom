"""GitHub PR comment connector — POST to /repos/{owner}/{repo}/issues/{pr}/comments."""

from __future__ import annotations

import os

from aibom.pr_comment._http import PrCommentError, Requester, post_json


def post_github_pr_comment(
    repo: str,
    pr_number: int,
    body: str,
    *,
    token_env: str = "GITHUB_TOKEN",
    api_base: str = "https://api.github.com",
    requester: Requester | None = None,
) -> dict:
    token = os.environ.get(token_env)
    if not token:
        raise PrCommentError(f"missing token in env {token_env}")
    if "/" not in repo:
        raise PrCommentError("repo must be in owner/repo form")
    url = f"{api_base.rstrip('/')}/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "aibom-pr-comment",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return post_json(url, {"body": body}, headers=headers, requester=requester)
