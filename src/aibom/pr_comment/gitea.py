"""Gitea PR comment.

POST <base>/api/v1/repos/{owner}/{repo}/issues/{pr}/comments
Body shape: {"body": "..."}
Auth: 'token <pat>' header (Gitea convention) — Bearer also works.
"""

from __future__ import annotations

import os

from aibom.pr_comment._http import PrCommentError, Requester, post_json


def post_gitea_pr_comment(
    repo: str,
    pr_number: int,
    body: str,
    *,
    base_url: str,
    token_env: str = "GITEA_TOKEN",
    requester: Requester | None = None,
) -> dict:
    if not base_url:
        raise PrCommentError("Gitea base_url is required")
    if "/" not in repo:
        raise PrCommentError("repo must be in owner/repo form")
    token = os.environ.get(token_env)
    if not token:
        raise PrCommentError(f"missing token in env {token_env}")
    url = f"{base_url.rstrip('/')}/api/v1/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"token {token}",
        "User-Agent": "aibom-pr-comment",
    }
    return post_json(url, {"body": body}, headers=headers, requester=requester)
