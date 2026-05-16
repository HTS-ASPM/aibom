"""Bitbucket Server / Data Center PR comment.

POST <base>/rest/api/1.0/projects/{project}/repos/{repo}/pull-requests/{id}/comments
Body shape: {"text": "..."}
Auth: HTTP token (PAT) as Bearer.
"""

from __future__ import annotations

import os

from aibom.pr_comment._http import PrCommentError, Requester, post_json


def post_bitbucket_server_pr_comment(
    project: str,
    repo: str,
    pr_id: int,
    body: str,
    *,
    base_url: str,
    token_env: str = "BITBUCKET_TOKEN",
    requester: Requester | None = None,
) -> dict:
    if not base_url:
        raise PrCommentError("Bitbucket Server base_url is required")
    token = os.environ.get(token_env)
    if not token:
        raise PrCommentError(f"missing token in env {token_env}")
    url = (
        f"{base_url.rstrip('/')}/rest/api/1.0/projects/{project}/repos/{repo}/"
        f"pull-requests/{pr_id}/comments"
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "aibom-pr-comment",
    }
    return post_json(url, {"text": body}, headers=headers, requester=requester)
