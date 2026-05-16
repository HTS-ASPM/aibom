"""GitLab MR comment connector — POST to /api/v4/projects/{project}/merge_requests/{mr}/notes."""

from __future__ import annotations

import os
from urllib.parse import quote

from aibom.pr_comment._http import PrCommentError, Requester, post_json


def post_gitlab_mr_comment(
    project: str,
    mr_iid: int,
    body: str,
    *,
    token_env: str = "GITLAB_TOKEN",
    base_url: str = "https://gitlab.com",
    requester: Requester | None = None,
) -> dict:
    token = os.environ.get(token_env)
    if not token:
        raise PrCommentError(f"missing token in env {token_env}")
    project_part = project if project.isdigit() else quote(project, safe="")
    url = f"{base_url.rstrip('/')}/api/v4/projects/{project_part}/merge_requests/{mr_iid}/notes"
    headers = {
        "Content-Type": "application/json",
        "PRIVATE-TOKEN": token,
        "User-Agent": "aibom-pr-comment",
    }
    return post_json(url, {"body": body}, headers=headers, requester=requester)
