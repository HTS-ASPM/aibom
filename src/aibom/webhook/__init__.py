"""Webhook receiver mode and PR-check helpers.

  receiver.py    HTTP server that auto-scans on push / pull_request /
                 merge_request events and posts the diff summary as a
                 PR/MR comment via aibom.pr_comment.
  check_run.py   POST a GitHub Check Run (annotated, with SARIF detail)
                 so AiBOM appears as a status check on the PR rather
                 than just an issue comment.
  signatures.py  HMAC verification — GitHub (sha256), GitLab (token
                 header), Bitbucket Server (none — IP allowlist only),
                 Gitea (sha256 like GitHub).
"""

from aibom.webhook.check_run import build_check_run_body, post_check_run
from aibom.webhook.receiver import (
    WebhookConfig,
    WebhookHandler,
    create_server,
)
from aibom.webhook.signatures import (
    verify_github_signature,
    verify_gitea_signature,
    verify_gitlab_token,
)

__all__ = [
    "WebhookConfig",
    "WebhookHandler",
    "build_check_run_body",
    "create_server",
    "post_check_run",
    "verify_gitea_signature",
    "verify_github_signature",
    "verify_gitlab_token",
]
