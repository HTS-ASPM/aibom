"""PR / MR comment connectors — GitHub, GitLab, Bitbucket Server, Gitea.

Each connector posts a markdown comment summarising the AiBOM scan
result (typically the output of a git-diff scoped scan). Auth tokens
are read from env vars per provider; the connectors share a single
markdown formatter so the comment shape stays consistent across hosts.
"""

from aibom.pr_comment.bitbucket_server import post_bitbucket_server_pr_comment
from aibom.pr_comment.format import format_aibom_comment, format_diff_comment
from aibom.pr_comment.gitea import post_gitea_pr_comment
from aibom.pr_comment.github import post_github_pr_comment
from aibom.pr_comment.gitlab import post_gitlab_mr_comment

__all__ = [
    "format_aibom_comment",
    "format_diff_comment",
    "post_bitbucket_server_pr_comment",
    "post_gitea_pr_comment",
    "post_github_pr_comment",
    "post_gitlab_mr_comment",
]
