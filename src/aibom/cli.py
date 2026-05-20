from __future__ import annotations

import argparse
from importlib import resources
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from aibom.asset_graph import (
    build_asset_graph,
    diff_asset_graphs,
    render_asset_graph_diff_json,
    render_asset_graph_json,
)
from aibom.compliance import (
    generate_annex_iv_html,
    generate_iso_42001_html,
    generate_nist_rmf_html,
)
from aibom.connectors import scan_aws_account, scan_azure_subscription, scan_gcp_project, scan_github_repo, scan_huggingface_model
from aibom.cyclonedx import build_bom
from aibom.dashboard import generate_executive_dashboard_html
from aibom.cache import (
    clear_all as cache_clear_all,
    default_cache_path,
    open_cache,
    prune_other_versions as cache_prune_other_versions,
    stats_for_version as cache_stats_for_version,
)
from aibom.code_hosts import scan_bitbucket_repo, scan_gitlab_repo
from aibom.diff import diff_scans as diff_scan_results, render_diff_html, render_diff_json
from aibom.git_diff import GitNotAvailableError, scan_diff as scan_git_diff
from aibom.hts_aspm import build_aspm_payload, push_aspm_payload
from aibom.models import ScanResult
from aibom.pr_comment import (
    format_aibom_comment,
    format_diff_comment,
    post_bitbucket_server_pr_comment,
    post_gitea_pr_comment,
    post_github_pr_comment,
    post_gitlab_mr_comment,
)
from aibom.policy import load_policy_file
from aibom.reporters import render_cyclonedx, render_json, render_markdown, render_pretty_json, render_sarif
from aibom.sbom_unified import merge_sbom_aibom
from aibom.scanner import scan_path
from aibom.signing import build_signature_manifest
from aibom.store import diff_scans, get_scan, list_scans, save_scan
from aibom.tuning import load_tuning_file
from aibom.webhook import (
    WebhookConfig,
    build_check_run_body,
    create_server,
    post_check_run,
)
from aibom.runtime import load_otel_spans, reconcile_runtime_with_bom
from aibom.serve import ServeConfig, create_server as create_dashboard_server
from aibom.vex import (
    KevRefreshError,
    cross_reference,
    cross_reference_kev,
    load_feed,
    load_kev_feed,
    merge_vex_into_bom,
    refresh_kev_feed,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aibom", description="Scan a repository for AI usage artifacts.")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a local path")
    add_common_arguments(scan_parser)
    scan_parser.add_argument("target", nargs="?", default=".", help="Path to scan")

    github_parser = subparsers.add_parser("scan-github", help="Scan a GitHub repository archive")
    add_common_arguments(github_parser)
    github_parser.add_argument("repo", help="GitHub repository in owner/repo form")
    github_parser.add_argument("--ref", default="main", help="Git ref, branch, or tag to scan")
    github_parser.add_argument(
        "--github-token-env",
        default="GITHUB_TOKEN",
        help=(
            "Environment variable containing a GitHub token (PAT or GitHub App "
            "installation token, e.g. GITHUB_APP_INSTALLATION_TOKEN)"
        ),
    )

    gitlab_parser = subparsers.add_parser("scan-gitlab", help="Scan a GitLab repository archive")
    add_common_arguments(gitlab_parser)
    gitlab_parser.add_argument(
        "project",
        help="GitLab project — numeric id OR url-encoded full path (group%%2Fproject)",
    )
    gitlab_parser.add_argument("--ref", default="main", help="Git ref, branch, or tag")
    gitlab_parser.add_argument("--gitlab-base-url", default="https://gitlab.com", help="Self-hosted GitLab base URL")
    gitlab_parser.add_argument(
        "--gitlab-token-env",
        default="GITLAB_TOKEN",
        help="Env var containing a GitLab personal / project access token",
    )

    bitbucket_parser = subparsers.add_parser("scan-bitbucket", help="Scan a Bitbucket Cloud repository archive")
    add_common_arguments(bitbucket_parser)
    bitbucket_parser.add_argument("repo", help="Bitbucket repo in workspace/repo form")
    bitbucket_parser.add_argument("--ref", default="main", help="Git ref, branch, or tag")
    bitbucket_parser.add_argument(
        "--bitbucket-base-url",
        default="https://api.bitbucket.org",
        help="Bitbucket Server / Data Center base URL (defaults to Cloud)",
    )
    bitbucket_parser.add_argument(
        "--bitbucket-token-env",
        default="BITBUCKET_TOKEN",
        help="Env var containing a Bitbucket access token / app password",
    )

    hf_parser = subparsers.add_parser("scan-huggingface", help="Scan a Hugging Face model metadata record")
    add_common_arguments(hf_parser)
    hf_parser.add_argument("model_id", help="Hugging Face model id, for example org/model")
    hf_parser.add_argument(
        "--huggingface-token-env",
        default="HUGGINGFACE_TOKEN",
        help="Environment variable containing a Hugging Face token",
    )

    aws_parser = subparsers.add_parser("scan-aws", help="Scan AWS metadata for AI-related inventory")
    add_common_arguments(aws_parser)
    aws_parser.add_argument("account_label", help="Friendly label for the AWS account or environment")
    aws_parser.add_argument("--region", default="us-east-1", help="AWS region to inspect")
    aws_parser.add_argument("--aws-profile", help="Optional AWS profile name to use with boto3")

    azure_parser = subparsers.add_parser("scan-azure", help="Scan Azure metadata for AI-related inventory")
    add_common_arguments(azure_parser)
    azure_parser.add_argument("subscription_label", help="Friendly label for the Azure subscription or environment")
    azure_parser.add_argument("--subscription-id", required=True, help="Azure subscription id to inspect")

    gcp_parser = subparsers.add_parser("scan-gcp", help="Scan GCP metadata for AI-related inventory")
    add_common_arguments(gcp_parser)
    gcp_parser.add_argument("project_label", help="Friendly label for the GCP project or environment")
    gcp_parser.add_argument("--project-id", required=True, help="GCP project id to inspect")

    history_parser = subparsers.add_parser("history", help="List saved scan history")
    history_parser.add_argument("--db", help="Path to the scan history database")
    history_parser.add_argument("--limit", type=int, default=20, help="Maximum number of scans to return")

    show_parser = subparsers.add_parser("show-scan", help="Show a saved scan result")
    show_parser.add_argument("scan_id", help="Saved scan id")
    show_parser.add_argument("--db", help="Path to the scan history database")
    show_parser.add_argument(
        "--format",
        choices=("json", "markdown", "sarif", "cyclonedx"),
        default="json",
        help="Output format",
    )

    diff_parser = subparsers.add_parser("diff-scans", help="Diff two saved scans")
    diff_parser.add_argument("left_scan_id", help="Older or baseline scan id")
    diff_parser.add_argument("right_scan_id", help="Newer scan id")
    diff_parser.add_argument("--db", help="Path to the scan history database")

    vex_parser = subparsers.add_parser(
        "vex", help="Cross-reference a CycloneDX BOM against the AiBOM VEX feed",
    )
    vex_parser.add_argument("bom_path", help="Path to a CycloneDX 1.6 JSON BOM")
    vex_parser.add_argument("--feed", help="Override default VEX feed JSON path")
    vex_parser.add_argument("--output", help="Write augmented BOM to this path (default: stdout)")
    vex_parser.add_argument(
        "--no-merge",
        action="store_true",
        help="Print only the VEX vulnerability entries (don't merge into the BOM)",
    )

    kev_parser = subparsers.add_parser(
        "kev", help="Cross-reference a CycloneDX BOM's vulnerabilities against CISA KEV",
    )
    kev_parser.add_argument("bom_path", help="Path to a CycloneDX 1.6 JSON BOM")
    kev_parser.add_argument("--kev-feed", help="Path to cached CISA KEV JSON (or set AIBOM_KEV_FEED)")
    kev_parser.add_argument("--output", help="Write augmented BOM to this path (default: stdout)")
    kev_parser.add_argument(
        "--report-only",
        action="store_true",
        help="Print the list of KEV matches as JSON instead of the augmented BOM",
    )

    sign_parser = subparsers.add_parser(
        "sign-bom", help="Build a Sigstore-friendly signing manifest for a BOM file",
    )
    sign_parser.add_argument("bom_path", help="Path to the BOM file to sign")
    sign_parser.add_argument(
        "--signer",
        default="ci@hts.consulting",
        help="Identity that will perform the signature (informational)",
    )
    sign_parser.add_argument("--key-ref", help="cosign key reference (env://, k8s://, file path)")
    sign_parser.add_argument(
        "--rekor-url",
        default="https://rekor.sigstore.dev",
        help="Rekor transparency log URL (informational)",
    )
    sign_parser.add_argument("--output", help="Write manifest JSON to this path (default: stdout)")

    report_parser = subparsers.add_parser(
        "report", help="Render a compliance HTML report for a scan target",
    )
    report_parser.add_argument(
        "--type",
        choices=("annex-iv", "nist-rmf", "iso-42001"),
        required=True,
        help="Compliance framework",
    )
    report_parser.add_argument("target", nargs="?", default=".", help="Path to scan (default: cwd)")
    report_parser.add_argument("--output", help="Write HTML to this path (default: stdout)")
    report_parser.add_argument("--policy", help="Optional policy file")
    report_parser.add_argument("--tuning", help="Optional tuning file")

    dash_parser = subparsers.add_parser(
        "dashboard", help="Render the AiBOM executive dashboard HTML for a scan target",
    )
    dash_parser.add_argument("target", nargs="?", default=".", help="Path to scan (default: cwd)")
    dash_parser.add_argument("--output", required=True, help="Write HTML to this path")
    dash_parser.add_argument("--policy", help="Optional policy file")
    dash_parser.add_argument("--tuning", help="Optional tuning file")

    unified_parser = subparsers.add_parser(
        "unified-bom",
        help="Merge a CycloneDX SBOM (HTS-ASPM SBOM module / Trivy / Syft / cdxgen) with the AiBOM",
    )
    unified_parser.add_argument("sbom_path", help="Path to a CycloneDX 1.6 JSON SBOM")
    unified_parser.add_argument("target", nargs="?", default=".", help="Path to scan with AiBOM (default: cwd)")
    unified_parser.add_argument("--output", help="Write merged BOM to this path (default: stdout)")
    unified_parser.add_argument("--policy", help="Optional policy file")
    unified_parser.add_argument("--tuning", help="Optional tuning file")

    asset_parser = subparsers.add_parser(
        "asset-graph", help="Emit the AiBOM asset graph as JSON",
    )
    asset_parser.add_argument("target", nargs="?", default=".", help="Path to scan (default: cwd)")
    asset_parser.add_argument("--output", help="Write JSON to this path (default: stdout)")
    asset_parser.add_argument(
        "--no-findings",
        action="store_true",
        help="Skip the per-finding nodes (smaller graph for dashboard rendering)",
    )

    asset_diff_parser = subparsers.add_parser(
        "asset-graph-diff", help="Diff two asset-graph JSON files",
    )
    asset_diff_parser.add_argument("older_path", help="Path to the older asset-graph JSON")
    asset_diff_parser.add_argument("newer_path", help="Path to the newer asset-graph JSON")
    asset_diff_parser.add_argument("--output", help="Write diff JSON to this path (default: stdout)")

    scan_diff_parser = subparsers.add_parser(
        "scan-diff",
        help="Diff two raw AiBOM scan JSON files (richer than `diff-scans`, no DB required)",
    )
    scan_diff_parser.add_argument("older_path", help="Path to the older scan JSON")
    scan_diff_parser.add_argument("newer_path", help="Path to the newer scan JSON")
    scan_diff_parser.add_argument(
        "--format",
        choices=("json", "html"),
        default="json",
        help="Output format",
    )
    scan_diff_parser.add_argument("--output", help="Write diff to this path (default: stdout)")
    scan_diff_parser.add_argument("--older-label", default="older", help="Label for the older scan in HTML")
    scan_diff_parser.add_argument("--newer-label", default="newer", help="Label for the newer scan in HTML")

    scan_refs_parser = subparsers.add_parser(
        "scan-refs",
        help="Scan only files changed between two git refs (base..head)",
    )
    scan_refs_parser.add_argument("base", help="Base git ref (e.g. main)")
    scan_refs_parser.add_argument("head", nargs="?", default="HEAD", help="Head git ref (default: HEAD)")
    scan_refs_parser.add_argument("--repo", default=".", help="Path to the local git repo (default: cwd)")
    scan_refs_parser.add_argument(
        "--format",
        choices=("json", "markdown", "sarif", "cyclonedx"),
        default="json",
        help="Output format",
    )
    scan_refs_parser.add_argument("--output", help="Optional output file path")
    scan_refs_parser.add_argument("--policy", help="Optional policy file")
    scan_refs_parser.add_argument("--tuning", help="Optional tuning file")
    scan_refs_parser.add_argument(
        "--max-file-size",
        type=int,
        default=512_000,
        help="Maximum file size to scan in bytes",
    )

    pr_comment_parser = subparsers.add_parser(
        "pr-comment",
        help="Post an AiBOM scan or diff summary as a PR/MR comment",
    )
    pr_sub = pr_comment_parser.add_subparsers(dest="pr_provider", required=True)

    def _pr_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--scan", help="Path to an aibom scan JSON to summarize (alternative to --diff)")
        p.add_argument("--diff", help="Path to an aibom scan-diff JSON to summarize")
        p.add_argument("--title", default="AiBOM scan", help="Comment title")

    pr_github = pr_sub.add_parser("github", help="Post to a GitHub PR")
    pr_github.add_argument("repo", help="owner/repo")
    pr_github.add_argument("pr_number", type=int)
    pr_github.add_argument("--token-env", default="GITHUB_TOKEN")
    pr_github.add_argument("--api-base", default="https://api.github.com")
    _pr_common(pr_github)

    pr_gitlab = pr_sub.add_parser("gitlab", help="Post to a GitLab MR")
    pr_gitlab.add_argument("project", help="numeric id OR url-encoded full path")
    pr_gitlab.add_argument("mr_iid", type=int)
    pr_gitlab.add_argument("--token-env", default="GITLAB_TOKEN")
    pr_gitlab.add_argument("--base-url", default="https://gitlab.com")
    _pr_common(pr_gitlab)

    pr_bbs = pr_sub.add_parser("bitbucket-server", help="Post to a Bitbucket Server / DC pull request")
    pr_bbs.add_argument("project")
    pr_bbs.add_argument("repo")
    pr_bbs.add_argument("pr_id", type=int)
    pr_bbs.add_argument("--base-url", required=True)
    pr_bbs.add_argument("--token-env", default="BITBUCKET_TOKEN")
    _pr_common(pr_bbs)

    pr_gitea = pr_sub.add_parser("gitea", help="Post to a Gitea PR")
    pr_gitea.add_argument("repo", help="owner/repo")
    pr_gitea.add_argument("pr_number", type=int)
    pr_gitea.add_argument("--base-url", required=True)
    pr_gitea.add_argument("--token-env", default="GITEA_TOKEN")
    _pr_common(pr_gitea)

    webhook_parser = subparsers.add_parser(
        "webhook",
        help="Run a stdlib HTTP webhook receiver — auto-scan on push / PR / MR events",
    )
    webhook_parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    webhook_parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    webhook_parser.add_argument("--github-secret-env", help="Env var holding the GitHub webhook secret")
    webhook_parser.add_argument("--gitlab-token-env", help="Env var holding the GitLab webhook token")
    webhook_parser.add_argument("--gitea-secret-env", help="Env var holding the Gitea webhook secret")

    check_run_parser = subparsers.add_parser(
        "check-run",
        help="POST a GitHub Check Run from an existing aibom scan JSON",
    )
    check_run_parser.add_argument("repo", help="owner/repo")
    check_run_parser.add_argument("head_sha", help="Commit SHA the check ties to (head of the PR)")
    check_run_parser.add_argument("--scan", required=True, help="Path to an aibom scan JSON file")
    check_run_parser.add_argument("--name", default="aibom", help="Check Run name")
    check_run_parser.add_argument("--details-url", help="External URL with full results")
    check_run_parser.add_argument("--token-env", default="GITHUB_TOKEN")
    check_run_parser.add_argument("--api-base", default="https://api.github.com")

    demo_parser = subparsers.add_parser(
        "demo",
        help="Scan a built-in tiny fixture — covers provider / IaC / CI / dataset / MLflow layers",
    )
    demo_parser.add_argument(
        "--format",
        choices=("json", "markdown", "cyclonedx"),
        default="json",
        help="Output format (default: json)",
    )
    demo_parser.add_argument("--output", help="Optional output file path")

    push_parser = subparsers.add_parser(
        "push",
        help="Scan a target then POST the HTS-ASPM envelope to an ingest endpoint",
    )
    push_parser.add_argument("target", nargs="?", default=".", help="Path to scan (default: cwd)")
    push_parser.add_argument("--aspm-url", required=True, help="HTS-ASPM ingest URL")
    push_parser.add_argument("--project", help="Optional project identifier (sent as X-Aibom-Project)")
    push_parser.add_argument(
        "--token-env",
        default="ASPM_TOKEN",
        help="Env var containing the bearer token (default: ASPM_TOKEN)",
    )
    push_parser.add_argument("--kev-feed", help="Path to cached CISA KEV JSON")
    push_parser.add_argument("--no-vex", action="store_true", help="Skip VEX cross-reference")
    push_parser.add_argument("--no-kev", action="store_true", help="Skip KEV cross-reference")
    push_parser.add_argument("--signer", help="Include a signature_manifest with this signer identity")
    push_parser.add_argument("--key-ref", help="cosign key reference for the signature manifest")
    push_parser.add_argument("--policy", help="Optional policy file")
    push_parser.add_argument("--tuning", help="Optional tuning file")
    push_parser.add_argument(
        "--max-file-size",
        type=int,
        default=512_000,
        help="Maximum file size to scan in bytes",
    )

    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the stdlib HTTP dashboard server (dashboard / BOM / asset-graph / reports)",
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8088, help="Bind port (default: 8088)")
    serve_parser.add_argument(
        "--allowed-root",
        help="Path-traversal sandbox — `target` query-string values must resolve under this dir (default: cwd)",
    )

    kev_refresh_parser = subparsers.add_parser(
        "kev-refresh",
        help="Fetch the CISA KEV catalog to a local cache (atomic write)",
    )
    kev_refresh_parser.add_argument(
        "--destination",
        help="Cache file path (default: ~/.aibom/kev.json)",
    )
    kev_refresh_parser.add_argument(
        "--source-url",
        help="Override the CISA feed URL (e.g. for air-gapped mirrors)",
    )
    kev_refresh_parser.add_argument(
        "--no-network",
        action="store_true",
        help="Fail instead of touching the network unless a custom --source-url is local",
    )

    reconcile_parser = subparsers.add_parser(
        "reconcile",
        help="Reconcile an OTel-GenAI trace dump with a CycloneDX BOM (shadow AI + dead inventory)",
    )
    reconcile_parser.add_argument("bom_path", help="Path to a CycloneDX 1.6 JSON BOM")
    reconcile_parser.add_argument("traces_path", help="Path to an OTel-GenAI spans JSON file")
    reconcile_parser.add_argument("--output", help="Write reconciliation JSON to this path (default: stdout)")

    cache_parser = subparsers.add_parser(
        "cache",
        help="Manage the per-file fingerprint cache used by --use-cache scans",
    )
    cache_sub = cache_parser.add_subparsers(dest="cache_action", required=True)
    for action_name, action_help in (
        ("stats", "Show row count + age range for the current scanner version"),
        ("clear", "Delete every cached entry"),
        ("prune", "Drop cached entries from older scanner versions"),
    ):
        sub = cache_sub.add_parser(action_name, help=action_help)
        sub.add_argument(
            "--cache-db",
            help=f"SQLite cache file (default: {default_cache_path()})",
        )

    return parser


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "sarif", "cyclonedx"),
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--output",
        help="Optional output file path",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=512_000,
        help="Maximum file size to scan in bytes",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern to exclude. Can be used multiple times.",
    )
    parser.add_argument(
        "--policy",
        help="Optional TOML or JSON policy file for approved providers/models and severity overrides",
    )
    parser.add_argument(
        "--tuning",
        help="Optional TOML or JSON tuning file for suppressions, rule overrides, and baseline-ignore settings",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Persist this scan result to the local history database",
    )
    parser.add_argument(
        "--db",
        help="Path to the scan history database",
    )
    parser.add_argument(
        "--use-cache",
        action="store_true",
        help="Look up per-file findings by content fingerprint to skip unchanged files",
    )
    parser.add_argument(
        "--cache-db",
        help=f"SQLite cache file (default: {default_cache_path()})",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    known_commands = {
        "scan", "scan-github", "scan-gitlab", "scan-bitbucket",
        "scan-huggingface", "scan-aws", "scan-azure", "scan-gcp",
        "history", "show-scan", "diff-scans", "vex", "kev", "sign-bom",
        "report", "dashboard", "unified-bom",
        "asset-graph", "asset-graph-diff", "scan-diff",
        "scan-refs", "pr-comment",
        "webhook", "check-run",
        "cache", "demo", "push",
        "serve", "kev-refresh", "reconcile",
        "-h", "--help",
    }
    if not argv or argv[0] not in known_commands:
        argv = ["scan", *argv]
    args = parser.parse_args(argv)

    if args.command == "history":
        print(render_pretty_json(list_scans(db_path=args.db, limit=args.limit)))
        return 0

    if args.command == "show-scan":
        stored = get_scan(args.scan_id, db_path=args.db)
        output = render_scan_result(stored.result, args.format)
        print(output)
        return 0

    if args.command == "diff-scans":
        print(render_pretty_json(diff_scans(args.left_scan_id, args.right_scan_id, db_path=args.db)))
        return 0

    if args.command == "vex":
        return _run_vex_command(args)

    if args.command == "kev":
        return _run_kev_command(args)

    if args.command == "sign-bom":
        return _run_sign_bom_command(args)

    if args.command == "report":
        return _run_report_command(args)

    if args.command == "dashboard":
        return _run_dashboard_command(args)

    if args.command == "unified-bom":
        return _run_unified_bom_command(args)

    if args.command == "asset-graph":
        return _run_asset_graph_command(args)

    if args.command == "asset-graph-diff":
        return _run_asset_graph_diff_command(args)

    if args.command == "scan-diff":
        return _run_scan_diff_command(args)

    if args.command == "cache":
        return _run_cache_command(args)

    if args.command == "demo":
        return _run_demo_command(args)

    if args.command == "scan-refs":
        return _run_scan_refs_command(args)

    if args.command == "pr-comment":
        return _run_pr_comment_command(args)

    if args.command == "webhook":
        return _run_webhook_command(args)

    if args.command == "check-run":
        return _run_check_run_command(args)

    if args.command == "push":
        return _run_push_command(args)

    if args.command == "serve":
        return _run_serve_command(args)

    if args.command == "kev-refresh":
        return _run_kev_refresh_command(args)

    if args.command == "reconcile":
        return _run_reconcile_command(args)

    policy = load_policy_file(args.policy)
    tuning = load_tuning_file(args.tuning)
    cache_conn = None
    if getattr(args, "use_cache", False):
        cache_path = Path(args.cache_db) if args.cache_db else None
        cache_conn = open_cache(cache_path)

    if args.command == "scan-github":
        token = os.environ.get(args.github_token_env)
        result = scan_github_repo(
            args.repo,
            ref=args.ref,
            token=token,
            max_file_size=args.max_file_size,
            exclude_patterns=args.exclude,
            policy=policy,
            tuning=tuning,
        )
    elif args.command == "scan-gitlab":
        token = os.environ.get(args.gitlab_token_env)
        result = scan_gitlab_repo(
            args.project,
            ref=args.ref,
            token=token,
            base_url=args.gitlab_base_url,
            max_file_size=args.max_file_size,
            exclude_patterns=args.exclude,
            policy=policy,
            tuning=tuning,
        )
    elif args.command == "scan-bitbucket":
        token = os.environ.get(args.bitbucket_token_env)
        result = scan_bitbucket_repo(
            args.repo,
            ref=args.ref,
            token=token,
            base_url=args.bitbucket_base_url,
            max_file_size=args.max_file_size,
            exclude_patterns=args.exclude,
            policy=policy,
            tuning=tuning,
        )
    elif args.command == "scan-huggingface":
        token = os.environ.get(args.huggingface_token_env)
        result = scan_huggingface_model(
            args.model_id,
            token=token,
            policy=policy,
        )
    elif args.command == "scan-aws":
        result = scan_aws_account(
            args.account_label,
            region=args.region,
            profile=args.aws_profile,
            policy=policy,
        )
    elif args.command == "scan-azure":
        result = scan_azure_subscription(
            args.subscription_label,
            subscription_id=args.subscription_id,
            policy=policy,
        )
    elif args.command == "scan-gcp":
        result = scan_gcp_project(
            args.project_label,
            project_id=args.project_id,
            policy=policy,
        )
    else:
        target = Path(args.target).resolve()
        result = scan_path(
            target,
            max_file_size=args.max_file_size,
            exclude_patterns=args.exclude,
            policy=policy,
            tuning=tuning,
            cache_conn=cache_conn,
        )

    output = render_scan_result(result, args.format)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.save:
        scan_id = save_scan(result, command=" ".join(argv), output_format=args.format, db_path=args.db)
        print(render_pretty_json({"saved_scan_id": scan_id, "db": str(args.db or "")}), file=sys.stderr)
    return 0


def render_scan_result(result, output_format: str) -> str:
    if output_format == "markdown":
        return render_markdown(result)
    if output_format == "sarif":
        return render_sarif(result)
    if output_format == "cyclonedx":
        return render_cyclonedx(result)
    return render_json(result)


# --------------------------------------------------------------------------- #
# vex / kev / sign-bom command handlers (P7 + P8)
# --------------------------------------------------------------------------- #

def _run_vex_command(args: argparse.Namespace) -> int:
    bom = _read_bom(args.bom_path)
    feed = load_feed(Path(args.feed) if args.feed else None)
    if args.no_merge:
        from aibom.vex import emit_vex_for_bom
        payload = {"vulnerabilities": emit_vex_for_bom(bom, feed=feed)}
    else:
        payload = merge_vex_into_bom(bom, feed=feed)
    output = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    findings = cross_reference(bom, feed=feed)
    print(render_pretty_json({"vex_matches": len(findings)}), file=sys.stderr)
    return 0


def _run_kev_command(args: argparse.Namespace) -> int:
    bom = _read_bom(args.bom_path)
    kev_path = Path(args.kev_feed) if args.kev_feed else None
    kev_index = load_kev_feed(kev_path)
    if not kev_index:
        print(
            "warning: no KEV catalog loaded (set AIBOM_KEV_FEED or pass --kev-feed)",
            file=sys.stderr,
        )
    findings = cross_reference_kev(bom, kev_index)
    if args.report_only:
        report = {
            "kev_matches": len(findings),
            "matches": [
                {
                    "cve_id": f.metadata.get("cve_id"),
                    "vendor": f.metadata.get("kev_vendor"),
                    "product": f.metadata.get("kev_product"),
                    "date_added": f.metadata.get("kev_date_added"),
                    "known_ransomware": f.metadata.get("known_ransomware"),
                    "bom_ref": f.metadata.get("bom_ref"),
                    "summary": f.summary,
                }
                for f in findings
            ],
        }
        output = json.dumps(report, indent=2)
    else:
        output = json.dumps(bom, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    print(render_pretty_json({"kev_matches": len(findings)}), file=sys.stderr)
    return 0


def _run_sign_bom_command(args: argparse.Namespace) -> int:
    bom_path = Path(args.bom_path)
    if not bom_path.exists():
        print(f"error: {bom_path} does not exist", file=sys.stderr)
        return 2
    manifest = build_signature_manifest(
        bom_path,
        intended_signer=args.signer,
        rekor_log_url=args.rekor_url,
        key_ref=args.key_ref,
    )
    output = json.dumps(manifest.to_dict(), indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


def _read_bom(path: str) -> dict:
    bom_path = Path(path)
    if not bom_path.exists():
        raise FileNotFoundError(f"BOM file not found: {bom_path}")
    with bom_path.open(encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# report / dashboard / unified-bom / asset-graph / scan-diff handlers (P9)
# --------------------------------------------------------------------------- #

_REPORT_GENERATORS = {
    "annex-iv": generate_annex_iv_html,
    "nist-rmf": generate_nist_rmf_html,
    "iso-42001": generate_iso_42001_html,
}


def _scan_target_for_report(args: argparse.Namespace) -> ScanResult:
    """Run scan_path for the report / dashboard / asset-graph subcommands."""
    target = Path(args.target).resolve()
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    policy = load_policy_file(getattr(args, "policy", None))
    tuning = load_tuning_file(getattr(args, "tuning", None))
    return scan_path(target, policy=policy, tuning=tuning)


def _emit(content: str, output: str | None) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
    else:
        print(content)


def _run_report_command(args: argparse.Namespace) -> int:
    try:
        result = _scan_target_for_report(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    generator = _REPORT_GENERATORS[args.type]
    _emit(generator(result), args.output)
    return 0


def _run_dashboard_command(args: argparse.Namespace) -> int:
    try:
        result = _scan_target_for_report(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(generate_executive_dashboard_html(result), args.output)
    return 0


def _run_unified_bom_command(args: argparse.Namespace) -> int:
    sbom_path = Path(args.sbom_path)
    if not sbom_path.exists():
        print(f"error: SBOM file not found: {sbom_path}", file=sys.stderr)
        return 2
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: SBOM is not valid JSON: {exc}", file=sys.stderr)
        return 2
    try:
        result = _scan_target_for_report(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    aibom = build_bom(result)
    merged = merge_sbom_aibom(sbom, aibom)
    _emit(json.dumps(merged, indent=2), args.output)
    print(
        render_pretty_json({
            "sbom_components": len(sbom.get("components", []) or []),
            "aibom_components": len(aibom.get("components", []) or []),
            "merged_components": len(merged.get("components", []) or []),
            "merged_services": len(merged.get("services", []) or []),
        }),
        file=sys.stderr,
    )
    return 0


def _run_asset_graph_command(args: argparse.Namespace) -> int:
    try:
        result = _scan_target_for_report(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rendered = render_asset_graph_json(result, include_findings=not args.no_findings)
    _emit(rendered, args.output)
    return 0


def _run_asset_graph_diff_command(args: argparse.Namespace) -> int:
    older = _read_bom(args.older_path)
    newer = _read_bom(args.newer_path)
    _emit(render_asset_graph_diff_json(older, newer), args.output)
    return 0


def _run_scan_diff_command(args: argparse.Namespace) -> int:
    older = _read_scan_result(args.older_path)
    newer = _read_scan_result(args.newer_path)
    diff = diff_scan_results(older, newer)
    if args.format == "html":
        rendered = render_diff_html(diff, older_label=args.older_label, newer_label=args.newer_label)
    else:
        rendered = render_diff_json(diff)
    _emit(rendered, args.output)
    return 0


def _read_scan_result(path: str) -> ScanResult:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scan file not found: {p}")
    with p.open(encoding="utf-8") as fh:
        payload = json.load(fh)
    return ScanResult.from_dict(payload)


def _run_scan_refs_command(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    if not repo_root.exists():
        print(f"error: repo path does not exist: {repo_root}", file=sys.stderr)
        return 2
    policy = load_policy_file(args.policy)
    tuning = load_tuning_file(args.tuning)
    try:
        result = scan_git_diff(
            repo_root,
            args.base,
            args.head,
            max_file_size=args.max_file_size,
            policy=policy,
            tuning=tuning,
        )
    except GitNotAvailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    _emit(render_scan_result(result, args.format), args.output)
    print(
        render_pretty_json({
            "ref_base": args.base, "ref_head": args.head,
            "findings_in_diff": len(result.findings),
        }),
        file=sys.stderr,
    )
    return 0


def _run_pr_comment_command(args: argparse.Namespace) -> int:
    try:
        body = _build_pr_body(args)
        if args.pr_provider == "github":
            response = post_github_pr_comment(
                args.repo, args.pr_number, body,
                token_env=args.token_env, api_base=args.api_base,
            )
        elif args.pr_provider == "gitlab":
            response = post_gitlab_mr_comment(
                args.project, args.mr_iid, body,
                token_env=args.token_env, base_url=args.base_url,
            )
        elif args.pr_provider == "bitbucket-server":
            response = post_bitbucket_server_pr_comment(
                args.project, args.repo, args.pr_id, body,
                base_url=args.base_url, token_env=args.token_env,
            )
        elif args.pr_provider == "gitea":
            response = post_gitea_pr_comment(
                args.repo, args.pr_number, body,
                base_url=args.base_url, token_env=args.token_env,
            )
        else:
            print(f"error: unknown provider {args.pr_provider}", file=sys.stderr)
            return 2
    except Exception as exc:  # noqa: BLE001 — surface any transport error as exit 4
        print(f"error: {exc}", file=sys.stderr)
        return 4
    print(render_pretty_json({"posted": True, "status": response.get("status")}))
    return 0


def _build_pr_body(args: argparse.Namespace) -> str:
    if getattr(args, "diff", None):
        diff_payload = json.loads(Path(args.diff).read_text(encoding="utf-8"))
        from aibom.diff import FindingDiff
        from aibom.models import Finding
        # Reconstruct the dataclass-light shape format_diff_comment expects.
        diff = FindingDiff(
            added=[Finding.from_dict(f) for f in diff_payload.get("added", [])],
            removed=[Finding.from_dict(f) for f in diff_payload.get("removed", [])],
            severity_raised=[
                (Finding.from_dict(item["older"]), Finding.from_dict(item["newer"]))
                for item in diff_payload.get("severity_raised", [])
            ],
            severity_lowered=[
                (Finding.from_dict(item["older"]), Finding.from_dict(item["newer"]))
                for item in diff_payload.get("severity_lowered", [])
            ],
            unchanged_count=int(diff_payload.get("unchanged_count", 0)),
        )
        return format_diff_comment(diff, title=args.title)
    if getattr(args, "scan", None):
        scan_payload = json.loads(Path(args.scan).read_text(encoding="utf-8"))
        result = ScanResult.from_dict(scan_payload)
        return format_aibom_comment(result, title=args.title)
    raise ValueError("either --scan or --diff is required for pr-comment")


def _run_webhook_command(args: argparse.Namespace) -> int:
    config = WebhookConfig(
        github_secret=os.environ.get(args.github_secret_env) if args.github_secret_env else None,
        gitlab_token=os.environ.get(args.gitlab_token_env) if args.gitlab_token_env else None,
        gitea_secret=os.environ.get(args.gitea_secret_env) if args.gitea_secret_env else None,
    )
    server = create_server(config, host=args.host, port=args.port)
    print(f"aibom webhook receiver listening on http://{args.host}:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _run_check_run_command(args: argparse.Namespace) -> int:
    scan_path_arg = Path(args.scan)
    if not scan_path_arg.exists():
        print(f"error: scan file not found: {scan_path_arg}", file=sys.stderr)
        return 2
    payload = json.loads(scan_path_arg.read_text(encoding="utf-8"))
    result = ScanResult.from_dict(payload)
    body = build_check_run_body(
        result, name=args.name, head_sha=args.head_sha, details_url=args.details_url,
    )
    try:
        response = post_check_run(
            args.repo, body,
            token_env=args.token_env, api_base=args.api_base,
        )
    except Exception as exc:  # noqa: BLE001 — surface any transport error as exit 4
        print(f"error: {exc}", file=sys.stderr)
        return 4
    print(render_pretty_json({"posted": True, "status": response.get("status")}))
    return 0


def _run_demo_command(args: argparse.Namespace) -> int:
    """Scan the built-in `aibom.demo_fixture` package and print a summary.

    The fixture lives inside the wheel as package data, so we copy it
    into a temp directory (the scanner expects a real filesystem path
    for IaC + MLflow + GHA walks). ``importlib.resources.as_file``
    handles both source checkouts and installed wheels uniformly.
    """
    fixture = resources.files("aibom.demo_fixture")
    with resources.as_file(fixture) as fixture_path:
        with tempfile.TemporaryDirectory(prefix="aibom-demo-") as tmp:
            target = Path(tmp) / "fixture"
            shutil.copytree(fixture_path, target, ignore=shutil.ignore_patterns("__pycache__", "__init__.py"))
            result = scan_path(target)
    output = render_scan_result(result, args.format)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    categories = sorted({finding.category for finding in result.findings})
    source_kinds = sorted({finding.source_kind for finding in result.findings})
    print(
        render_pretty_json({
            "demo_findings": len(result.findings),
            "categories": categories,
            "source_kinds": source_kinds,
        }),
        file=sys.stderr,
    )
    return 0


# Module-level seam so tests can inject a fake transport without
# monkey-patching deeper modules. None means "use real urllib".
_PUSH_REQUESTER = None


def _run_push_command(args: argparse.Namespace) -> int:
    from aibom.aspm_push import PushError

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 2
    policy = load_policy_file(args.policy)
    tuning = load_tuning_file(args.tuning)
    result = scan_path(
        target,
        max_file_size=args.max_file_size,
        policy=policy,
        tuning=tuning,
    )
    kev_feed = Path(args.kev_feed) if args.kev_feed else None
    payload = build_aspm_payload(
        result,
        include_vex=not args.no_vex,
        include_kev=not args.no_kev,
        kev_feed=kev_feed,
        signer=args.signer,
        key_ref=args.key_ref,
    )
    try:
        response = push_aspm_payload(
            args.aspm_url,
            payload,
            token_env=args.token_env,
            project=args.project,
            requester=_PUSH_REQUESTER,
        )
    except PushError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    print(render_pretty_json({
        "posted": True,
        "status": response.status,
        "scan_id": payload["scan_id"],
        "schema_version": payload["schema_version"],
        "findings_total": payload["findings_summary"]["total"],
    }))
    return 0


# --------------------------------------------------------------------------- #
# serve / kev-refresh / reconcile handlers (P16)
# --------------------------------------------------------------------------- #

def _run_serve_command(args: argparse.Namespace) -> int:
    root = Path(args.allowed_root).expanduser().resolve() if args.allowed_root else Path.cwd().resolve()
    if not root.exists():
        print(f"error: allowed-root does not exist: {root}", file=sys.stderr)
        return 2
    config = ServeConfig(allowed_root=root)
    server = create_dashboard_server(config, host=args.host, port=args.port)
    print(
        f"aibom dashboard server listening on http://{args.host}:{args.port} "
        f"(allowed-root={root})",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _run_kev_refresh_command(args: argparse.Namespace) -> int:
    destination = Path(args.destination).expanduser() if args.destination else None
    source_url = args.source_url
    if args.no_network and not source_url:
        print(
            "error: --no-network requires --source-url (or a pre-populated local cache); "
            "refusing to call the CISA endpoint",
            file=sys.stderr,
        )
        return 3
    if source_url and source_url.startswith("file://"):
        # Allow `file://` URLs without going through urllib for air-gapped fixtures.
        local = Path(source_url[len("file://"):])
        def _file_fetcher(_url: str) -> bytes:
            return local.read_bytes()
        fetcher = _file_fetcher
    else:
        fetcher = None
    try:
        summary = refresh_kev_feed(destination, source_url=source_url, fetcher=fetcher)
    except KevRefreshError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    print(render_pretty_json(summary))
    return 0


def _run_reconcile_command(args: argparse.Namespace) -> int:
    bom_path = Path(args.bom_path)
    traces_path = Path(args.traces_path)
    if not bom_path.exists():
        print(f"error: BOM not found: {bom_path}", file=sys.stderr)
        return 2
    if not traces_path.exists():
        print(f"error: traces not found: {traces_path}", file=sys.stderr)
        return 2
    bom = json.loads(bom_path.read_text(encoding="utf-8"))
    spans = load_otel_spans(traces_path)
    report = reconcile_runtime_with_bom(bom, spans)
    _emit(json.dumps(report, indent=2), args.output)
    print(
        render_pretty_json({
            "observed_models": report["summary"]["observed_model_count"],
            "shadow_models": report["summary"]["shadow_model_count"],
            "dead_inventory": report["summary"]["dead_inventory_count"],
            "matches": report["summary"]["match_count"],
        }),
        file=sys.stderr,
    )
    return 0


def _run_cache_command(args: argparse.Namespace) -> int:
    cache_path = Path(args.cache_db) if args.cache_db else default_cache_path()
    conn = open_cache(cache_path)
    try:
        if args.cache_action == "stats":
            print(render_pretty_json({**cache_stats_for_version(conn), "cache_db": str(cache_path)}))
            return 0
        if args.cache_action == "clear":
            removed = cache_clear_all(conn)
            print(render_pretty_json({"cleared_rows": removed, "cache_db": str(cache_path)}))
            return 0
        if args.cache_action == "prune":
            removed = cache_prune_other_versions(conn)
            print(render_pretty_json({"pruned_old_version_rows": removed, "cache_db": str(cache_path)}))
            return 0
    finally:
        conn.close()
    return 1
