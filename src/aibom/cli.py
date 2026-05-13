from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from aibom.connectors import scan_aws_account, scan_azure_subscription, scan_gcp_project, scan_github_repo, scan_huggingface_model
from aibom.policy import load_policy_file
from aibom.reporters import render_cyclonedx, render_json, render_markdown, render_pretty_json, render_sarif
from aibom.scanner import scan_path
from aibom.store import diff_scans, get_scan, list_scans, save_scan
from aibom.tuning import load_tuning_file


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
        help="Environment variable containing a GitHub token",
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in {"scan", "scan-github", "scan-huggingface", "scan-aws", "scan-azure", "scan-gcp", "history", "show-scan", "diff-scans", "-h", "--help"}:
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

    policy = load_policy_file(args.policy)
    tuning = load_tuning_file(args.tuning)

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
        result = scan_path(target, max_file_size=args.max_file_size, exclude_patterns=args.exclude, policy=policy, tuning=tuning)

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
