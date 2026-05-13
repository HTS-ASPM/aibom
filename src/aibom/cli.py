from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from aibom.connectors import scan_aws_account, scan_azure_subscription, scan_gcp_project, scan_github_repo, scan_huggingface_model
from aibom.policy import load_policy_file
from aibom.reporters import render_cyclonedx, render_json, render_markdown, render_pretty_json, render_sarif
from aibom.scanner import scan_path
from aibom.signing import build_signature_manifest
from aibom.store import diff_scans, get_scan, list_scans, save_scan
from aibom.tuning import load_tuning_file
from aibom.vex import (
    cross_reference,
    cross_reference_kev,
    load_feed,
    load_kev_feed,
    merge_vex_into_bom,
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
    known_commands = {
        "scan", "scan-github", "scan-huggingface", "scan-aws", "scan-azure", "scan-gcp",
        "history", "show-scan", "diff-scans", "vex", "kev", "sign-bom",
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
