# main.py
"""
CLI entrypoint for the scanner.

- Supports two modes:
  * dummy: read resources from a JSON file (offline testing)
  * aws: run against a live AWS account using boto3.Session
- Produces JSON, CSV, and HTML reports and prints a colorful summary table.
"""

import argparse
import logging
import os

import boto3

from scanner.aws_s3 import scan_all_buckets_live, scan_all_buckets_from_json
from utils import load_json_file, save_report, print_summary_and_report_path
from config import DEFAULT_AWS_REGION

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloud_scanner")


def run_dummy(file_path: str, report_dir: str = "reports", print_table: bool = False):
    """
    Run the scanner in dummy mode using a local JSON file.
    No AWS access is required in this mode.
    """
    logger.info("Running in dummy mode using file: %s", file_path)
    data = load_json_file(file_path)
    findings = scan_all_buckets_from_json(data)
    report_paths = save_report(
        findings,
        mode="dummy",
        extra={"source_file": file_path},
        out_dir=report_dir,
    )
    print_summary_and_report_path(
        findings, report_paths, print_full_table=print_table
    )


def run_aws(profile: str = None, region: str = None,
            report_dir: str = "reports", print_table: bool = False):
    """
    Run the scanner against a live AWS account.

    Credential model:
    - AWS Vault (or similar) injects temporary credentials via environment variables.
    - This function does NOT require a profile name; it only needs a region.
    """
    # Resolve region: CLI -> env -> config default
    region = region or os.environ.get("AWS_REGION") or DEFAULT_AWS_REGION

    logger.info("Running in live AWS mode (region=%s)", region)

    # No profile_name here – credentials are expected to come from the environment
    # (e.g., via `aws-vault exec scanner-user -- python main.py ...`).
    session = boto3.Session(region_name=region)

    findings = scan_all_buckets_live(session)
    report_paths = save_report(
        findings,
        mode="aws",
        extra={"region": region},
        out_dir=report_dir,
    )
    print_summary_and_report_path(
        findings, report_paths, print_full_table=print_table
    )


def parse_args():
    p = argparse.ArgumentParser(
        description="Cloud misconfiguration scanner (S3 example)."
    )
    p.add_argument(
        "--mode",
        choices=["dummy", "aws"],
        required=True,
        help="Run mode: dummy (JSON) or aws (live)",
    )
    p.add_argument(
        "--file",
        help="Path to dummy JSON file (required for dummy mode)",
    )
    p.add_argument(
        "--profile",
        help="AWS profile name (optional for aws mode, currently ignored when using AWS Vault)",
    )
    p.add_argument(
        "--region",
        help="AWS region (optional)",
    )
    p.add_argument(
        "--report-dir",
        default="reports",
        help="Directory to save reports (default: reports)",
    )
    p.add_argument(
        "--print-table",
        action="store_true",
        help="Print full findings table to stdout",
    )
    return p.parse_args()


def main():
    args = parse_args()
    if args.mode == "dummy":
        if not args.file:
            raise SystemExit("dummy mode requires --file path to JSON")
        run_dummy(
            args.file,
            report_dir=args.report_dir,
            print_table=args.print_table,
        )
    else:
        # `profile` argument is accepted for compatibility, but not used
        run_aws(
            profile=args.profile,
            region=args.region,
            report_dir=args.report_dir,
            print_table=args.print_table,
        )


if __name__ == "__main__":
    main()
