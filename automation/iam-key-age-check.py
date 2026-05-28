#!/usr/bin/env python3
"""
IAM Access Key Age Review Script

Purpose:
    Detection-only script that lists IAM user access keys, calculates key age,
    and flags long-lived keys that exceed a configurable threshold.

Security model:
    - Read-only IAM API calls only.
    - Does not create, rotate, deactivate, or delete keys.
    - Does not print secret access key values.
    - Masks access key IDs except for a short suffix.

Example:
    python automation/iam-key-age-check.py --threshold-days 90 --format table
    python automation/iam-key-age-check.py --threshold-days 90 --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound


@dataclass
class AccessKeyFinding:
    user_name: str
    access_key_id_suffix: str
    status: str
    create_date: str
    age_days: int
    threshold_days: int
    exceeds_threshold: bool
    last_used_date: str | None
    last_used_service: str | None
    last_used_region: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review IAM user access key age using read-only AWS IAM API calls."
    )
    parser.add_argument(
        "--threshold-days",
        type=int,
        default=90,
        help="Flag keys older than this many days. Default: 90.",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Optional AWS named profile to use.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format. Default: table.",
    )
    parser.add_argument(
        "--include-last-used",
        action="store_true",
        help="Include last-used metadata for each access key.",
    )
    return parser.parse_args()


def mask_access_key_id(access_key_id: str) -> str:
    """Return only a short suffix so the full access key ID is not printed."""
    if len(access_key_id) <= 4:
        return "****"
    return f"****{access_key_id[-4:]}"


def get_iam_client(profile: str | None) -> Any:
    if profile:
        session = boto3.Session(profile_name=profile)
    else:
        session = boto3.Session()
    return session.client("iam")


def paginate_users(iam_client: Any) -> Iterable[dict[str, Any]]:
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            yield user


def paginate_access_keys(iam_client: Any, user_name: str) -> Iterable[dict[str, Any]]:
    paginator = iam_client.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=user_name):
        for key_metadata in page.get("AccessKeyMetadata", []):
            yield key_metadata


def get_last_used_metadata(iam_client: Any, access_key_id: str) -> dict[str, str | None]:
    response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
    metadata = response.get("AccessKeyLastUsed", {})

    last_used_date = metadata.get("LastUsedDate")
    if isinstance(last_used_date, datetime):
        last_used_date_value = last_used_date.astimezone(
            timezone.utc).isoformat()
    else:
        last_used_date_value = None

    return {
        "last_used_date": last_used_date_value,
        "last_used_service": metadata.get("ServiceName"),
        "last_used_region": metadata.get("Region"),
    }


def build_findings(
    iam_client: Any,
    threshold_days: int,
    include_last_used: bool,
) -> list[AccessKeyFinding]:
    now = datetime.now(timezone.utc)
    findings: list[AccessKeyFinding] = []

    for user in paginate_users(iam_client):
        user_name = user["UserName"]

        for key in paginate_access_keys(iam_client, user_name):
            access_key_id = key["AccessKeyId"]
            create_date = key["CreateDate"].astimezone(timezone.utc)
            age_days = (now - create_date).days

            last_used = {
                "last_used_date": None,
                "last_used_service": None,
                "last_used_region": None,
            }

            if include_last_used:
                last_used = get_last_used_metadata(iam_client, access_key_id)

            findings.append(
                AccessKeyFinding(
                    user_name=user_name,
                    access_key_id_suffix=mask_access_key_id(access_key_id),
                    status=key["Status"],
                    create_date=create_date.isoformat(),
                    age_days=age_days,
                    threshold_days=threshold_days,
                    exceeds_threshold=age_days > threshold_days,
                    last_used_date=last_used["last_used_date"],
                    last_used_service=last_used["last_used_service"],
                    last_used_region=last_used["last_used_region"],
                )
            )

    return findings


def print_table(findings: list[AccessKeyFinding]) -> None:
    if not findings:
        print("No IAM user access keys found.")
        return

    headers = [
        "User",
        "Key Suffix",
        "Status",
        "Created",
        "Age Days",
        "Flagged",
        "Last Used",
        "Last Service",
        "Last Region",
    ]

    rows = [
        [
            finding.user_name,
            finding.access_key_id_suffix,
            finding.status,
            finding.create_date,
            str(finding.age_days),
            "YES" if finding.exceeds_threshold else "NO",
            finding.last_used_date or "N/A",
            finding.last_used_service or "N/A",
            finding.last_used_region or "N/A",
        ]
        for finding in findings
    ]

    widths = [
        max(len(str(row[index])) for row in [headers] + rows)
        for index in range(len(headers))
    ]

    def format_row(row: list[str]) -> str:
        return " | ".join(str(value).ljust(widths[index]) for index, value in enumerate(row))

    print(format_row(headers))
    print("-+-".join("-" * width for width in widths))

    for row in rows:
        print(format_row(row))


def print_json(findings: list[AccessKeyFinding]) -> None:
    print(json.dumps([asdict(finding) for finding in findings], indent=2))


def main() -> int:
    args = parse_args()

    try:
        iam_client = get_iam_client(args.profile)
        findings = build_findings(
            iam_client=iam_client,
            threshold_days=args.threshold_days,
            include_last_used=args.include_last_used,
        )

        if args.format == "json":
            print_json(findings)
        else:
            print_table(findings)

        flagged_count = sum(
            1 for finding in findings if finding.exceeds_threshold)
        print(
            f"\nSummary: {flagged_count} key(s) older than {args.threshold_days} days.")

        return 1 if flagged_count > 0 else 0

    except ProfileNotFound as error:
        print(f"ERROR: AWS profile not found: {error}", file=sys.stderr)
        return 2
    except NoCredentialsError:
        print(
            "ERROR: AWS credentials were not found. Configure credentials or use --profile.",
            file=sys.stderr,
        )
        return 2
    except ClientError as error:
        print(f"ERROR: AWS client error: {error}", file=sys.stderr)
        return 2
    except BotoCoreError as error:
        print(f"ERROR: AWS SDK error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
