#!/usr/bin/env python3
"""
Public S3 Exposure Review Script

Purpose:
    Detection-only script that reviews S3 bucket public exposure posture.

Security model:
    - Read-only S3, S3 Control, and STS API calls only.
    - Does not create, modify, delete, upload, download, or read S3 objects.
    - Does not print object data.
    - Does not require Terraform state.

Example:
    python automation/public-s3-check.py --format table
    python automation/public-s3-check.py --profile lab-profile --format json
    python automation/public-s3-check.py --account-id <ACCOUNT_ID> --format table
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)


PUBLIC_ACCESS_BLOCK_KEYS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]

PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
    "INFO": 5,
}


@dataclass
class S3ExposureFinding:
    bucket_name: str
    region: str | None
    severity: str
    finding_type: str
    reason: str
    evidence: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review S3 bucket public exposure posture using read-only AWS API calls."
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Optional AWS named profile to use.",
    )
    parser.add_argument(
        "--account-id",
        type=str,
        default=None,
        help="Optional AWS account ID. If omitted, the script calls STS GetCallerIdentity.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format. Default: table.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 1 if HIGH or CRITICAL findings are detected.",
    )
    return parser.parse_args()


def get_session(profile: str | None) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def get_account_id(session: boto3.Session, supplied_account_id: str | None) -> str:
    if supplied_account_id:
        return supplied_account_id

    sts_client = session.client("sts")
    response = sts_client.get_caller_identity()
    return response["Account"]


def get_s3_client(session: boto3.Session, region: str | None = None) -> Any:
    if region:
        return session.client("s3", region_name=region)
    return session.client("s3")


def get_s3control_client(session: boto3.Session) -> Any:
    return session.client("s3control")


def list_buckets(s3_client: Any) -> list[dict[str, Any]]:
    response = s3_client.list_buckets()
    return response.get("Buckets", [])


def get_bucket_region(s3_client: Any, bucket_name: str) -> str | None:
    """
    Use HeadBucket to infer bucket region from response headers.

    AWS recommends HeadBucket over GetBucketLocation for returning the bucket
    region in newer guidance. This call does not read object contents.
    """
    try:
        response = s3_client.head_bucket(Bucket=bucket_name)
        headers = response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        return headers.get("x-amz-bucket-region") or "us-east-1"
    except ClientError as error:
        headers = error.response.get(
            "ResponseMetadata", {}).get("HTTPHeaders", {})
        return headers.get("x-amz-bucket-region")


def is_complete_public_access_block(config: dict[str, Any] | None) -> bool:
    if not config:
        return False
    return all(config.get(key) is True for key in PUBLIC_ACCESS_BLOCK_KEYS)


def missing_public_access_block_keys(config: dict[str, Any] | None) -> list[str]:
    if not config:
        return PUBLIC_ACCESS_BLOCK_KEYS.copy()
    return [key for key in PUBLIC_ACCESS_BLOCK_KEYS if config.get(key) is not True]


def get_account_public_access_block(
    s3control_client: Any,
    account_id: str,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        response = s3control_client.get_public_access_block(
            AccountId=account_id)
        return response.get("PublicAccessBlockConfiguration"), None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return None, f"{code}: {message}"


def get_bucket_public_access_block(
    s3_client: Any,
    bucket_name: str,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        return response.get("PublicAccessBlockConfiguration"), None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return None, f"{code}: {message}"


def get_bucket_policy_status(
    s3_client: Any,
    bucket_name: str,
) -> tuple[bool | None, str | None]:
    try:
        response = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        return response.get("PolicyStatus", {}).get("IsPublic"), None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return None, f"{code}: {message}"


def get_bucket_acl_public_grants(
    s3_client: Any,
    bucket_name: str,
) -> tuple[list[str], str | None]:
    public_grants: list[str] = []

    try:
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return public_grants, f"{code}: {message}"

    for grant in response.get("Grants", []):
        grantee = grant.get("Grantee", {})
        permission = grant.get("Permission", "UNKNOWN")
        uri = grantee.get("URI")

        if uri in PUBLIC_ACL_URIS:
            public_grants.append(f"{PUBLIC_ACL_URIS[uri]}:{permission}")

    return public_grants, None


def account_level_findings(
    account_config: dict[str, Any] | None,
    account_error: str | None,
) -> list[S3ExposureFinding]:
    findings: list[S3ExposureFinding] = []

    if account_error:
        findings.append(
            S3ExposureFinding(
                bucket_name="ACCOUNT_LEVEL",
                region=None,
                severity="UNKNOWN",
                finding_type="unable to evaluate account-level public access block",
                reason="Unable to retrieve account-level S3 Public Access Block configuration.",
                evidence=account_error,
            )
        )
        return findings

    if not account_config:
        findings.append(
            S3ExposureFinding(
                bucket_name="ACCOUNT_LEVEL",
                region=None,
                severity="HIGH",
                finding_type="missing account-level S3 Public Access Block",
                reason="Account-level S3 Public Access Block configuration was not found.",
                evidence=None,
            )
        )
        return findings

    missing_keys = missing_public_access_block_keys(account_config)
    if missing_keys:
        findings.append(
            S3ExposureFinding(
                bucket_name="ACCOUNT_LEVEL",
                region=None,
                severity="HIGH",
                finding_type="incomplete account-level S3 Public Access Block",
                reason="Account-level S3 Public Access Block exists but not all four settings are enabled.",
                evidence=", ".join(missing_keys),
            )
        )

    return findings


def bucket_level_findings(
    bucket_name: str,
    region: str | None,
    account_config: dict[str, Any] | None,
    bucket_config: dict[str, Any] | None,
    bucket_pab_error: str | None,
    policy_is_public: bool | None,
    policy_error: str | None,
    public_acl_grants: list[str],
    acl_error: str | None,
) -> list[S3ExposureFinding]:
    findings: list[S3ExposureFinding] = []

    account_pab_complete = is_complete_public_access_block(account_config)

    if bucket_pab_error:
        findings.append(
            S3ExposureFinding(
                bucket_name=bucket_name,
                region=region,
                severity="MEDIUM" if account_pab_complete else "HIGH",
                finding_type="missing or unavailable bucket-level S3 Public Access Block",
                reason="Bucket-level S3 Public Access Block could not be retrieved.",
                evidence=bucket_pab_error,
            )
        )
    elif not bucket_config:
        findings.append(
            S3ExposureFinding(
                bucket_name=bucket_name,
                region=region,
                severity="MEDIUM" if account_pab_complete else "HIGH",
                finding_type="missing bucket-level S3 Public Access Block",
                reason="Bucket-level S3 Public Access Block configuration was not found.",
                evidence=None,
            )
        )
    else:
        missing_keys = missing_public_access_block_keys(bucket_config)
        if missing_keys:
            findings.append(
                S3ExposureFinding(
                    bucket_name=bucket_name,
                    region=region,
                    severity="MEDIUM" if account_pab_complete else "HIGH",
                    finding_type="incomplete bucket-level S3 Public Access Block",
                    reason="Bucket-level S3 Public Access Block exists but not all four settings are enabled.",
                    evidence=", ".join(missing_keys),
                )
            )

    if policy_error:
        findings.append(
            S3ExposureFinding(
                bucket_name=bucket_name,
                region=region,
                severity="UNKNOWN",
                finding_type="unable to evaluate bucket policy status",
                reason="Unable to retrieve bucket policy public status.",
                evidence=policy_error,
            )
        )
    elif policy_is_public is True:
        findings.append(
            S3ExposureFinding(
                bucket_name=bucket_name,
                region=region,
                severity="CRITICAL",
                finding_type="public bucket policy",
                reason="S3 reports that the bucket policy is public.",
                evidence="PolicyStatus.IsPublic=true",
            )
        )

    if acl_error:
        findings.append(
            S3ExposureFinding(
                bucket_name=bucket_name,
                region=region,
                severity="UNKNOWN",
                finding_type="unable to evaluate bucket ACL",
                reason="Unable to retrieve bucket ACL.",
                evidence=acl_error,
            )
        )
    elif public_acl_grants:
        findings.append(
            S3ExposureFinding(
                bucket_name=bucket_name,
                region=region,
                severity="HIGH",
                finding_type="public ACL grant",
                reason="Bucket ACL includes a public group grant.",
                evidence=", ".join(public_acl_grants),
            )
        )

    return findings


def build_findings(session: boto3.Session, account_id: str) -> list[S3ExposureFinding]:
    findings: list[S3ExposureFinding] = []

    global_s3_client = get_s3_client(session)
    s3control_client = get_s3control_client(session)

    account_config, account_error = get_account_public_access_block(
        s3control_client=s3control_client,
        account_id=account_id,
    )

    findings.extend(account_level_findings(account_config, account_error))

    buckets = list_buckets(global_s3_client)

    for bucket in buckets:
        bucket_name = bucket["Name"]
        region = get_bucket_region(global_s3_client, bucket_name)
        regional_s3_client = get_s3_client(
            session, region=region) if region else global_s3_client

        bucket_config, bucket_pab_error = get_bucket_public_access_block(
            s3_client=regional_s3_client,
            bucket_name=bucket_name,
        )

        policy_is_public, policy_error = get_bucket_policy_status(
            s3_client=regional_s3_client,
            bucket_name=bucket_name,
        )

        public_acl_grants, acl_error = get_bucket_acl_public_grants(
            s3_client=regional_s3_client,
            bucket_name=bucket_name,
        )

        findings.extend(
            bucket_level_findings(
                bucket_name=bucket_name,
                region=region,
                account_config=account_config,
                bucket_config=bucket_config,
                bucket_pab_error=bucket_pab_error,
                policy_is_public=policy_is_public,
                policy_error=policy_error,
                public_acl_grants=public_acl_grants,
                acl_error=acl_error,
            )
        )

    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 99),
            finding.bucket_name,
            finding.finding_type,
        ),
    )


def print_table(findings: list[S3ExposureFinding]) -> None:
    if not findings:
        print("No public S3 exposure findings detected.")
        return

    headers = ["Severity", "Bucket", "Region",
               "Finding Type", "Reason", "Evidence"]

    rows = [
        [
            finding.severity,
            finding.bucket_name,
            finding.region or "N/A",
            finding.finding_type,
            finding.reason,
            finding.evidence or "N/A",
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


def print_json(findings: list[S3ExposureFinding]) -> None:
    print(json.dumps([asdict(finding) for finding in findings], indent=2))


def main() -> int:
    args = parse_args()

    try:
        session = get_session(args.profile)
        account_id = get_account_id(session, args.account_id)
        findings = build_findings(session=session, account_id=account_id)

        high_or_critical_count = sum(
            1 for finding in findings if finding.severity in {"HIGH", "CRITICAL"}
        )

        if args.format == "json":
            print_json(findings)
        else:
            print_table(findings)
            print(
                f"\nSummary: {len(findings)} finding(s), "
                f"{high_or_critical_count} high/critical finding(s)."
            )

        if args.fail_on_findings and high_or_critical_count > 0:
            return 1

        return 0

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
