#!/usr/bin/env python3
"""
CloudTrail Logging Coverage Review Script

Purpose:
    Detection-only script that reviews AWS CloudTrail logging coverage and
    reports gaps that could weaken investigation and audit evidence.

Security model:
    - Read-only CloudTrail API calls only.
    - Does not create, modify, start, stop, or delete trails.
    - Does not read CloudTrail log object contents.
    - Does not require Terraform state.

Example:
    python automation/cloudtrail-coverage-check.py --region us-east-1 --format table
    python automation/cloudtrail-coverage-check.py --profile lab-profile --region us-east-1 --format json
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
    NoRegionError,
    ProfileNotFound,
)


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
    "INFO": 5,
}


@dataclass
class CloudTrailFinding:
    trail_name: str
    trail_arn: str | None
    home_region: str | None
    severity: str
    finding_type: str
    reason: str
    evidence: str | None


@dataclass
class CloudTrailSummary:
    trail_name: str
    trail_arn: str | None
    home_region: str | None
    is_multi_region: bool | None
    is_logging: bool | None
    log_file_validation_enabled: bool | None
    has_kms_key: bool
    s3_bucket_name: str | None
    cloudwatch_logs_configured: bool
    management_events_enabled: bool | None
    read_write_type: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review CloudTrail logging coverage using read-only AWS API calls."
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Optional AWS named profile to use.",
    )
    parser.add_argument(
        "--region",
        type=str,
        default=None,
        help="AWS region to query. If omitted, boto3 uses the configured default region.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format. Default: table.",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="Include informational findings.",
    )
    parser.add_argument(
        "--skip-event-history-check",
        action="store_true",
        help="Skip the CloudTrail LookupEvents availability check.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 1 if HIGH or CRITICAL findings are detected.",
    )
    return parser.parse_args()


def get_session(profile: str | None, region: str | None) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def resolve_region(session: boto3.Session, supplied_region: str | None) -> str:
    region = supplied_region or session.region_name
    if not region:
        raise NoRegionError()
    return region


def get_cloudtrail_client(session: boto3.Session, region: str) -> Any:
    return session.client("cloudtrail", region_name=region)


def safe_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def describe_trails(cloudtrail_client: Any) -> tuple[list[dict[str, Any]], str | None]:
    try:
        response = cloudtrail_client.describe_trails(includeShadowTrails=True)
        trails = response.get("trailList", [])
        unique: dict[str, dict[str, Any]] = {}

        for trail in trails:
            key = trail.get("TrailARN") or trail.get("Name")
            if key:
                unique[key] = trail

        return list(unique.values()), None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return [], f"{code}: {message}"


def get_trail_status(
    cloudtrail_client: Any,
    trail_name_or_arn: str,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        response = cloudtrail_client.get_trail_status(Name=trail_name_or_arn)
        return response, None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return None, f"{code}: {message}"


def get_event_selectors(
    cloudtrail_client: Any,
    trail_name_or_arn: str,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        response = cloudtrail_client.get_event_selectors(
            TrailName=trail_name_or_arn)
        return response, None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return None, f"{code}: {message}"


def check_lookup_events_available(
    cloudtrail_client: Any,
) -> tuple[bool | None, str | None]:
    try:
        cloudtrail_client.lookup_events(MaxResults=1)
        return True, None
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        message = error.response.get("Error", {}).get("Message", "")
        return None, f"{code}: {message}"


def management_events_enabled(selector_response: dict[str, Any] | None) -> tuple[bool | None, str | None]:
    if not selector_response:
        return None, None

    event_selectors = selector_response.get("EventSelectors", [])
    advanced_selectors = selector_response.get("AdvancedEventSelectors", [])

    if event_selectors:
        for selector in event_selectors:
            if selector.get("IncludeManagementEvents") is True:
                return True, selector.get("ReadWriteType")
        return False, None

    if advanced_selectors:
        for selector in advanced_selectors:
            field_selectors = selector.get("FieldSelectors", [])
            for field_selector in field_selectors:
                if (
                    field_selector.get("Field") == "eventCategory"
                    and "Management" in field_selector.get("Equals", [])
                ):
                    return True, "AdvancedEventSelectors"
        return None, "AdvancedEventSelectors"

    return None, None


def build_summary(
    trail: dict[str, Any],
    status: dict[str, Any] | None,
    selector_response: dict[str, Any] | None,
) -> CloudTrailSummary:
    trail_name = trail.get("Name", "unknown")
    trail_arn = trail.get("TrailARN")
    management_enabled, read_write_type = management_events_enabled(
        selector_response)

    return CloudTrailSummary(
        trail_name=trail_name,
        trail_arn=trail_arn,
        home_region=trail.get("HomeRegion"),
        is_multi_region=safe_bool(trail.get("IsMultiRegionTrail")),
        is_logging=safe_bool(status.get("IsLogging")) if status else None,
        log_file_validation_enabled=safe_bool(
            trail.get("LogFileValidationEnabled")),
        has_kms_key=bool(trail.get("KmsKeyId")),
        s3_bucket_name=trail.get("S3BucketName"),
        cloudwatch_logs_configured=bool(
            trail.get("CloudWatchLogsLogGroupArn")),
        management_events_enabled=management_enabled,
        read_write_type=read_write_type,
    )


def build_trail_findings(
    trail: dict[str, Any],
    status: dict[str, Any] | None,
    status_error: str | None,
    selector_response: dict[str, Any] | None,
    selector_error: str | None,
) -> list[CloudTrailFinding]:
    findings: list[CloudTrailFinding] = []

    trail_name = trail.get("Name", "unknown")
    trail_arn = trail.get("TrailARN")
    home_region = trail.get("HomeRegion")

    if status_error:
        findings.append(
            CloudTrailFinding(
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
                severity="UNKNOWN",
                finding_type="unable to retrieve trail status",
                reason="Could not retrieve CloudTrail trail logging status.",
                evidence=status_error,
            )
        )
    elif status and status.get("IsLogging") is not True:
        findings.append(
            CloudTrailFinding(
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
                severity="CRITICAL",
                finding_type="trail is not logging",
                reason="CloudTrail trail exists but IsLogging is not true.",
                evidence=f"IsLogging={status.get('IsLogging')}",
            )
        )

    if trail.get("LogFileValidationEnabled") is not True:
        findings.append(
            CloudTrailFinding(
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
                severity="MEDIUM",
                finding_type="log file validation disabled",
                reason="CloudTrail log file validation is not enabled for this trail.",
                evidence=f"LogFileValidationEnabled={trail.get('LogFileValidationEnabled')}",
            )
        )

    if not trail.get("KmsKeyId"):
        findings.append(
            CloudTrailFinding(
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
                severity="LOW",
                finding_type="KMS encryption key not configured",
                reason="Trail does not show a KMS key for log file encryption metadata.",
                evidence="KmsKeyId not present",
            )
        )

    if not trail.get("CloudWatchLogsLogGroupArn"):
        findings.append(
            CloudTrailFinding(
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
                severity="LOW",
                finding_type="CloudWatch Logs delivery not configured",
                reason="Trail does not show CloudWatch Logs delivery metadata.",
                evidence="CloudWatchLogsLogGroupArn not present",
            )
        )

    if selector_error:
        findings.append(
            CloudTrailFinding(
                trail_name=trail_name,
                trail_arn=trail_arn,
                home_region=home_region,
                severity="UNKNOWN",
                finding_type="unable to retrieve event selectors",
                reason="Could not retrieve CloudTrail event selector configuration.",
                evidence=selector_error,
            )
        )
    else:
        management_enabled, read_write_type = management_events_enabled(
            selector_response)

        if management_enabled is False:
            findings.append(
                CloudTrailFinding(
                    trail_name=trail_name,
                    trail_arn=trail_arn,
                    home_region=home_region,
                    severity="HIGH",
                    finding_type="management events not enabled",
                    reason="Trail event selectors do not include management events.",
                    evidence=f"ReadWriteType={read_write_type}",
                )
            )
        elif read_write_type and read_write_type not in {"All", "AdvancedEventSelectors"}:
            findings.append(
                CloudTrailFinding(
                    trail_name=trail_name,
                    trail_arn=trail_arn,
                    home_region=home_region,
                    severity="MEDIUM",
                    finding_type="management event coverage may be incomplete",
                    reason="Trail management event selector is not configured for all read/write activity.",
                    evidence=f"ReadWriteType={read_write_type}",
                )
            )

    return findings


def build_findings_and_summaries(
    cloudtrail_client: Any,
    include_info: bool,
    skip_event_history_check: bool,
) -> tuple[list[CloudTrailFinding], list[CloudTrailSummary]]:
    findings: list[CloudTrailFinding] = []
    summaries: list[CloudTrailSummary] = []

    trails, describe_error = describe_trails(cloudtrail_client)

    if describe_error:
        findings.append(
            CloudTrailFinding(
                trail_name="ACCOUNT_REGION",
                trail_arn=None,
                home_region=None,
                severity="UNKNOWN",
                finding_type="unable to describe trails",
                reason="Could not retrieve CloudTrail trail configuration.",
                evidence=describe_error,
            )
        )
        return findings, summaries

    if not trails:
        findings.append(
            CloudTrailFinding(
                trail_name="ACCOUNT_REGION",
                trail_arn=None,
                home_region=None,
                severity="CRITICAL",
                finding_type="no trails found",
                reason="No CloudTrail trails were returned in this region.",
                evidence=None,
            )
        )

    if trails and not any(trail.get("IsMultiRegionTrail") is True for trail in trails):
        findings.append(
            CloudTrailFinding(
                trail_name="ACCOUNT_REGION",
                trail_arn=None,
                home_region=None,
                severity="HIGH",
                finding_type="no multi-region trail found",
                reason="No CloudTrail trail returned by this region is configured as multi-region.",
                evidence=f"trails_checked={len(trails)}",
            )
        )

    for trail in trails:
        trail_identifier = trail.get("TrailARN") or trail.get("Name", "")
        status, status_error = get_trail_status(
            cloudtrail_client, trail_identifier)
        selectors, selector_error = get_event_selectors(
            cloudtrail_client, trail_identifier)

        summaries.append(build_summary(trail, status, selectors))
        findings.extend(
            build_trail_findings(
                trail=trail,
                status=status,
                status_error=status_error,
                selector_response=selectors,
                selector_error=selector_error,
            )
        )

    if not skip_event_history_check:
        lookup_available, lookup_error = check_lookup_events_available(
            cloudtrail_client)
        if lookup_error:
            findings.append(
                CloudTrailFinding(
                    trail_name="EVENT_HISTORY",
                    trail_arn=None,
                    home_region=None,
                    severity="UNKNOWN",
                    finding_type="CloudTrail LookupEvents unavailable",
                    reason="Could not perform a recent CloudTrail event history lookup.",
                    evidence=lookup_error,
                )
            )
        elif include_info and lookup_available:
            findings.append(
                CloudTrailFinding(
                    trail_name="EVENT_HISTORY",
                    trail_arn=None,
                    home_region=None,
                    severity="INFO",
                    finding_type="CloudTrail LookupEvents available",
                    reason="CloudTrail event history lookup completed successfully for this region.",
                    evidence="lookup_events MaxResults=1 succeeded",
                )
            )

    return sorted_findings(findings, include_info), sorted_summaries(summaries)


def sorted_findings(
    findings: list[CloudTrailFinding],
    include_info: bool,
) -> list[CloudTrailFinding]:
    filtered = [
        finding for finding in findings if include_info or finding.severity != "INFO"
    ]
    return sorted(
        filtered,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 99),
            finding.trail_name,
            finding.finding_type,
        ),
    )


def sorted_summaries(summaries: list[CloudTrailSummary]) -> list[CloudTrailSummary]:
    return sorted(
        summaries,
        key=lambda summary: (summary.trail_name, summary.home_region or ""),
    )


def print_findings_table(findings: list[CloudTrailFinding]) -> None:
    if not findings:
        print("No CloudTrail coverage findings detected.")
        return

    headers = ["Severity", "Trail", "Home Region",
               "Finding Type", "Reason", "Evidence"]

    rows = [
        [
            finding.severity,
            finding.trail_name,
            finding.home_region or "N/A",
            finding.finding_type,
            finding.reason,
            finding.evidence or "N/A",
        ]
        for finding in findings
    ]

    print_table(headers, rows)


def print_summaries_table(summaries: list[CloudTrailSummary]) -> None:
    if not summaries:
        print("\nNo CloudTrail trail summaries available.")
        return

    headers = [
        "Trail",
        "Home Region",
        "Multi-Region",
        "Logging",
        "Validation",
        "KMS",
        "S3 Bucket",
        "CloudWatch Logs",
        "Mgmt Events",
        "Read/Write",
    ]

    rows = [
        [
            summary.trail_name,
            summary.home_region or "N/A",
            str(summary.is_multi_region),
            str(summary.is_logging),
            str(summary.log_file_validation_enabled),
            "YES" if summary.has_kms_key else "NO",
            summary.s3_bucket_name or "N/A",
            "YES" if summary.cloudwatch_logs_configured else "NO",
            str(summary.management_events_enabled),
            summary.read_write_type or "N/A",
        ]
        for summary in summaries
    ]

    print("\nTrail Summary")
    print_table(headers, rows)


def print_table(headers: list[str], rows: list[list[str]]) -> None:
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


def print_json(
    findings: list[CloudTrailFinding],
    summaries: list[CloudTrailSummary],
) -> None:
    payload = {
        "findings": [asdict(finding) for finding in findings],
        "trail_summaries": [asdict(summary) for summary in summaries],
    }
    print(json.dumps(payload, indent=2))


def main() -> int:
    args = parse_args()

    try:
        session = get_session(profile=args.profile, region=args.region)
        region = resolve_region(session, args.region)
        cloudtrail_client = get_cloudtrail_client(session, region)

        findings, summaries = build_findings_and_summaries(
            cloudtrail_client=cloudtrail_client,
            include_info=args.include_info,
            skip_event_history_check=args.skip_event_history_check,
        )

        high_or_critical_count = sum(
            1 for finding in findings if finding.severity in {"HIGH", "CRITICAL"}
        )

        if args.format == "json":
            print_json(findings, summaries)
        else:
            print_findings_table(findings)
            print_summaries_table(summaries)
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
    except NoRegionError:
        print(
            "ERROR: AWS region was not configured. Use --region or configure a default AWS region.",
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
