#!/usr/bin/env python3
"""
Finding Normalizer

Purpose:
    Normalize JSON output from AWS Cloud Security Guardrails automation scripts
    into a consistent finding schema for reporting, evidence collection,
    remediation backlog creation, and future ticket generation.

Security model:
    - Does not call AWS APIs.
    - Does not require AWS credentials.
    - Does not modify cloud resources.
    - Reads local JSON input only.
    - Writes normalized JSON to stdout or an optional output file.

Supported sources:
    - iam-key-age-check
    - security-group-risk-check
    - public-s3-check
    - cloudtrail-coverage-check

Examples:
    python automation/finding-normalizer.py \
      --source security-group-risk-check \
      --input sg-findings.json

    python automation/finding-normalizer.py \
      --source public-s3-check \
      --input s3-findings.json \
      --output normalized-s3-findings.json

    python automation/finding-normalizer.py \
      --source auto \
      --input cloudtrail-findings.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SUPPORTED_SOURCES = {
    "auto",
    "iam-key-age-check",
    "security-group-risk-check",
    "public-s3-check",
    "cloudtrail-coverage-check",
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
class NormalizedFinding:
    schema_version: str
    normalized_at: str
    source: str
    resource_type: str
    resource_id: str
    resource_name: str | None
    region: str | None
    severity: str
    finding_type: str
    reason: str
    recommendation: str
    evidence: dict[str, Any]
    original_finding: dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize JSON findings from AWS Cloud Security Guardrails automation scripts."
    )
    parser.add_argument(
        "--source",
        choices=sorted(SUPPORTED_SOURCES),
        required=True,
        help="Source script that produced the JSON input. Use 'auto' to infer from input shape.",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to JSON input file produced by a supported automation script.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write normalized JSON. Defaults to stdout.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output. Enabled automatically for stdout.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: str) -> Any:
    input_path = Path(path)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    try:
        return json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"Input file is not valid JSON: {error}") from error


def write_json(payload: Any, output_path: str | None, pretty: bool) -> None:
    indent = 2 if pretty or output_path is None else None
    rendered = json.dumps(payload, indent=indent, sort_keys=False)

    if output_path:
        Path(output_path).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def normalize_severity(value: Any) -> str:
    if not value:
        return "UNKNOWN"

    severity = str(value).upper()
    if severity in SEVERITY_ORDER:
        return severity

    return "UNKNOWN"


def safe_string(value: Any, default: str = "unknown") -> str:
    if value is None:
        return default
    return str(value)


def infer_source(data: Any) -> str:
    if isinstance(data, dict) and "findings" in data and "trail_summaries" in data:
        return "cloudtrail-coverage-check"

    if isinstance(data, list) and data:
        first = data[0]

        if not isinstance(first, dict):
            return "unknown"

        if {"user_name", "access_key_id_suffix", "age_days"}.issubset(first.keys()):
            return "iam-key-age-check"

        if {"group_id", "source", "protocol", "category"}.issubset(first.keys()):
            return "security-group-risk-check"

        if {"bucket_name", "finding_type", "reason"}.issubset(first.keys()):
            return "public-s3-check"

    return "unknown"


def iam_recommendation(finding: dict[str, Any]) -> str:
    if finding.get("exceeds_threshold") is True:
        return (
            "Review whether this IAM access key is still required. Rotate or retire "
            "long-lived keys, prefer role-based access where possible, and confirm "
            "recent usage before removal."
        )

    return (
        "No threshold breach was reported for this key. Continue monitoring key age "
        "and prefer role-based access over long-lived static credentials."
    )


def security_group_recommendation(finding: dict[str, Any]) -> str:
    category = safe_string(finding.get("category"), "").lower()

    if "ssh" in category:
        return (
            "Restrict SSH exposure to approved administrative CIDRs, use a VPN or "
            "bastion pattern if required, or prefer AWS Systems Manager Session Manager."
        )

    if "rdp" in category:
        return (
            "Restrict RDP exposure to approved administrative CIDRs, use private access "
            "paths, and require strong identity controls."
        )

    if "database" in category or any(
        term in category
        for term in ["mysql", "postgresql", "sql server", "oracle", "mongodb"]
    ):
        return (
            "Remove public database exposure. Restrict access to application security "
            "groups, private subnets, or approved administrative CIDRs."
        )

    if "all-port" in category or "broad" in category:
        return (
            "Replace broad public ingress with least-privilege rules that limit source "
            "CIDRs, protocols, and required ports."
        )

    if "web" in category:
        return (
            "Confirm public HTTP/HTTPS exposure is intentional. If public access is not "
            "required, restrict the source or place the workload behind approved edge controls."
        )

    return (
        "Review the public ingress rule and restrict source CIDRs, protocols, and ports "
        "to the minimum required access."
    )


def public_s3_recommendation(finding: dict[str, Any]) -> str:
    finding_type = safe_string(finding.get("finding_type"), "").lower()

    if "account-level" in finding_type:
        return (
            "Enable all four account-level S3 Public Access Block settings unless a "
            "documented exception exists."
        )

    if "bucket-level" in finding_type:
        return (
            "Enable all four bucket-level S3 Public Access Block settings for this bucket "
            "unless a documented exception exists."
        )

    if "public bucket policy" in finding_type:
        return (
            "Review the bucket policy, remove unintended public principals, and confirm "
            "that account-level and bucket-level Public Access Block controls are enabled."
        )

    if "public ACL" in finding_type:
        return (
            "Remove public ACL grants and prefer bucket policies or access points with "
            "least-privilege access controls."
        )

    return (
        "Review the S3 exposure finding, confirm whether public access is intentional, "
        "and apply Public Access Block or least-privilege policy controls."
    )


def cloudtrail_recommendation(finding: dict[str, Any]) -> str:
    finding_type = safe_string(finding.get("finding_type"), "").lower()

    if "no trails" in finding_type:
        return (
            "Create an organization or account CloudTrail trail with multi-region "
            "management event coverage."
        )

    if "not logging" in finding_type:
        return (
            "Investigate why the trail is stopped and restart logging after confirming "
            "the delivery destination and permissions."
        )

    if "multi-region" in finding_type:
        return (
            "Configure at least one multi-region trail so activity across enabled AWS "
            "Regions is captured."
        )

    if "log file validation" in finding_type:
        return (
            "Enable CloudTrail log file validation to support integrity verification of "
            "delivered CloudTrail logs."
        )

    if "management events" in finding_type:
        return (
            "Configure CloudTrail event selectors to include management events, ideally "
            "for both read and write activity."
        )

    if "lookup" in finding_type:
        return (
            "Verify CloudTrail Event History permissions and regional availability for "
            "investigation workflows."
        )

    return (
        "Review the CloudTrail coverage finding and update trail configuration to improve "
        "investigation and audit evidence readiness."
    )


def normalize_iam_findings(data: Any, normalized_at: str) -> list[NormalizedFinding]:
    if not isinstance(data, list):
        raise ValueError("IAM key age input must be a JSON list.")

    normalized: list[NormalizedFinding] = []

    for finding in data:
        if not isinstance(finding, dict):
            continue

        exceeds_threshold = finding.get("exceeds_threshold") is True
        severity = "HIGH" if exceeds_threshold else "INFO"
        user_name = safe_string(finding.get("user_name"))

        normalized.append(
            NormalizedFinding(
                schema_version="1.0",
                normalized_at=normalized_at,
                source="iam-key-age-check",
                resource_type="iam_access_key",
                resource_id=safe_string(finding.get("access_key_id_suffix")),
                resource_name=user_name,
                region=None,
                severity=severity,
                finding_type="long_lived_iam_access_key" if exceeds_threshold else "iam_access_key_age_observed",
                reason=(
                    f"IAM access key for user {user_name} is "
                    f"{finding.get('age_days')} days old. Threshold is "
                    f"{finding.get('threshold_days')} days."
                ),
                recommendation=iam_recommendation(finding),
                evidence={
                    "user_name": user_name,
                    "access_key_id_suffix": finding.get("access_key_id_suffix"),
                    "status": finding.get("status"),
                    "create_date": finding.get("create_date"),
                    "age_days": finding.get("age_days"),
                    "threshold_days": finding.get("threshold_days"),
                    "exceeds_threshold": exceeds_threshold,
                    "last_used_date": finding.get("last_used_date"),
                    "last_used_service": finding.get("last_used_service"),
                    "last_used_region": finding.get("last_used_region"),
                },
                original_finding=finding,
            )
        )

    return normalized


def normalize_security_group_findings(data: Any, normalized_at: str) -> list[NormalizedFinding]:
    if not isinstance(data, list):
        raise ValueError("Security group risk input must be a JSON list.")

    normalized: list[NormalizedFinding] = []

    for finding in data:
        if not isinstance(finding, dict):
            continue

        group_id = safe_string(finding.get("group_id"))

        normalized.append(
            NormalizedFinding(
                schema_version="1.0",
                normalized_at=normalized_at,
                source="security-group-risk-check",
                resource_type="security_group",
                resource_id=group_id,
                resource_name=finding.get("group_name"),
                region=None,
                severity=normalize_severity(finding.get("severity")),
                finding_type=safe_string(
                    finding.get("category")).replace(" ", "_"),
                reason=safe_string(finding.get("reason")),
                recommendation=security_group_recommendation(finding),
                evidence={
                    "group_id": group_id,
                    "group_name": finding.get("group_name"),
                    "vpc_id": finding.get("vpc_id"),
                    "protocol": finding.get("protocol"),
                    "from_port": finding.get("from_port"),
                    "to_port": finding.get("to_port"),
                    "source_type": finding.get("source_type"),
                    "source": finding.get("source"),
                    "rule_description": finding.get("rule_description"),
                },
                original_finding=finding,
            )
        )

    return normalized


def normalize_public_s3_findings(data: Any, normalized_at: str) -> list[NormalizedFinding]:
    if not isinstance(data, list):
        raise ValueError("Public S3 input must be a JSON list.")

    normalized: list[NormalizedFinding] = []

    for finding in data:
        if not isinstance(finding, dict):
            continue

        bucket_name = safe_string(finding.get("bucket_name"))

        normalized.append(
            NormalizedFinding(
                schema_version="1.0",
                normalized_at=normalized_at,
                source="public-s3-check",
                resource_type="s3_bucket" if bucket_name != "ACCOUNT_LEVEL" else "aws_account",
                resource_id=bucket_name,
                resource_name=bucket_name,
                region=finding.get("region"),
                severity=normalize_severity(finding.get("severity")),
                finding_type=safe_string(finding.get(
                    "finding_type")).replace(" ", "_"),
                reason=safe_string(finding.get("reason")),
                recommendation=public_s3_recommendation(finding),
                evidence={
                    "bucket_name": finding.get("bucket_name"),
                    "region": finding.get("region"),
                    "finding_type": finding.get("finding_type"),
                    "evidence": finding.get("evidence"),
                },
                original_finding=finding,
            )
        )

    return normalized


def normalize_cloudtrail_findings(data: Any, normalized_at: str) -> list[NormalizedFinding]:
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        raise ValueError(
            "CloudTrail input must be a JSON object with a findings list or a JSON list.")

    normalized: list[NormalizedFinding] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        trail_name = safe_string(finding.get("trail_name"))
        trail_arn = finding.get("trail_arn")

        normalized.append(
            NormalizedFinding(
                schema_version="1.0",
                normalized_at=normalized_at,
                source="cloudtrail-coverage-check",
                resource_type="cloudtrail_trail",
                resource_id=safe_string(trail_arn or trail_name),
                resource_name=trail_name,
                region=finding.get("home_region"),
                severity=normalize_severity(finding.get("severity")),
                finding_type=safe_string(finding.get(
                    "finding_type")).replace(" ", "_"),
                reason=safe_string(finding.get("reason")),
                recommendation=cloudtrail_recommendation(finding),
                evidence={
                    "trail_name": finding.get("trail_name"),
                    "trail_arn": finding.get("trail_arn"),
                    "home_region": finding.get("home_region"),
                    "finding_type": finding.get("finding_type"),
                    "evidence": finding.get("evidence"),
                },
                original_finding=finding,
            )
        )

    return normalized


def normalize_findings(source: str, data: Any) -> list[NormalizedFinding]:
    actual_source = infer_source(data) if source == "auto" else source

    if actual_source not in SUPPORTED_SOURCES or actual_source == "auto":
        raise ValueError(
            "Could not infer supported source. Specify --source explicitly. "
            f"Supported sources: {', '.join(sorted(SUPPORTED_SOURCES - {'auto'}))}"
        )

    normalized_at = utc_now()

    if actual_source == "iam-key-age-check":
        return normalize_iam_findings(data, normalized_at)

    if actual_source == "security-group-risk-check":
        return normalize_security_group_findings(data, normalized_at)

    if actual_source == "public-s3-check":
        return normalize_public_s3_findings(data, normalized_at)

    if actual_source == "cloudtrail-coverage-check":
        return normalize_cloudtrail_findings(data, normalized_at)

    raise ValueError(f"Unsupported source: {actual_source}")


def main() -> int:
    args = parse_args()

    try:
        data = load_json(args.input)
        findings = normalize_findings(args.source, data)

        payload = {
            "schema_version": "1.0",
            "finding_count": len(findings),
            "findings": [asdict(finding) for finding in sorted_findings(findings)],
        }

        write_json(payload, args.output, pretty=args.pretty)
        return 0

    except (FileNotFoundError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: File operation failed: {error}", file=sys.stderr)
        return 2


def sorted_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 99),
            finding.source,
            finding.resource_type,
            finding.resource_id,
            finding.finding_type,
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
