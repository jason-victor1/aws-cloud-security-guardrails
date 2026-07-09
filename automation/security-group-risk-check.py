#!/usr/bin/env python3
"""
Security Group Risk Review Script

Purpose:
    Detection-only script that reviews AWS security group inbound rules and
    flags risky public exposure patterns.

Security model:
    - Read-only EC2 API calls only.
    - Does not create, modify, revoke, or delete security group rules.
    - Does not require Terraform state.
    - Does not print AWS secret values.

Example:
    python automation/security-group-risk-check.py --region us-east-1 --format table
    python automation/security-group-risk-check.py --profile lab-profile --region us-east-1 --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any, Iterable

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)


PUBLIC_IPV4 = "0.0.0.0/0"
PUBLIC_IPV6 = "::/0"


RISKY_PORTS: dict[int, tuple[str, str]] = {
    20: ("FTP data", "HIGH"),
    21: ("FTP control", "HIGH"),
    22: ("SSH", "CRITICAL"),
    23: ("Telnet", "CRITICAL"),
    25: ("SMTP", "MEDIUM"),
    110: ("POP3", "MEDIUM"),
    135: ("Microsoft RPC", "HIGH"),
    139: ("NetBIOS", "HIGH"),
    143: ("IMAP", "MEDIUM"),
    389: ("LDAP", "HIGH"),
    445: ("SMB", "CRITICAL"),
    1433: ("Microsoft SQL Server", "HIGH"),
    1521: ("Oracle Database", "HIGH"),
    2049: ("NFS", "HIGH"),
    2375: ("Docker API without TLS", "CRITICAL"),
    2376: ("Docker API with TLS", "HIGH"),
    2379: ("etcd client API", "CRITICAL"),
    2380: ("etcd peer API", "CRITICAL"),
    3306: ("MySQL/MariaDB", "HIGH"),
    3389: ("RDP", "CRITICAL"),
    5432: ("PostgreSQL", "HIGH"),
    5601: ("Kibana/OpenSearch Dashboards", "HIGH"),
    5900: ("VNC", "HIGH"),
    5985: ("WinRM HTTP", "HIGH"),
    5986: ("WinRM HTTPS", "HIGH"),
    6379: ("Redis", "CRITICAL"),
    6443: ("Kubernetes API", "CRITICAL"),
    8080: ("HTTP alternate", "MEDIUM"),
    8443: ("HTTPS alternate", "MEDIUM"),
    9200: ("Elasticsearch/OpenSearch HTTP", "HIGH"),
    9300: ("Elasticsearch/OpenSearch transport", "HIGH"),
    11211: ("Memcached", "CRITICAL"),
    27017: ("MongoDB", "HIGH"),
}


WEB_PORTS = {
    80: "HTTP",
    443: "HTTPS",
}


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class SecurityGroupFinding:
    group_id: str
    group_name: str
    vpc_id: str | None
    protocol: str
    from_port: int | None
    to_port: int | None
    source_type: str
    source: str
    severity: str
    category: str
    reason: str
    rule_description: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review security group ingress rules for risky public exposure."
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
        help="AWS region to scan. If omitted, boto3 uses the configured default region.",
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
        help="Include informational HTTP/HTTPS public exposure findings.",
    )
    parser.add_argument(
        "--broad-range-threshold",
        type=int,
        default=100,
        help="Flag public port ranges wider than this number of ports. Default: 100.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 1 if findings are detected. Useful for future CI usage.",
    )
    return parser.parse_args()


def get_ec2_client(profile: str | None, region: str | None) -> Any:
    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)

    return session.client("ec2")


def paginate_security_groups(ec2_client: Any) -> Iterable[dict[str, Any]]:
    paginator = ec2_client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for security_group in page.get("SecurityGroups", []):
            yield security_group


def is_public_source(source: str) -> bool:
    return source in {PUBLIC_IPV4, PUBLIC_IPV6}


def port_range_label(from_port: int | None, to_port: int | None) -> str:
    if from_port is None and to_port is None:
        return "all"
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def range_includes_port(from_port: int | None, to_port: int | None, port: int) -> bool:
    if from_port is None and to_port is None:
        return True
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def port_range_width(from_port: int | None, to_port: int | None) -> int | None:
    if from_port is None or to_port is None:
        return None
    return abs(to_port - from_port) + 1


def classify_public_ingress(
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    source: str,
    broad_range_threshold: int,
) -> tuple[str, str, str]:
    if protocol == "-1":
        return (
            "CRITICAL",
            "all-port public exposure",
            f"Security group allows all protocols and ports from {source}.",
        )

    width = port_range_width(from_port, to_port)

    if from_port == 0 and to_port == 65535:
        return (
            "CRITICAL",
            "all-port public exposure",
            f"Security group allows all TCP/UDP ports from {source}.",
        )

    if width is not None and width > broad_range_threshold:
        return (
            "HIGH",
            "broad public port range",
            f"Security group allows a broad public port range {port_range_label(from_port, to_port)} from {source}.",
        )

    risky_matches: list[tuple[int, str, str]] = []
    for port, (service_name, severity) in RISKY_PORTS.items():
        if range_includes_port(from_port, to_port, port):
            risky_matches.append((port, service_name, severity))

    if risky_matches:
        highest = sorted(
            risky_matches, key=lambda item: SEVERITY_ORDER[item[2]])[0]
        port, service_name, severity = highest
        return (
            severity,
            f"public {service_name.lower()} exposure",
            f"Security group exposes {service_name} on port {port} to {source}.",
        )

    web_matches: list[str] = []
    for port, service_name in WEB_PORTS.items():
        if range_includes_port(from_port, to_port, port):
            web_matches.append(service_name)

    if web_matches:
        return (
            "INFO",
            "public web exposure",
            f"Security group exposes {'/'.join(web_matches)} to {source}. Review whether this is intentional.",
        )

    return (
        "MEDIUM",
        "public ingress exposure",
        f"Security group allows public ingress on protocol {protocol}, ports {port_range_label(from_port, to_port)} from {source}.",
    )


def build_findings(
    ec2_client: Any,
    include_info: bool,
    broad_range_threshold: int,
) -> list[SecurityGroupFinding]:
    findings: list[SecurityGroupFinding] = []

    for security_group in paginate_security_groups(ec2_client):
        group_id = security_group.get("GroupId", "unknown")
        group_name = security_group.get("GroupName", "unknown")
        vpc_id = security_group.get("VpcId")

        for permission in security_group.get("IpPermissions", []):
            protocol = permission.get("IpProtocol", "unknown")
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            sources: list[tuple[str, str, str | None]] = []

            for ip_range in permission.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                if cidr:
                    sources.append(("ipv4", cidr, ip_range.get("Description")))

            for ipv6_range in permission.get("Ipv6Ranges", []):
                cidr = ipv6_range.get("CidrIpv6")
                if cidr:
                    sources.append(
                        ("ipv6", cidr, ipv6_range.get("Description")))

            for source_type, source, description in sources:
                if not is_public_source(source):
                    continue

                severity, category, reason = classify_public_ingress(
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    source=source,
                    broad_range_threshold=broad_range_threshold,
                )

                if severity == "INFO" and not include_info:
                    continue

                findings.append(
                    SecurityGroupFinding(
                        group_id=group_id,
                        group_name=group_name,
                        vpc_id=vpc_id,
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        source_type=source_type,
                        source=source,
                        severity=severity,
                        category=category,
                        reason=reason,
                        rule_description=description,
                    )
                )

    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 99),
            finding.group_id,
            finding.from_port if finding.from_port is not None else -1,
        ),
    )


def print_table(findings: list[SecurityGroupFinding]) -> None:
    if not findings:
        print("No risky public security group ingress findings detected.")
        return

    headers = [
        "Severity",
        "Group ID",
        "Group Name",
        "VPC ID",
        "Protocol",
        "Ports",
        "Source",
        "Category",
        "Reason",
    ]

    rows = [
        [
            finding.severity,
            finding.group_id,
            finding.group_name,
            finding.vpc_id or "N/A",
            finding.protocol,
            port_range_label(finding.from_port, finding.to_port),
            finding.source,
            finding.category,
            finding.reason,
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


def print_json(findings: list[SecurityGroupFinding]) -> None:
    print(json.dumps([asdict(finding) for finding in findings], indent=2))


def main() -> int:
    args = parse_args()

    try:
        ec2_client = get_ec2_client(profile=args.profile, region=args.region)
        findings = build_findings(
            ec2_client=ec2_client,
            include_info=args.include_info,
            broad_range_threshold=args.broad_range_threshold,
        )

        flagged_count = sum(
            1 for finding in findings if finding.exceeds_threshold
        )

        if args.format == "json":
            print_json(findings)
        else:
            print_table(findings)
            print(
                f"\nSummary: {flagged_count} key(s) older than {args.threshold_days} days."
            )

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
