#!/usr/bin/env python3
"""
Remediation Ticket Generator

Purpose:
    Convert normalized security findings from automation/finding-normalizer.py
    into structured remediation backlog items.

Security model:
    - Does not call AWS APIs.
    - Does not require AWS credentials.
    - Does not modify cloud resources.
    - Does not create GitHub Issues automatically in V1.
    - Reads local normalized JSON input only.
    - Writes Markdown or JSON output to stdout or an optional output file.

Expected input shape:
    {
      "schema_version": "1.0",
      "finding_count": 1,
      "findings": [
        {
          "schema_version": "1.0",
          "normalized_at": "2026-01-01T00:00:00+00:00",
          "source": "security-group-risk-check",
          "resource_type": "security_group",
          "resource_id": "sg-xxxxxxxx",
          "resource_name": "example-security-group",
          "region": null,
          "severity": "HIGH",
          "finding_type": "public_ssh_exposure",
          "reason": "Security group exposes SSH on port 22 to 0.0.0.0/0.",
          "recommendation": "Restrict SSH exposure...",
          "evidence": {},
          "original_finding": {}
        }
      ]
    }

Examples:
    python automation/remediation-ticket-generator.py \
      --input normalized-findings.json \
      --format markdown

    python automation/remediation-ticket-generator.py \
      --input normalized-findings.json \
      --format json \
      --output remediation-tickets.json

    python automation/remediation-ticket-generator.py \
      --input normalized-findings.json \
      --format markdown \
      --output remediation-backlog.md
"""

from __future__ import annotations

import os
import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
    "INFO": 5,
}

DEFAULT_STATUS = "Open"


@dataclass
class RemediationTicket:
    ticket_id: str
    title: str
    severity: str
    status: str
    source: str
    resource_type: str
    resource_id: str
    resource_name: str | None
    region: str | None
    finding_type: str
    reason: str
    recommendation: str
    evidence_summary: dict[str, Any]
    normalized_at: str | None
    generated_at: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate remediation tickets from normalized AWS security findings."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to normalized JSON findings produced by automation/finding-normalizer.py.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format. Default: markdown.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write generated tickets. Defaults to stdout.",
    )
    parser.add_argument(
        "--status",
        default=DEFAULT_STATUS,
        help=f"Default ticket status. Default: {DEFAULT_STATUS}.",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="Include INFO severity findings. By default, INFO findings are excluded.",
    )
    return parser.parse_args()


def utc_now() -> str:
    fixed_timestamp = os.environ.get("AWS_GUARDRAILS_FIXED_TIMESTAMP")
    if fixed_timestamp:
        return fixed_timestamp
    return datetime.now(timezone.utc).isoformat()


def load_json(path: str) -> dict[str, Any]:
    input_path = Path(path)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"Input file is not valid JSON: {error}") from error

    if not isinstance(data, dict):
        raise ValueError("Normalized input must be a JSON object.")

    if "findings" not in data:
        raise ValueError("Normalized input must contain a 'findings' field.")

    if not isinstance(data["findings"], list):
        raise ValueError("'findings' must be a list.")

    return data


def write_output(content: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(content + "\n", encoding="utf-8")
    else:
        print(content)


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


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or "finding"


def truncate(value: str, max_length: int = 90) -> str:
    if len(value) <= max_length:
        return value
    return value[: max_length - 3].rstrip() + "..."


def sanitize_for_markdown(value: Any) -> str:
    """
    Basic Markdown-safe rendering.

    This does not try to redact arbitrary secrets. Upstream workflows should avoid
    feeding raw secrets or sensitive scan outputs into this tool.
    """
    if value is None:
        return "N/A"

    rendered = str(value)
    rendered = rendered.replace("\n", " ").replace("\r", " ")
    return rendered


def evidence_summary(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}

    summary: dict[str, Any] = {}

    preferred_keys = [
        "user_name",
        "access_key_id_suffix",
        "status",
        "age_days",
        "threshold_days",
        "last_used_date",
        "last_used_service",
        "last_used_region",
        "group_id",
        "group_name",
        "vpc_id",
        "protocol",
        "from_port",
        "to_port",
        "source_type",
        "source",
        "bucket_name",
        "region",
        "trail_name",
        "trail_arn",
        "home_region",
        "finding_type",
        "evidence",
    ]

    for key in preferred_keys:
        if key in evidence and evidence[key] is not None:
            summary[key] = evidence[key]

    for key, value in evidence.items():
        if key not in summary and value is not None:
            summary[key] = value

    return summary


def generate_ticket_id(index: int, finding: dict[str, Any]) -> str:
    severity = normalize_severity(finding.get("severity"))
    source = slugify(safe_string(finding.get("source")))
    resource_type = slugify(safe_string(finding.get("resource_type")))
    finding_type = slugify(safe_string(finding.get("finding_type")))

    return f"REM-{index:04d}-{severity}-{source}-{resource_type}-{finding_type}".upper()


def build_title(finding: dict[str, Any]) -> str:
    severity = normalize_severity(finding.get("severity"))
    resource_type = safe_string(finding.get("resource_type"))
    resource_id = safe_string(finding.get("resource_id"))
    finding_type = safe_string(finding.get("finding_type")).replace("_", " ")

    return truncate(f"[{severity}] {finding_type} on {resource_type} {resource_id}")


def build_tickets(
    normalized_payload: dict[str, Any],
    default_status: str,
    include_info: bool,
) -> list[RemediationTicket]:
    findings = normalized_payload["findings"]
    generated_at = utc_now()

    filtered_findings: list[dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(finding.get("severity"))

        if severity == "INFO" and not include_info:
            continue

        filtered_findings.append(finding)

    filtered_findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER.get(normalize_severity(
                finding.get("severity")), 99),
            safe_string(finding.get("source")),
            safe_string(finding.get("resource_type")),
            safe_string(finding.get("resource_id")),
            safe_string(finding.get("finding_type")),
        )
    )

    tickets: list[RemediationTicket] = []

    for index, finding in enumerate(filtered_findings, start=1):
        tickets.append(
            RemediationTicket(
                ticket_id=generate_ticket_id(index, finding),
                title=build_title(finding),
                severity=normalize_severity(finding.get("severity")),
                status=default_status,
                source=safe_string(finding.get("source")),
                resource_type=safe_string(finding.get("resource_type")),
                resource_id=safe_string(finding.get("resource_id")),
                resource_name=finding.get("resource_name"),
                region=finding.get("region"),
                finding_type=safe_string(finding.get("finding_type")),
                reason=safe_string(finding.get("reason")),
                recommendation=safe_string(finding.get("recommendation")),
                evidence_summary=evidence_summary(finding.get("evidence")),
                normalized_at=finding.get("normalized_at"),
                generated_at=generated_at,
            )
        )

    return tickets


def tickets_to_json(tickets: list[RemediationTicket]) -> str:
    payload = {
        "schema_version": "1.0",
        "ticket_count": len(tickets),
        "tickets": [asdict(ticket) for ticket in tickets],
    }
    return json.dumps(payload, indent=2)


def tickets_to_markdown(tickets: list[RemediationTicket]) -> str:
    lines: list[str] = []

    lines.append("# Remediation Backlog")
    lines.append("")
    lines.append(f"Generated at: `{utc_now()}`")
    lines.append("")
    lines.append(f"Ticket count: `{len(tickets)}`")
    lines.append("")

    if not tickets:
        lines.append("No remediation tickets generated.")
        return "\n".join(lines)

    lines.append("## Summary by Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")

    severity_counts: dict[str, int] = {}

    for ticket in tickets:
        severity_counts[ticket.severity] = severity_counts.get(
            ticket.severity, 0) + 1

    for severity in sorted(severity_counts, key=lambda item: SEVERITY_ORDER.get(item, 99)):
        lines.append(f"| {severity} | {severity_counts[severity]} |")

    lines.append("")
    lines.append("## Tickets")
    lines.append("")

    current_severity: str | None = None

    for ticket in tickets:
        if ticket.severity != current_severity:
            current_severity = ticket.severity
            lines.append(f"### {current_severity}")
            lines.append("")

        lines.append(
            f"#### {ticket.ticket_id}: {sanitize_for_markdown(ticket.title)}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append(f"| Status | {sanitize_for_markdown(ticket.status)} |")
        lines.append(
            f"| Severity | {sanitize_for_markdown(ticket.severity)} |")
        lines.append(f"| Source | `{sanitize_for_markdown(ticket.source)}` |")
        lines.append(
            f"| Resource Type | `{sanitize_for_markdown(ticket.resource_type)}` |")
        lines.append(
            f"| Resource ID | `{sanitize_for_markdown(ticket.resource_id)}` |")
        lines.append(
            f"| Resource Name | {sanitize_for_markdown(ticket.resource_name)} |")
        lines.append(f"| Region | {sanitize_for_markdown(ticket.region)} |")
        lines.append(
            f"| Finding Type | `{sanitize_for_markdown(ticket.finding_type)}` |")
        lines.append(
            f"| Normalized At | {sanitize_for_markdown(ticket.normalized_at)} |")
        lines.append(
            f"| Generated At | {sanitize_for_markdown(ticket.generated_at)} |")
        lines.append("")
        lines.append("**Reason**")
        lines.append("")
        lines.append(sanitize_for_markdown(ticket.reason))
        lines.append("")
        lines.append("**Recommended Remediation**")
        lines.append("")
        lines.append(sanitize_for_markdown(ticket.recommendation))
        lines.append("")
        lines.append("**Evidence Summary**")
        lines.append("")

        if ticket.evidence_summary:
            lines.append("```json")
            lines.append(json.dumps(ticket.evidence_summary, indent=2))
            lines.append("```")
        else:
            lines.append("No evidence summary provided.")

        lines.append("")
        lines.append("**Closure Checklist**")
        lines.append("")
        lines.append("- [ ] Owner assigned")
        lines.append("- [ ] Finding validated")
        lines.append("- [ ] Remediation plan approved")
        lines.append("- [ ] Change implemented")
        lines.append("- [ ] Evidence captured")
        lines.append("- [ ] Finding retested")
        lines.append("- [ ] Ticket closed")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()

    try:
        normalized_payload = load_json(args.input)
        tickets = build_tickets(
            normalized_payload=normalized_payload,
            default_status=args.status,
            include_info=args.include_info,
        )

        if args.format == "json":
            output = tickets_to_json(tickets)
        else:
            output = tickets_to_markdown(tickets)

        write_output(output, args.output)
        return 0

    except (FileNotFoundError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: File operation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
