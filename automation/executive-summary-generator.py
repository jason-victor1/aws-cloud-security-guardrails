#!/usr/bin/env python3
"""
Executive Summary Report Generator

Purpose:
    Convert normalized AWS security findings from automation/finding-normalizer.py
    into a client-style Markdown executive summary report.

Security model:
    - Does not call AWS APIs.
    - Does not require AWS credentials.
    - Does not modify cloud resources.
    - Does not deploy infrastructure.
    - Reads local normalized JSON input only.
    - Writes Markdown to stdout or an optional output file.

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
    python automation/executive-summary-generator.py \
      --input normalized-findings.json

    python automation/executive-summary-generator.py \
      --input normalized-findings.json \
      --output executive-summary.md

    python automation/executive-summary-generator.py \
      --input normalized-findings.json \
      --title "AWS Security Assessment Summary" \
      --top-n 10
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
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

DEFAULT_TITLE = "AWS Cloud Security Guardrails Executive Summary"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown executive summary from normalized AWS security findings."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to normalized JSON findings produced by automation/finding-normalizer.py.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write the Markdown report. Defaults to stdout.",
    )
    parser.add_argument(
        "--title",
        default=DEFAULT_TITLE,
        help=f"Report title. Default: {DEFAULT_TITLE}.",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Maximum number of top findings to include. Default: 10.",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="Include INFO severity findings. By default, INFO findings are excluded.",
    )
    return parser.parse_args()


def utc_now() -> str:
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


def sanitize_markdown(value: Any) -> str:
    if value is None:
        return "N/A"

    rendered = str(value)
    rendered = rendered.replace("\n", " ").replace("\r", " ")
    rendered = rendered.replace("|", "\\|")
    return rendered


def filter_findings(findings: list[Any], include_info: bool) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(finding.get("severity"))

        if severity == "INFO" and not include_info:
            continue

        normalized = dict(finding)
        normalized["severity"] = severity
        filtered.append(normalized)

    return sorted_findings(filtered)


def sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(normalize_severity(
                finding.get("severity")), 99),
            safe_string(finding.get("source")),
            safe_string(finding.get("resource_type")),
            safe_string(finding.get("resource_id")),
            safe_string(finding.get("finding_type")),
        ),
    )


def count_by_key(findings: list[dict[str, Any]], key: str) -> Counter[str]:
    counter: Counter[str] = Counter()

    for finding in findings:
        counter[safe_string(finding.get(key))] += 1

    return counter


def severity_counts(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()

    for finding in findings:
        counter[normalize_severity(finding.get("severity"))] += 1

    return counter


def high_or_critical_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        finding
        for finding in findings
        if normalize_severity(finding.get("severity")) in {"CRITICAL", "HIGH"}
    ]


def classify_theme(finding: dict[str, Any]) -> str:
    source = safe_string(finding.get("source"), "").lower()
    finding_type = safe_string(finding.get("finding_type"), "").lower()
    resource_type = safe_string(finding.get("resource_type"), "").lower()
    reason = safe_string(finding.get("reason"), "").lower()

    joined = f"{source} {finding_type} {resource_type} {reason}"

    if any(term in joined for term in ["iam", "access_key", "credential", "secret", "token"]):
        return "Credential risk"

    if any(
        term in joined
        for term in [
            "security_group",
            "ssh",
            "rdp",
            "public_ingress",
            "public_ssh",
            "public_rdp",
            "database",
            "redis",
            "kubernetes",
            "elasticsearch",
            "opensearch",
            "broad_public",
        ]
    ):
        return "Network exposure risk"

    if any(term in joined for term in ["s3", "bucket", "public_acl", "public_bucket_policy"]):
        return "S3 public exposure risk"

    if any(term in joined for term in ["cloudtrail", "trail", "logging", "event_selector", "lookup"]):
        return "Logging and investigation readiness"

    return "General cloud security hygiene"


def remediation_theme_summary(findings: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()

    for finding in findings:
        counter[classify_theme(finding)] += 1

    return counter


def theme_recommendation(theme: str) -> str:
    recommendations = {
        "Credential risk": (
            "Prioritize credential rotation, key retirement, least-privilege review, "
            "and migration from long-lived keys to role-based access where possible."
        ),
        "Network exposure risk": (
            "Restrict public ingress, remove broad administrative exposure, and prefer "
            "private access patterns such as VPN, bastion, or AWS Systems Manager Session Manager."
        ),
        "S3 public exposure risk": (
            "Enable account-level and bucket-level S3 Public Access Block, remove unintended "
            "public policies or ACLs, and document exceptions."
        ),
        "Logging and investigation readiness": (
            "Improve CloudTrail coverage, confirm multi-region management event logging, "
            "enable log file validation, and verify investigation workflows."
        ),
        "General cloud security hygiene": (
            "Review the finding, validate business context, assign an owner, and track remediation "
            "through the backlog."
        ),
    }

    return recommendations.get(theme, recommendations["General cloud security hygiene"])


def posture_label(findings: list[dict[str, Any]]) -> str:
    counts = severity_counts(findings)

    if counts.get("CRITICAL", 0) > 0:
        return "Critical attention required"

    if counts.get("HIGH", 0) > 0:
        return "High-priority remediation required"

    if counts.get("MEDIUM", 0) > 0:
        return "Moderate risk with remediation needed"

    if counts.get("LOW", 0) > 0 or counts.get("UNKNOWN", 0) > 0:
        return "Low-to-unknown risk requiring review"

    return "No non-informational findings reported"


def recommended_next_actions(findings: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    counts = severity_counts(findings)
    themes = remediation_theme_summary(findings)

    if counts.get("CRITICAL", 0) > 0:
        actions.append(
            "Address critical findings first and preserve evidence before making changes.")

    if counts.get("HIGH", 0) > 0:
        actions.append(
            "Assign owners for high-severity findings and define remediation due dates.")

    if themes.get("Credential risk", 0) > 0:
        actions.append(
            "Review credential findings for active exposure, rotate or retire risky keys, and confirm CloudTrail activity.")

    if themes.get("Network exposure risk", 0) > 0:
        actions.append(
            "Review public ingress findings and restrict administrative or database exposure to approved access paths.")

    if themes.get("S3 public exposure risk", 0) > 0:
        actions.append(
            "Review S3 public exposure findings and enable Public Access Block controls unless a documented exception exists.")

    if themes.get("Logging and investigation readiness", 0) > 0:
        actions.append(
            "Review CloudTrail coverage findings to improve audit evidence and incident investigation readiness.")

    if not actions:
        actions.append(
            "Continue monitoring with the existing guardrail and detection workflow.")

    actions.append(
        "Generate remediation tickets for validated findings and track closure evidence.")

    return actions


def render_count_table(title: str, counts: Counter[str], severity_sort: bool = False) -> list[str]:
    lines: list[str] = []

    lines.append(f"## {title}")
    lines.append("")

    if not counts:
        lines.append("No data available.")
        lines.append("")
        return lines

    lines.append("| Category | Count |")
    lines.append("|---|---:|")

    if severity_sort:
        keys = sorted(
            counts.keys(), key=lambda item: SEVERITY_ORDER.get(item, 99))
    else:
        keys = sorted(counts.keys(), key=lambda item: (-counts[item], item))

    for key in keys:
        lines.append(f"| {sanitize_markdown(key)} | {counts[key]} |")

    lines.append("")
    return lines


def render_top_findings(findings: list[dict[str, Any]], top_n: int) -> list[str]:
    lines: list[str] = []
    top_findings = high_or_critical_findings(findings)[:top_n]

    lines.append("## Top High/Critical Findings")
    lines.append("")

    if not top_findings:
        lines.append(
            "No high or critical findings were included in the normalized input.")
        lines.append("")
        return lines

    lines.append("| Severity | Source | Resource | Finding Type | Reason |")
    lines.append("|---|---|---|---|---|")

    for finding in top_findings:
        resource = f"{safe_string(finding.get('resource_type'))}: {safe_string(finding.get('resource_id'))}"
        lines.append(
            "| "
            f"{sanitize_markdown(finding.get('severity'))} | "
            f"`{sanitize_markdown(finding.get('source'))}` | "
            f"`{sanitize_markdown(resource)}` | "
            f"`{sanitize_markdown(finding.get('finding_type'))}` | "
            f"{sanitize_markdown(finding.get('reason'))} |"
        )

    lines.append("")
    return lines


def render_remediation_themes(findings: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    themes = remediation_theme_summary(findings)

    lines.append("## Remediation Themes")
    lines.append("")

    if not themes:
        lines.append("No remediation themes were identified.")
        lines.append("")
        return lines

    lines.append("| Theme | Count | Recommended Focus |")
    lines.append("|---|---:|---|")

    for theme, count in sorted(themes.items(), key=lambda item: (-item[1], item[0])):
        lines.append(
            f"| {sanitize_markdown(theme)} | {count} | {sanitize_markdown(theme_recommendation(theme))} |"
        )

    lines.append("")
    return lines


def render_next_actions(findings: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    actions = recommended_next_actions(findings)

    lines.append("## Recommended Next Actions")
    lines.append("")

    for index, action in enumerate(actions, start=1):
        lines.append(f"{index}. {sanitize_markdown(action)}")

    lines.append("")
    return lines


def render_report(title: str, findings: list[dict[str, Any]], top_n: int, include_info: bool) -> str:
    generated_at = utc_now()
    counts = severity_counts(findings)
    sources = count_by_key(findings, "source")
    resource_types = count_by_key(findings, "resource_type")
    critical_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)

    lines: list[str] = []

    lines.append(f"# {sanitize_markdown(title)}")
    lines.append("")
    lines.append(f"Generated at: `{generated_at}`")
    lines.append("")
    lines.append("## Executive Overview")
    lines.append("")
    lines.append(
        f"This report summarizes `{len(findings)}` normalized finding(s) from the "
        "AWS Cloud Security Guardrails automation workflow."
    )
    lines.append("")
    lines.append(
        f"Overall posture: **{sanitize_markdown(posture_label(findings))}**")
    lines.append("")
    lines.append(f"High/Critical findings: `{critical_high}`")
    lines.append("")
    lines.append(
        "The report is generated from local normalized JSON input. It does not call AWS APIs, "
        "does not require AWS credentials, and does not modify cloud resources."
    )
    lines.append("")

    if not include_info:
        lines.append(
            "INFO findings are excluded by default. Use `--include-info` to include them in the report."
        )
        lines.append("")

    lines.extend(render_count_table(
        "Findings by Severity", counts, severity_sort=True))
    lines.extend(render_count_table("Findings by Source", sources))
    lines.extend(render_count_table("Affected Resource Types", resource_types))
    lines.extend(render_top_findings(findings, top_n))
    lines.extend(render_remediation_themes(findings))
    lines.extend(render_next_actions(findings))

    lines.append("## Notes and Limitations")
    lines.append("")
    lines.append(
        "- This report depends on the completeness and quality of the normalized input file.")
    lines.append(
        "- Findings should be validated before remediation work is executed.")
    lines.append(
        "- Generated reports should be reviewed for sensitive environment details before sharing.")
    lines.append(
        "- This report does not prove remediation; it summarizes current findings and recommended actions.")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()

    try:
        normalized_payload = load_json(args.input)
        findings = filter_findings(
            normalized_payload["findings"], include_info=args.include_info)
        report = render_report(
            title=args.title,
            findings=findings,
            top_n=args.top_n,
            include_info=args.include_info,
        )
        write_output(report, args.output)
        return 0

    except (FileNotFoundError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: File operation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
