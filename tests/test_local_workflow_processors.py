#!/usr/bin/env python3
"""
Unit tests for local workflow processors.

These tests use synthetic fixtures only. They do not require AWS credentials,
do not call AWS APIs, and do not deploy infrastructure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXED_TIMESTAMP = "2026-01-01T00:00:00+00:00"


class LocalWorkflowProcessorTests(unittest.TestCase):
    maxDiff = None

    def run_command(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command_env = os.environ.copy()
        command_env["AWS_GUARDRAILS_FIXED_TIMESTAMP"] = FIXED_TIMESTAMP

        if env:
            command_env.update(env)

        result = subprocess.run(
            args,
            cwd=REPO_ROOT,
            env=command_env,
            text=True,
            capture_output=True,
            check=False,
        )

        if check and result.returncode != 0:
            self.fail(
                "Command failed\n"
                f"Command: {' '.join(args)}\n"
                f"Return code: {result.returncode}\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            )

        return result

    def normalize_fixture(self, source: str, input_path: str) -> dict:
        result = self.run_command(
            [
                sys.executable,
                "automation/finding-normalizer.py",
                "--source",
                source,
                "--input",
                input_path,
            ]
        )
        return json.loads(result.stdout)

    def test_finding_normalizer_supports_iam_key_age_findings(self) -> None:
        payload = self.normalize_fixture(
            "iam-key-age-check",
            "samples/raw/iam-key-age-findings.json",
        )

        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["finding_count"], 2)
        self.assertEqual(payload["findings"][0]["source"], "iam-key-age-check")
        self.assertEqual(payload["findings"][0]
                         ["normalized_at"], FIXED_TIMESTAMP)

        resource_types = {finding["resource_type"]
                          for finding in payload["findings"]}
        self.assertEqual(resource_types, {"iam_access_key"})

    def test_finding_normalizer_supports_security_group_findings(self) -> None:
        payload = self.normalize_fixture(
            "security-group-risk-check",
            "samples/raw/security-group-findings.json",
        )

        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["finding_count"], 3)

        sources = {finding["source"] for finding in payload["findings"]}
        resource_types = {finding["resource_type"]
                          for finding in payload["findings"]}

        self.assertEqual(sources, {"security-group-risk-check"})
        self.assertEqual(resource_types, {"security_group"})

    def test_finding_normalizer_supports_public_s3_findings(self) -> None:
        payload = self.normalize_fixture(
            "public-s3-check",
            "samples/raw/public-s3-findings.json",
        )

        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["finding_count"], 3)

        sources = {finding["source"] for finding in payload["findings"]}
        resource_types = {finding["resource_type"]
                          for finding in payload["findings"]}

        self.assertEqual(sources, {"public-s3-check"})
        self.assertIn("s3_bucket", resource_types)
        self.assertIn("aws_account", resource_types)

    def test_finding_normalizer_supports_cloudtrail_findings(self) -> None:
        payload = self.normalize_fixture(
            "cloudtrail-coverage-check",
            "samples/raw/cloudtrail-findings.json",
        )

        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["finding_count"], 3)

        sources = {finding["source"] for finding in payload["findings"]}
        resource_types = {finding["resource_type"]
                          for finding in payload["findings"]}

        self.assertEqual(sources, {"cloudtrail-coverage-check"})
        self.assertEqual(resource_types, {"cloudtrail_trail"})

    def test_remediation_ticket_generator_outputs_expected_json(self) -> None:
        result = self.run_command(
            [
                sys.executable,
                "automation/remediation-ticket-generator.py",
                "--input",
                "samples/normalized/normalized-findings.json",
                "--format",
                "json",
            ]
        )

        payload = json.loads(result.stdout)
        normalized_payload = json.loads(
            (REPO_ROOT / "samples/normalized/normalized-findings.json").read_text(
                encoding="utf-8"
            )
        )

        non_info_count = sum(
            1
            for finding in normalized_payload["findings"]
            if str(finding.get("severity", "")).upper() != "INFO"
        )

        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["ticket_count"], non_info_count)
        self.assertGreater(payload["ticket_count"], 0)

        first_ticket = payload["tickets"][0]
        self.assertIn("ticket_id", first_ticket)
        self.assertIn("title", first_ticket)
        self.assertIn("severity", first_ticket)
        self.assertIn("recommendation", first_ticket)
        self.assertIn("evidence_summary", first_ticket)
        self.assertEqual(first_ticket["generated_at"], FIXED_TIMESTAMP)

    def test_remediation_ticket_generator_excludes_info_by_default(self) -> None:
        result = self.run_command(
            [
                sys.executable,
                "automation/remediation-ticket-generator.py",
                "--input",
                "samples/normalized/normalized-findings.json",
                "--format",
                "json",
            ]
        )

        payload = json.loads(result.stdout)
        severities = {ticket["severity"] for ticket in payload["tickets"]}

        self.assertNotIn("INFO", severities)

    def test_remediation_ticket_generator_includes_info_when_requested(self) -> None:
        result = self.run_command(
            [
                sys.executable,
                "automation/remediation-ticket-generator.py",
                "--input",
                "samples/normalized/normalized-findings.json",
                "--format",
                "json",
                "--include-info",
            ]
        )

        payload = json.loads(result.stdout)
        normalized_payload = json.loads(
            (REPO_ROOT / "samples/normalized/normalized-findings.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(payload["ticket_count"],
                         normalized_payload["finding_count"])

        severities = {ticket["severity"] for ticket in payload["tickets"]}
        self.assertIn("INFO", severities)

    def test_executive_summary_generator_outputs_expected_sections(self) -> None:
        result = self.run_command(
            [
                sys.executable,
                "automation/executive-summary-generator.py",
                "--input",
                "samples/normalized/normalized-findings.json",
            ]
        )

        report = result.stdout

        self.assertIn(
            "# AWS Cloud Security Guardrails Executive Summary", report)
        self.assertIn("## Executive Overview", report)
        self.assertIn("## Findings by Severity", report)
        self.assertIn("## Findings by Source", report)
        self.assertIn("## Affected Resource Types", report)
        self.assertIn("## Top High/Critical Findings", report)
        self.assertIn("## Remediation Themes", report)
        self.assertIn("## Recommended Next Actions", report)
        self.assertIn(FIXED_TIMESTAMP, report)

    def test_executive_summary_generator_excludes_info_by_default(self) -> None:
        result = self.run_command(
            [
                sys.executable,
                "automation/executive-summary-generator.py",
                "--input",
                "samples/normalized/normalized-findings.json",
            ]
        )

        report = result.stdout

        self.assertIn("INFO findings are excluded by default", report)
        self.assertNotIn("| INFO |", report)

    def test_malformed_input_fails_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_json = Path(tmpdir) / "bad.json"
            bad_json.write_text("{not valid json\n", encoding="utf-8")

            result = self.run_command(
                [
                    sys.executable,
                    "automation/finding-normalizer.py",
                    "--source",
                    "iam-key-age-check",
                    "--input",
                    str(bad_json),
                ],
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ERROR:", result.stderr)


if __name__ == "__main__":
    unittest.main()
