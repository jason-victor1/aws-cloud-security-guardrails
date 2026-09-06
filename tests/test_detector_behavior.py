from __future__ import annotations

import importlib.util
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]


def load_script(module_name: str, relative_path: str):
    """Load a repository script whose filename contains hyphens."""
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


IAM = load_script(
    "guardrails_iam_key_age",
    "automation/iam-key-age-check.py",
)
SG = load_script(
    "guardrails_security_group",
    "automation/security-group-risk-check.py",
)
S3 = load_script(
    "guardrails_public_s3",
    "automation/public-s3-check.py",
)
CT = load_script(
    "guardrails_cloudtrail",
    "automation/cloudtrail-coverage-check.py",
)


class FakePaginator:
    """Minimal paginator used to exercise IAM build_findings without AWS."""

    def __init__(
        self,
        page_factory: Callable[..., list[dict[str, Any]]],
    ):
        self.page_factory = page_factory

    def paginate(self, **kwargs):
        return self.page_factory(**kwargs)


class FakeIAMClient:
    """Minimal IAM client implementing only the paginator surface under test."""

    def __init__(
        self,
        keys_by_user: dict[str, list[dict[str, Any]]],
    ):
        self.keys_by_user = keys_by_user

    def get_paginator(self, operation_name: str):
        if operation_name == "list_users":
            return FakePaginator(
                lambda **_: [
                    {
                        "Users": [
                            {"UserName": user_name}
                            for user_name in sorted(self.keys_by_user)
                        ]
                    }
                ]
            )

        if operation_name == "list_access_keys":
            return FakePaginator(
                lambda **kwargs: [
                    {
                        "AccessKeyMetadata": self.keys_by_user[
                            kwargs["UserName"]
                        ]
                    }
                ]
            )

        raise AssertionError(
            f"Unexpected paginator requested: {operation_name}"
        )


class IAMKeyAgeBehaviorTests(unittest.TestCase):
    THRESHOLD_DAYS = 90

    def build_one_key(self, age_days: int):
        reference = datetime.now(timezone.utc)

        client = FakeIAMClient(
            {
                "test-user": [
                    {
                        "UserName": "test-user",
                        "AccessKeyId": "AKIATEST000000000001",
                        "Status": "Active",
                        "CreateDate": (
                            reference - timedelta(days=age_days)
                        ),
                    }
                ]
            }
        )

        findings = IAM.build_findings(
            client,
            threshold_days=self.THRESHOLD_DAYS,
            include_last_used=False,
        )

        self.assertEqual(len(findings), 1)
        return findings[0]

    def test_key_older_than_threshold_is_marked_exceeded(self):
        finding = self.build_one_key(
            self.THRESHOLD_DAYS + 1
        )

        self.assertTrue(finding.exceeds_threshold)
        self.assertGreater(
            finding.age_days,
            self.THRESHOLD_DAYS,
        )

    def test_key_younger_than_threshold_is_not_marked_exceeded(self):
        finding = self.build_one_key(
            self.THRESHOLD_DAYS - 1
        )

        self.assertFalse(finding.exceeds_threshold)
        self.assertLess(
            finding.age_days,
            self.THRESHOLD_DAYS,
        )

    def test_key_exactly_at_threshold_is_not_marked_exceeded(self):
        finding = self.build_one_key(
            self.THRESHOLD_DAYS
        )

        self.assertEqual(
            finding.age_days,
            self.THRESHOLD_DAYS,
        )
        self.assertFalse(finding.exceeds_threshold)


class SecurityGroupBehaviorTests(unittest.TestCase):
    def test_public_and_restricted_sources_are_distinguished(self):
        self.assertTrue(
            SG.is_public_source("0.0.0.0/0")
        )
        self.assertTrue(
            SG.is_public_source("::/0")
        )
        self.assertFalse(
            SG.is_public_source("10.0.0.0/16")
        )

    def test_world_open_ssh_is_classified_as_public_ssh_exposure(self):
        severity, finding_type, reason = (
            SG.classify_public_ingress(
                protocol="tcp",
                from_port=22,
                to_port=22,
                source="0.0.0.0/0",
                broad_range_threshold=100,
            )
        )

        self.assertEqual(
            finding_type,
            "public ssh exposure",
        )
        self.assertIn(
            severity,
            {"HIGH", "CRITICAL"},
        )
        self.assertIn(
            "port 22",
            reason,
        )

    def test_all_protocols_public_exposure_is_critical(self):
        severity, finding_type, _ = (
            SG.classify_public_ingress(
                protocol="-1",
                from_port=None,
                to_port=None,
                source="0.0.0.0/0",
                broad_range_threshold=100,
            )
        )

        self.assertEqual(
            severity,
            "CRITICAL",
        )
        self.assertEqual(
            finding_type,
            "all-port public exposure",
        )


class S3PostureBehaviorTests(unittest.TestCase):
    @staticmethod
    def complete_pab():
        return {
            key: True
            for key in S3.PUBLIC_ACCESS_BLOCK_KEYS
        }

    def test_complete_account_public_access_block_has_no_finding(self):
        findings = S3.account_level_findings(
            account_config=self.complete_pab(),
            account_error=None,
        )

        self.assertEqual(findings, [])

    def test_incomplete_account_public_access_block_is_flagged(self):
        config = self.complete_pab()
        config["BlockPublicPolicy"] = False

        findings = S3.account_level_findings(
            account_config=config,
            account_error=None,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].finding_type,
            (
                "incomplete account-level "
                "S3 Public Access Block"
            ),
        )
        self.assertEqual(
            findings[0].severity,
            "HIGH",
        )
        self.assertIn(
            "BlockPublicPolicy",
            findings[0].evidence,
        )

    def test_private_bucket_posture_has_no_bucket_finding(self):
        findings = S3.bucket_level_findings(
            bucket_name="test-bucket-private",
            region="us-east-1",
            account_config=self.complete_pab(),
            bucket_config=self.complete_pab(),
            bucket_pab_error=None,
            policy_is_public=False,
            policy_error=None,
            public_acl_grants=[],
            acl_error=None,
        )

        self.assertEqual(findings, [])

    def test_public_bucket_policy_is_critical(self):
        findings = S3.bucket_level_findings(
            bucket_name="test-bucket-public",
            region="us-east-1",
            account_config=self.complete_pab(),
            bucket_config=self.complete_pab(),
            bucket_pab_error=None,
            policy_is_public=True,
            policy_error=None,
            public_acl_grants=[],
            acl_error=None,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].finding_type,
            "public bucket policy",
        )
        self.assertEqual(
            findings[0].severity,
            "CRITICAL",
        )


class CloudTrailBehaviorTests(unittest.TestCase):
    @staticmethod
    def complete_trail():
        return {
            "Name": "test-trail",
            "TrailARN": (
                "arn:aws:cloudtrail:us-east-1:"
                "000000000000:trail/test-trail"
            ),
            "HomeRegion": "us-east-1",
            "LogFileValidationEnabled": True,
            "KmsKeyId": (
                "arn:aws:kms:us-east-1:"
                "000000000000:key/test-key"
            ),
            "CloudWatchLogsLogGroupArn": (
                "arn:aws:logs:us-east-1:"
                "000000000000:log-group:"
                "test-cloudtrail"
            ),
        }

    @staticmethod
    def all_management_events():
        return {
            "EventSelectors": [
                {
                    "IncludeManagementEvents": True,
                    "ReadWriteType": "All",
                }
            ]
        }

    def test_complete_trail_core_posture_has_no_finding(self):
        findings = CT.build_trail_findings(
            trail=self.complete_trail(),
            status={"IsLogging": True},
            status_error=None,
            selector_response=self.all_management_events(),
            selector_error=None,
        )

        self.assertEqual(findings, [])

    def test_stopped_logging_is_critical(self):
        findings = CT.build_trail_findings(
            trail=self.complete_trail(),
            status={"IsLogging": False},
            status_error=None,
            selector_response=self.all_management_events(),
            selector_error=None,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].finding_type,
            "trail is not logging",
        )
        self.assertEqual(
            findings[0].severity,
            "CRITICAL",
        )

    def test_disabled_management_events_are_high(self):
        selectors = {
            "EventSelectors": [
                {
                    "IncludeManagementEvents": False,
                    "ReadWriteType": "All",
                }
            ]
        }

        findings = CT.build_trail_findings(
            trail=self.complete_trail(),
            status={"IsLogging": True},
            status_error=None,
            selector_response=selectors,
            selector_error=None,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].finding_type,
            "management events not enabled",
        )
        self.assertEqual(
            findings[0].severity,
            "HIGH",
        )

    def test_read_only_management_selector_is_incomplete_coverage(self):
        selectors = {
            "EventSelectors": [
                {
                    "IncludeManagementEvents": True,
                    "ReadWriteType": "ReadOnly",
                }
            ]
        }

        findings = CT.build_trail_findings(
            trail=self.complete_trail(),
            status={"IsLogging": True},
            status_error=None,
            selector_response=selectors,
            selector_error=None,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].finding_type,
            "management event coverage may be incomplete",
        )
        self.assertEqual(
            findings[0].severity,
            "MEDIUM",
        )


if __name__ == "__main__":
    unittest.main()
