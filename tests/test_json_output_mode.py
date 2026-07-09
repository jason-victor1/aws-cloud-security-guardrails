import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module(module_name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class JsonOutputModeTests(unittest.TestCase):
    def run_main(self, module, argv):
        stdout = io.StringIO()

        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            exit_code = module.main()

        return exit_code, stdout.getvalue()

    def test_iam_key_age_json_stdout_is_single_json_document(self):
        module = load_module(
            "iam_key_age_check_json_test",
            "automation/iam-key-age-check.py",
        )

        with patch.object(module, "get_iam_client", return_value=object()), patch.object(
            module, "build_findings", return_value=[]
        ):
            exit_code, stdout = self.run_main(
                module,
                ["iam-key-age-check.py", "--format", "json"],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout), [])
        self.assertNotIn("Summary:", stdout)

    def test_security_group_json_stdout_is_single_json_document(self):
        module = load_module(
            "security_group_risk_check_json_test",
            "automation/security-group-risk-check.py",
        )

        with patch.object(module, "get_ec2_client", return_value=object()), patch.object(
            module, "build_findings", return_value=[]
        ):
            exit_code, stdout = self.run_main(
                module,
                ["security-group-risk-check.py", "--format",
                    "json", "--region", "us-east-1"],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout), [])
        self.assertNotIn("Summary:", stdout)

    def test_public_s3_json_stdout_is_single_json_document(self):
        module = load_module(
            "public_s3_check_json_test",
            "automation/public-s3-check.py",
        )

        with patch.object(module, "get_session", return_value=object()), patch.object(
            module, "get_account_id", return_value="<ACCOUNT_ID_REDACTED>"
        ), patch.object(module, "build_findings", return_value=[]):
            exit_code, stdout = self.run_main(
                module,
                ["public-s3-check.py", "--format", "json"],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout), [])
        self.assertNotIn("Summary:", stdout)

    def test_cloudtrail_json_stdout_is_single_json_document(self):
        module = load_module(
            "cloudtrail_coverage_check_json_test",
            "automation/cloudtrail-coverage-check.py",
        )

        with patch.object(module, "get_session", return_value=object()), patch.object(
            module, "resolve_region", return_value="us-east-1"
        ), patch.object(module, "get_cloudtrail_client", return_value=object()), patch.object(
            module, "build_findings_and_summaries", return_value=([], [])
        ):
            exit_code, stdout = self.run_main(
                module,
                ["cloudtrail-coverage-check.py", "--format",
                    "json", "--region", "us-east-1"],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout),
            {
                "findings": [],
                "trail_summaries": [],
            },
        )
        self.assertNotIn("Summary:", stdout)


if __name__ == "__main__":
    unittest.main()
