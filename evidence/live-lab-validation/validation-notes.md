# Live AWS Lab Validation Notes

## Summary

This document records sanitized validation notes for running the AWS Cloud Security Guardrails read-only posture review workflow against a controlled AWS lab account.

No raw live-lab outputs are included in this repository.

## Validation Metadata

| Field                        | Value                                       |
| ---------------------------- | ------------------------------------------- |
| Validation date              | `<YYYY-MM-DD>`                              |
| AWS account type             | Controlled lab account                      |
| Assessment principal         | Dedicated read-only assessment principal    |
| Assessment policy used       | `docs/iam/read-only-assessment-policy.json` |
| Raw output storage location  | Outside repository                          |
| Sanitized evidence committed | Yes                                         |
| Raw output committed         | No                                          |

## Pre-Run Safety Checklist

- [x] Controlled AWS lab account used
- [x] Dedicated read-only assessment principal used
- [x] Active identity confirmed with STS before script execution
- [x] No administrator profile used for live-lab script execution
- [x] No root user credentials used
- [x] No production account used
- [x] Raw output folder created outside repository
- [x] No Terraform `apply` command run
- [x] No remediation workflow run
- [x] Redaction rules reviewed before creating evidence

## Identity Confirmation

Active AWS identity was confirmed before running scripts.

Command pattern used:

    aws sts get-caller-identity --profile <assessment-profile>

Sanitized result:

    Account: <ACCOUNT_ID_REDACTED>
    Arn: <ACCOUNT_ID_REDACTED>:user/aws-guardrails-readonly
    UserId: <USER_ID_REDACTED>

Validation result:

- Dedicated read-only assessment principal confirmed: yes

## Scripts Executed

|                                           | Script                                    | Status                                                                                                                                                                                                                                                | Notes |
| ----------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| `automation/iam-key-age-check.py`         | `executed with output validation finding` | Ran with `--profile guardrails-readonly --format json --include-last-used`; exit code `0`; stderr empty; raw output stored outside the repository; `python -m json.tool` reported `Extra data`, indicating output was not valid single-document JSON. |
| `automation/security-group-risk-check.py` | `executed with output validation finding` | Ran with `--profile guardrails-readonly --region us-east-1 --format json`; exit code `0`; stderr empty; raw output stored outside the repository; `python -m json.tool` reported `Extra data`, indicating output was not valid single-document JSON.  |
| `automation/public-s3-check.py`           | `executed with output validation finding` | Ran with `--profile guardrails-readonly --format json`; exit code `0`; stderr empty; raw output stored outside the repository; `python -m json.tool` reported `Extra data`, indicating output was not valid single-document JSON.                     |
| `automation/cloudtrail-coverage-check.py` | `executed with output validation finding` | Ran with `--profile guardrails-readonly --region us-east-1 --format json`; exit code `0`; stderr empty; raw output stored outside the repository; `python -m json.tool` reported `Extra data`, indicating output was not valid single-document JSON.  |

## Raw Output Handling

Raw outputs were stored outside the repository.

External raw output path pattern:

    ~/aws-guardrails-lab-evidence/raw/

Repository status:

- Raw live-lab outputs committed: no

## Sanitized Finding Summary

Use only sanitized counts and high-level summaries here.

| Source                     | Sanitized Finding Count | Notes                                                                                     |
| -------------------------- | ----------------------: | ----------------------------------------------------------------------------------------- |
| IAM key age review         |          `not recorded` | Script executed successfully, but raw JSON output failed single-document JSON validation. |
| Security group risk review |          `not recorded` | Script executed successfully, but raw JSON output failed single-document JSON validation. |
| Public S3 exposure review  |          `not recorded` | Script executed successfully, but raw JSON output failed single-document JSON validation. |
| CloudTrail coverage review |          `not recorded` | Script executed successfully, but raw JSON output failed single-document JSON validation. |

## No-Change Confirmation

- Validation mode: read-only
- Terraform apply used: no
- AWS mutation APIs intentionally used: no
- Remediation performed: no
- Infrastructure deployed: no
- Raw outputs committed: no

## Evidence Captured

Sanitized evidence captured:

- STS identity confirmation note with sensitive values redacted
- Script execution notes
- Sanitized finding count summary
- Redaction notes
- No-change confirmation

## Output Validation Finding

The live-lab scripts were executed with `--format json`, but each raw output file failed validation with `python -m json.tool`.

Observed validation results:

```text
iam-key-age-findings.json: Extra data
security-group-findings.json: Extra data
public-s3-findings.json: Extra data
cloudtrail-findings.json: Extra data
```

Interpretation:

```text
The scripts completed successfully, but JSON output mode should be corrected so each script emits one valid JSON document when `--format json` is selected.
```

Follow-up needed:

```text
Create a follow-up issue to fix JSON output mode for live AWS assessment scripts.
```

## Local diagnostic only — do not paste raw output

To inspect the structure without exposing details, run this locally:

```bash
for f in ~/aws-guardrails-lab-evidence/raw/*.json; do
  echo "===== $(basename "$f") ====="
  python - <<'PY' "$f"
import sys, json
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()
decoder = json.JSONDecoder()

try:
    obj, end = decoder.raw_decode(text)
    extra = text[end:].strip()
    print("first_json_type:", type(obj).__name__)
    print("first_json_end_char:", end)
    print("extra_content_after_first_json:", bool(extra))
    print("total_chars:", len(text))
    print("total_lines:", text.count("\n") + 1)
except Exception as exc:
    print("parse_error:", exc)
PY
done
```

## Notes

Add sanitized observations here.

Do not include real account IDs, ARNs, bucket names, security group IDs, access key IDs, IP addresses, or raw findings.

The initial STS identity check succeeded, but the active default IAM user had the AWS managed AdministratorAccess policy attached. To preserve the live-lab safety boundary, no assessment scripts were executed with this profile. A dedicated read-only assessment profile must be configured before live-lab execution continues.

Initial default profile check found AdministratorAccess. Live-lab execution was paused. A dedicated read-only assessment IAM user named aws-guardrails-readonly was created and configured under the guardrails-readonly AWS CLI profile before continuing.

Initial default profile check found AdministratorAccess. Live-lab execution was paused. A dedicated read-only IAM user named aws-guardrails-readonly was created, the project read-only assessment policy was attached, and a named AWS CLI profile called guardrails-readonly was configured before continuing.

Policy simulation confirmed that representative write/admin actions returned implicitDeny, while the required read-only assessment actions returned allowed.

Initial script help checks failed because boto3 was not installed in the local Python environment. No assessment scripts were executed at that point. A local Python virtual environment was created outside the repository, dependencies were installed from automation/requirements.txt, and script help checks were retried before live-lab execution.

Script help checks initially failed because boto3 was not installed in the local Python environment. A virtual environment was created outside the repository, dependencies were installed from automation/requirements.txt, and all script help checks passed before live-lab execution.

Live-lab scripts were executed only after the dedicated guardrails-readonly profile was confirmed and policy simulation showed write/admin actions as implicitDeny and required read-only actions as allowed.

Live-lab execution confirmed that the dedicated `guardrails-readonly` profile could run the four read-only assessment scripts successfully. Each script returned exit code 0 and produced no stderr output.

However, JSON validation failed for each raw output file with `Extra data`, which indicates the current `--format json` mode is not producing a single valid JSON document suitable for downstream parsing. Raw outputs remain outside the repository and were not committed.

This should be addressed in a follow-up issue to make JSON output machine-parseable for live-lab normalization and reporting.

## Live-Lab Result

Live-lab execution confirmed that the dedicated `guardrails-readonly` profile could run the four read-only assessment scripts successfully.

Each script:

- ran with the dedicated read-only AWS CLI profile
- returned exit code `0`
- produced an empty stderr log
- wrote raw output outside the repository

However, JSON validation failed for each raw output file with `Extra data`. This indicates the current `--format json` mode is not producing a single valid JSON document suitable for downstream parsing.

Raw outputs remain outside the repository and were not committed.
