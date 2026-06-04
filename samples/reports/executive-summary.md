# AWS Cloud Security Guardrails Executive Summary

Generated at: `2026-06-04T04:18:02.193640+00:00`

## Executive Overview

This report summarizes `9` normalized finding(s) from the AWS Cloud Security Guardrails automation workflow.

Overall posture: **Critical attention required**

High/Critical findings: `7`

The report is generated from local normalized JSON input. It does not call AWS APIs, does not require AWS credentials, and does not modify cloud resources.

INFO findings are excluded by default. Use `--include-info` to include them in the report.

## Findings by Severity

| Category | Count |
|---|---:|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 1 |
| LOW | 1 |

## Findings by Source

| Category | Count |
|---|---:|
| cloudtrail-coverage-check | 3 |
| public-s3-check | 3 |
| security-group-risk-check | 2 |
| iam-key-age-check | 1 |

## Affected Resource Types

| Category | Count |
|---|---:|
| cloudtrail_trail | 3 |
| s3_bucket | 2 |
| security_group | 2 |
| aws_account | 1 |
| iam_access_key | 1 |

## Top High/Critical Findings

| Severity | Source | Resource | Finding Type | Reason |
|---|---|---|---|---|
| CRITICAL | `public-s3-check` | `s3_bucket: demo-public-assets-bucket` | `public_bucket_policy` | S3 reports that the bucket policy is public. |
| CRITICAL | `security-group-risk-check` | `security_group: sg-demo0001` | `public_ssh_exposure` | Security group exposes SSH on port 22 to 0.0.0.0/0. |
| HIGH | `cloudtrail-coverage-check` | `cloudtrail_trail: ACCOUNT_REGION` | `no_multi-region_trail_found` | No CloudTrail trail returned by this region is configured as multi-region. |
| HIGH | `iam-key-age-check` | `iam_access_key: ****DEMO` | `long_lived_iam_access_key` | IAM access key for user demo-ci-user is 140 days old. Threshold is 90 days. |
| HIGH | `public-s3-check` | `aws_account: ACCOUNT_LEVEL` | `incomplete_account-level_S3_Public_Access_Block` | Account-level S3 Public Access Block exists but not all four settings are enabled. |
| HIGH | `public-s3-check` | `s3_bucket: demo-legacy-acl-bucket` | `public_ACL_grant` | Bucket ACL includes a public group grant. |
| HIGH | `security-group-risk-check` | `security_group: sg-demo0002` | `public_mysql/mariadb_exposure` | Security group exposes MySQL/MariaDB on port 3306 to 0.0.0.0/0. |

## Remediation Themes

| Theme | Count | Recommended Focus |
|---|---:|---|
| Logging and investigation readiness | 3 | Improve CloudTrail coverage, confirm multi-region management event logging, enable log file validation, and verify investigation workflows. |
| S3 public exposure risk | 3 | Enable account-level and bucket-level S3 Public Access Block, remove unintended public policies or ACLs, and document exceptions. |
| Network exposure risk | 2 | Restrict public ingress, remove broad administrative exposure, and prefer private access patterns such as VPN, bastion, or AWS Systems Manager Session Manager. |
| Credential risk | 1 | Prioritize credential rotation, key retirement, least-privilege review, and migration from long-lived keys to role-based access where possible. |

## Recommended Next Actions

1. Address critical findings first and preserve evidence before making changes.
2. Assign owners for high-severity findings and define remediation due dates.
3. Review credential findings for active exposure, rotate or retire risky keys, and confirm CloudTrail activity.
4. Review public ingress findings and restrict administrative or database exposure to approved access paths.
5. Review S3 public exposure findings and enable Public Access Block controls unless a documented exception exists.
6. Review CloudTrail coverage findings to improve audit evidence and incident investigation readiness.
7. Generate remediation tickets for validated findings and track closure evidence.

## Notes and Limitations

- This report depends on the completeness and quality of the normalized input file.
- Findings should be validated before remediation work is executed.
- Generated reports should be reviewed for sensitive environment details before sharing.
- This report does not prove remediation; it summarizes current findings and recommended actions.

