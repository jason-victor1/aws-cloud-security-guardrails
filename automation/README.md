# Automation Scripts

This directory contains detection-only automation scripts for the **AWS Cloud Security Guardrails** project.

## IAM Access Key Age Review

### Script

```text
automation/iam-key-age-check.py
```

### Purpose

Detect long-lived IAM user access keys that may increase credential exposure risk.

### Security Model

This script is detection-only and uses a read-only security model:

- Read-only IAM API calls
- No key creation
- No key rotation
- No key deletion
- No secret access key values printed
- Access key IDs are masked to suffix only

### Usage

Run the script with the default threshold:

```bash
python automation/iam-key-age-check.py --threshold-days 90 --format table
```

Run the script with an AWS profile:

```bash
python automation/iam-key-age-check.py --profile lab-profile --threshold-days 90 --format table
```

Generate JSON output:

```bash
python automation/iam-key-age-check.py --threshold-days 90 --format json
```

Include access-key last-used metadata:

```bash
python automation/iam-key-age-check.py --threshold-days 90 --include-last-used
```

### Exit Codes

| Code | Meaning                                 |
| ---: | --------------------------------------- |
|    0 | No keys exceeded the threshold          |
|    1 | One or more keys exceeded the threshold |
|    2 | Runtime or AWS configuration error      |

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "*"
    }
  ]
}
```

### Security Warning

Do not commit AWS credentials, profile files, access keys, secret keys, account IDs, or output containing sensitive environment details.

## Security Group Risk Review

Script:

```text
automation/security-group-risk-check.py
```

Purpose:

Detect risky public ingress rules in AWS security groups.

Security model:

- read-only EC2 API calls
- no security group creation
- no security group modification
- no ingress rule revocation
- no egress rule modification
- no infrastructure deployment

Usage:

```bash
python automation/security-group-risk-check.py --region us-east-1 --format table
```

With an AWS profile:

```bash
python automation/security-group-risk-check.py --profile lab-profile --region us-east-1 --format table
```

JSON output:

```bash
python automation/security-group-risk-check.py --region us-east-1 --format json
```

Include informational HTTP/HTTPS findings:

```bash
python automation/security-group-risk-check.py --region us-east-1 --include-info
```

Fail with exit code `1` when findings are detected:

```bash
python automation/security-group-risk-check.py --region us-east-1 --fail-on-findings
```

Risk categories include:

- public SSH exposure
- public RDP exposure
- public database exposure
- public Kubernetes API exposure
- public Redis exposure
- public Elasticsearch/OpenSearch exposure
- all-port public exposure
- broad public port ranges
- informational HTTP/HTTPS exposure when `--include-info` is used

Exit codes:

| Code | Meaning                                             |
| ---: | --------------------------------------------------- |
|    0 | Script completed successfully                       |
|    1 | Findings detected and `--fail-on-findings` was used |
|    2 | Runtime or AWS configuration error                  |

Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:DescribeSecurityGroups"],
      "Resource": "*"
    }
  ]
}
```

Do not commit AWS credentials, profile files, access keys, secret keys, account IDs, or output containing sensitive environment details.

## Public S3 Exposure Review

Script:

```text
automation/public-s3-check.py
```

Purpose:

Review S3 bucket public exposure posture and report risky bucket-level configurations.

Security model:

- read-only S3 API calls
- read-only S3 Control API calls
- read-only STS identity lookup if `--account-id` is not supplied
- no object reads
- no object downloads
- no bucket creation
- no bucket modification
- no bucket policy changes
- no infrastructure deployment

Usage:

```bash
python automation/public-s3-check.py --format table
```

With an AWS profile:

```bash
python automation/public-s3-check.py --profile lab-profile --format table
```

With an explicit account ID:

```bash
python automation/public-s3-check.py --account-id <ACCOUNT_ID> --format table
```

JSON output:

```bash
python automation/public-s3-check.py --format json
```

Fail with exit code `1` when high or critical findings are detected:

```bash
python automation/public-s3-check.py --fail-on-findings
```

Risk categories include:

- missing account-level S3 Public Access Block
- incomplete account-level S3 Public Access Block
- missing bucket-level S3 Public Access Block
- incomplete bucket-level S3 Public Access Block
- public bucket policy
- public ACL grant
- unable to evaluate account or bucket configuration

Exit codes:

| Code | Meaning                                                              |
| ---: | -------------------------------------------------------------------- |
|    0 | Script completed successfully                                        |
|    1 | High or critical findings detected and `--fail-on-findings` was used |
|    2 | Runtime or AWS configuration error                                   |

Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:HeadBucket",
        "s3control:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Do not commit AWS credentials, profile files, access keys, secret keys, account IDs, bucket contents, or output containing sensitive environment details.

## CloudTrail Logging Coverage Review

Script:

```text
automation/cloudtrail-coverage-check.py
```

Purpose:

Review AWS CloudTrail logging coverage and report gaps that could weaken incident investigation and audit evidence.

Security model:

- read-only CloudTrail API calls
- no trail creation
- no trail modification
- no logging start/stop actions
- no trail deletion
- no CloudTrail log object reads
- no infrastructure deployment

Usage:

```bash
python automation/cloudtrail-coverage-check.py --region us-east-1 --format table
```

With an AWS profile:

```bash
python automation/cloudtrail-coverage-check.py --profile lab-profile --region us-east-1 --format table
```

JSON output:

```bash
python automation/cloudtrail-coverage-check.py --region us-east-1 --format json
```

Include informational event-history lookup result:

```bash
python automation/cloudtrail-coverage-check.py --region us-east-1 --include-info
```

Skip the event-history lookup check:

```bash
python automation/cloudtrail-coverage-check.py --region us-east-1 --skip-event-history-check
```

Fail with exit code `1` when high or critical findings are detected:

```bash
python automation/cloudtrail-coverage-check.py --region us-east-1 --fail-on-findings
```

Risk categories include:

- no trails found
- trail is not logging
- no multi-region trail found
- log file validation disabled
- KMS encryption key not configured
- CloudWatch Logs delivery not configured
- unable to retrieve trail status
- unable to retrieve event selectors
- management events not enabled
- management event coverage may be incomplete
- CloudTrail LookupEvents unavailable

Exit codes:

| Code | Meaning                                                              |
| ---: | -------------------------------------------------------------------- |
|    0 | Script completed successfully                                        |
|    1 | High or critical findings detected and `--fail-on-findings` was used |
|    2 | Runtime or AWS configuration error                                   |

Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

Do not commit AWS credentials, profile files, access keys, secret keys, account IDs, CloudTrail log contents, or output containing sensitive environment details.

## Finding Normalizer

Script:

```text
automation/finding-normalizer.py
```

Purpose:

Normalize JSON output from AWS Cloud Security Guardrails automation scripts into a consistent finding schema for evidence collection, reporting, remediation backlog creation, and future ticket generation.

Security model:

- no AWS API calls
- no AWS credentials required
- no cloud resource modification
- reads local JSON input only
- writes normalized JSON to stdout or an optional output file

Supported sources:

- `iam-key-age-check`
- `security-group-risk-check`
- `public-s3-check`
- `cloudtrail-coverage-check`

Usage:

```bash
python automation/finding-normalizer.py \
  --source security-group-risk-check \
  --input sg-findings.json
```

Auto-detect source from input shape:

```bash
python automation/finding-normalizer.py \
  --source auto \
  --input cloudtrail-findings.json
```

Write normalized output to a file:

```bash
python automation/finding-normalizer.py \
  --source public-s3-check \
  --input s3-findings.json \
  --output normalized-s3-findings.json
```

Normalized finding schema:

```json
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
      "recommendation": "Restrict SSH exposure to approved administrative CIDRs, use a VPN or bastion pattern if required, or prefer AWS Systems Manager Session Manager.",
      "evidence": {
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "source": "0.0.0.0/0"
      },
      "original_finding": {}
    }
  ]
}
```

Do not commit AWS credentials, account IDs, access keys, secret keys, profiles, Terraform state, scan outputs, or normalized findings that contain sensitive environment details.

## Remediation Ticket Generator

Script:

```text
automation/remediation-ticket-generator.py
```

Purpose:

Convert normalized security findings into structured remediation backlog tickets.

Security model:

- no AWS API calls
- no AWS credentials required
- no cloud resource modification
- no automatic GitHub Issue creation in V1
- reads local normalized JSON input only
- writes Markdown or JSON output to stdout or an optional output file

Expected input:

```text
Normalized JSON output from automation/finding-normalizer.py
```

Usage:

```bash
python automation/remediation-ticket-generator.py \
  --input normalized-findings.json \
  --format markdown
```

Write Markdown tickets to a file:

```bash
python automation/remediation-ticket-generator.py \
  --input normalized-findings.json \
  --format markdown \
  --output remediation-backlog.md
```

Write JSON tickets to a file:

```bash
python automation/remediation-ticket-generator.py \
  --input normalized-findings.json \
  --format json \
  --output remediation-tickets.json
```

Include informational findings:

```bash
python automation/remediation-ticket-generator.py \
  --input normalized-findings.json \
  --format markdown \
  --include-info
```

Generated ticket fields include:

- ticket ID
- title
- severity
- status
- source
- resource type
- resource ID
- resource name
- region
- finding type
- reason
- recommendation
- evidence summary
- closure checklist

Do not commit AWS credentials, account IDs, access keys, secret keys, profiles, Terraform state, raw scan outputs, normalized findings, or generated remediation tickets that contain sensitive environment details.

## Executive Summary Report Generator

Script:

```text
automation/executive-summary-generator.py
```

Purpose:

Generate a client-style Markdown executive summary from normalized security findings.

Security model:

- no AWS API calls
- no AWS credentials required
- no cloud resource modification
- no infrastructure deployment
- reads local normalized JSON input only
- writes Markdown to stdout or an optional output file

Expected input:

```text
Normalized JSON output from automation/finding-normalizer.py
```

Usage:

```bash
python automation/executive-summary-generator.py \
  --input normalized-findings.json
```

Write the report to a file:

```bash
python automation/executive-summary-generator.py \
  --input normalized-findings.json \
  --output executive-summary.md
```

Set a custom report title:

```bash
python automation/executive-summary-generator.py \
  --input normalized-findings.json \
  --title "AWS Security Assessment Executive Summary"
```

Include informational findings:

```bash
python automation/executive-summary-generator.py \
  --input normalized-findings.json \
  --include-info
```

Report sections include:

- executive overview
- overall posture label
- findings by severity
- findings by source
- affected resource types
- top high/critical findings
- remediation themes
- recommended next actions
- notes and limitations

Do not commit AWS credentials, account IDs, access keys, secret keys, profiles, Terraform state, raw scan outputs, normalized findings, remediation tickets, or generated reports that contain sensitive environment details.
