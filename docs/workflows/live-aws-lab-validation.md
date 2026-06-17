# Live AWS Lab Validation Guide

## Purpose

This guide explains how to safely validate the AWS Cloud Security Guardrails read-only assessment scripts against a controlled AWS lab account.

The goal is to confirm that the scripts can run against a real AWS environment while preserving least privilege, avoiding infrastructure changes, and preventing sensitive account data from being committed to Git.

## Scope

This guide covers live-lab validation for:

```text
automation/iam-key-age-check.py
automation/security-group-risk-check.py
automation/public-s3-check.py
automation/cloudtrail-coverage-check.py
```

These scripts are intended for read-only posture review. They should not create, modify, delete, deploy, or remediate AWS resources.

## Related Documentation

Read this first:

```text
docs/iam/read-only-assessment-policy.md
docs/iam/read-only-assessment-policy.json
```

The read-only IAM assessment policy documents the least-privilege permissions intended for running the assessment scripts without administrator access.

## Validation Goals

A successful live-lab validation should confirm:

- the assessment principal can authenticate successfully
- the read-only IAM policy supports the current scripts
- the scripts run without administrator access
- the scripts do not mutate AWS resources
- outputs can be saved outside the repository
- evidence can be sanitized for portfolio use
- no credentials, account identifiers, or raw scan outputs are committed to Git

## Required Prerequisites

Before running live-lab validation, prepare:

- a controlled AWS lab account
- a dedicated read-only assessment IAM role or IAM user
- the read-only assessment policy from `docs/iam/read-only-assessment-policy.json`
- AWS CLI installed locally
- Python 3 installed locally
- repository cloned locally
- no production AWS profiles active in the current shell
- a local evidence folder outside the repository

## Dedicated Assessment Principal

Use a dedicated assessment principal.

Recommended pattern:

```text
AWS lab account
→ dedicated read-only assessment role or IAM user
→ attach read-only assessment policy
→ configure local AWS CLI profile
→ run assessment scripts
→ store raw outputs outside Git
→ sanitize evidence before sharing
```

Do not use:

- administrator users
- root user credentials
- daily-use privileged users
- production account profiles
- credentials from unrelated projects

## Pre-Run Safety Checklist

Before running any script, confirm:

- [ ] You are using a lab account, not a production account
- [ ] You are using a dedicated assessment profile
- [ ] The assessment principal has read-only permissions only
- [ ] No administrator credentials are active in the shell
- [ ] No Terraform `apply` command will be run
- [ ] No remediation script will be run
- [ ] Raw outputs will be saved outside this repository
- [ ] Screenshots will be reviewed and redacted before sharing
- [ ] Account IDs, ARNs, bucket names, user names, access key IDs, IP addresses, and resource IDs will be sanitized before public use

## Confirm Active AWS Identity

Before running any assessment script, confirm the active identity.

Use:

```bash
aws sts get-caller-identity --profile <assessment-profile>
```

Confirm that the returned identity is the dedicated assessment principal.

Do not proceed if the identity is:

- an administrator
- a root user
- a production principal
- an unexpected IAM user or role
- an account you did not intend to assess

## Recommended Local Evidence Folder

Store live-lab outputs outside the repository.

Example:

```bash
mkdir -p ~/aws-guardrails-lab-evidence/raw
mkdir -p ~/aws-guardrails-lab-evidence/sanitized
mkdir -p ~/aws-guardrails-lab-evidence/notes
```

Do not store raw live-lab output under:

```text
samples/
evidence/
docs/
automation/
```

unless the output has been fully sanitized and intentionally prepared for public documentation.

## Recommended Script Execution Order

Run the scripts in this order:

```text
1. IAM access key age review
2. Security group risk review
3. Public S3 exposure review
4. CloudTrail coverage review
```

Reasoning:

- IAM key age review confirms credential hygiene posture first
- Security group review checks network exposure risk
- Public S3 review checks data exposure risk
- CloudTrail review checks logging and investigation readiness

## Script Help Check

Before running a script against AWS, inspect its current CLI options:

```bash
python3 automation/iam-key-age-check.py --help
python3 automation/security-group-risk-check.py --help
python3 automation/public-s3-check.py --help
python3 automation/cloudtrail-coverage-check.py --help
```

Use the profile, region, and output options supported by the current script version.

## Live-Lab Execution Template

Use the following pattern and adapt it to each script’s supported options.

```bash
python3 automation/<script-name>.py \
  --profile <assessment-profile> \
  --output ~/aws-guardrails-lab-evidence/raw/<script-output>.json
```

If a script prints to stdout instead of accepting an output flag, redirect output to the external evidence directory:

```bash
python3 automation/<script-name>.py \
  --profile <assessment-profile> \
  > ~/aws-guardrails-lab-evidence/raw/<script-output>.json
```

Do not commit these raw output files.

## Suggested Output Names

Recommended local raw output names:

```text
~/aws-guardrails-lab-evidence/raw/iam-key-age-findings.json
~/aws-guardrails-lab-evidence/raw/security-group-findings.json
~/aws-guardrails-lab-evidence/raw/public-s3-findings.json
~/aws-guardrails-lab-evidence/raw/cloudtrail-findings.json
```

## Normalize Live-Lab Outputs Locally

After raw outputs are collected, normalize them outside the repository first.

Example external normalized folder:

```bash
mkdir -p ~/aws-guardrails-lab-evidence/normalized
```

Example normalization pattern:

```bash
python3 automation/finding-normalizer.py \
  --source iam-key-age-check \
  --input ~/aws-guardrails-lab-evidence/raw/iam-key-age-findings.json \
  --output ~/aws-guardrails-lab-evidence/normalized/iam-normalized.json
```

Repeat for the other sources.

Do not commit live normalized findings unless they are fully sanitized and intentionally prepared as public evidence.

## Generate Live-Lab Reports Locally

If generating remediation tickets or executive summaries from live-lab findings, write them outside the repository first:

```bash
mkdir -p ~/aws-guardrails-lab-evidence/reports
```

Example:

```bash
python3 automation/remediation-ticket-generator.py \
  --input ~/aws-guardrails-lab-evidence/normalized/normalized-findings.json \
  --format markdown \
  --output ~/aws-guardrails-lab-evidence/reports/remediation-backlog.md
```

Example:

```bash
python3 automation/executive-summary-generator.py \
  --input ~/aws-guardrails-lab-evidence/normalized/normalized-findings.json \
  --output ~/aws-guardrails-lab-evidence/reports/executive-summary.md
```

Review and sanitize generated reports before sharing or committing.

## What Must Not Be Committed

Do not commit:

- AWS account IDs
- access keys
- secret access keys
- session tokens
- IAM user names from real accounts
- IAM role ARNs from real accounts
- access key IDs or partial access key IDs from real accounts
- real bucket names
- real security group IDs
- real VPC IDs
- real subnet IDs
- real IP allowlists
- CloudTrail trail ARNs
- CloudTrail S3 log bucket names
- raw scan outputs
- normalized findings from real accounts
- remediation tickets from real accounts
- executive reports from real accounts
- unredacted screenshots
- Terraform state
- `.env` files
- AWS CLI credential files

## Redaction Rules

Before sharing screenshots, command output, findings, tickets, or reports, redact:

| Data Type             | Redaction Example                              |
| --------------------- | ---------------------------------------------- |
| AWS account ID        | `123456789012` → `<ACCOUNT_ID>`                |
| Access key ID         | `AKIA...` → `<ACCESS_KEY_ID_REDACTED>`         |
| Secret key            | always remove completely                       |
| Session token         | always remove completely                       |
| IAM user name         | `prod-admin-user` → `<IAM_USER>`               |
| IAM role ARN          | `arn:aws:iam::...:role/...` → `<IAM_ROLE_ARN>` |
| Bucket name           | `company-prod-logs` → `<BUCKET_NAME>`          |
| Security group ID     | `sg-0123456789abcdef0` → `<SECURITY_GROUP_ID>` |
| VPC ID                | `vpc-0123456789abcdef0` → `<VPC_ID>`           |
| Public IP             | `203.0.113.10/32` → `<PUBLIC_IP_CIDR>`         |
| CloudTrail ARN        | `arn:aws:cloudtrail:...` → `<CLOUDTRAIL_ARN>`  |
| CloudTrail log bucket | `company-cloudtrail-logs` → `<LOG_BUCKET>`     |

When unsure, redact.

## Sanitized Evidence Checklist

Safe portfolio evidence can include:

- screenshot showing scripts ran successfully, with sensitive values redacted
- summary of finding counts by severity, with real resource identifiers removed
- sanitized example of normalized finding structure
- sanitized remediation backlog excerpt
- sanitized executive summary excerpt
- screenshot of read-only IAM policy attached to lab assessment principal, with account details redacted
- screenshot of GitHub Actions required checks passing
- written validation notes explaining that the run was read-only

Do not include evidence that exposes real account structure or sensitive identifiers.

## No-Change Confirmation

After running scripts, confirm no infrastructure changes were intended or performed.

Document:

```text
Validation mode: read-only
Terraform apply used: no
AWS mutation APIs used: no
Remediation performed: no
Infrastructure deployed: no
Raw outputs committed: no
```

## Post-Run Cleanup

After live-lab validation:

- remove local temporary files that are no longer needed
- keep raw outputs only in a secure local folder if needed
- sanitize any evidence before adding it to the repository
- confirm `git status` before committing documentation changes
- do not commit raw live-lab data

Run:

```bash
git status
```

Confirm only intended documentation or sanitized evidence files are staged.

## Recommended Validation Notes Template

Use this template in local notes or a sanitized evidence file:

```text
Live AWS Lab Validation Notes

Date:
AWS account type: controlled lab account
Assessment principal: dedicated read-only assessment principal
Policy used: docs/iam/read-only-assessment-policy.json
Scripts executed:
- automation/iam-key-age-check.py
- automation/security-group-risk-check.py
- automation/public-s3-check.py
- automation/cloudtrail-coverage-check.py

Validation mode: read-only
Terraform apply used: no
AWS mutation APIs used: no
Remediation performed: no
Infrastructure deployed: no
Raw outputs committed: no

Evidence captured:
- sanitized screenshots
- sanitized finding counts
- sanitized remediation summary
- sanitized executive summary excerpt

Notes:
```

## Safety Boundary

This guide is for controlled lab validation only.

Do not use this process against client, employer, production, or shared environments without explicit authorization, approved scope, and agreed handling rules for evidence and findings.

## Next Step

After completing a live-lab run, create sanitized evidence artifacts that prove:

- the assessment profile was read-only
- scripts executed successfully
- raw outputs stayed outside Git
- sensitive values were redacted
- no infrastructure changes were made
