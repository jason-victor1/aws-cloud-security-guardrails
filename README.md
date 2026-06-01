# AWS Cloud Security Guardrails

## Purpose

This project demonstrates a practical AWS cloud security guardrails workflow for identifying and reducing common cloud security risks:

- leaked credentials
- over-permissive IAM
- public exposure
- missing logging and detection coverage
- weak CI/CD controls
- cloud cost-abuse risk
- weak compliance evidence

The project is designed as a portfolio-grade lab for cloud security, DevSecOps, and security automation contract work.

## Problem

Many AWS security failures come from preventable control gaps:

- long-lived or leaked AWS access keys
- overly permissive IAM policies
- public S3 buckets or exposed network paths
- missing CloudTrail, GuardDuty, Security Hub, or AWS Config coverage
- weak GitHub Actions and CI/CD token hygiene
- no repeatable evidence trail for remediation or audit readiness

## What This Lab Builds

This lab includes:

- Terraform security baselines
- CI/CD security checks
- AWS identity and exposure review scripts
- sample findings
- remediation backlog templates
- executive summary template
- control matrix
- incident response runbook
- audit evidence checklist

## Target Buyer Problems

This project maps to contractor needs in:

- AWS cloud security hardening
- DevSecOps / CI/CD security
- security automation
- IAM and credential risk reduction
- compliance evidence readiness

## Repo Structure

```text
aws-cloud-security-guardrails/
  README.md
  docs/
  terraform/
  github-actions/
  automation/
  sample-findings/
  diagrams/
```

## Automation

This project includes detection-only automation scripts.

| Script                                                                               | Purpose                                                                                                                                                                                              |
| ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`automation/iam-key-age-check.py`](automation/iam-key-age-check.py)                 | Reviews IAM user access key age and flags long-lived keys without printing secret access key values.                                                                                                 |
| [`automation/security-group-risk-check.py`](automation/security-group-risk-check.py) | Reviews AWS security group ingress rules and flags risky public exposure patterns such as public SSH, RDP, database, Kubernetes API, Redis, and broad port ranges.                                   |
| [`automation/public-s3-check.py`](automation/public-s3-check.py)                     | Reviews S3 bucket public exposure posture, including account-level and bucket-level Public Access Block, public bucket policy status, and public ACL grants.                                         |
| [`automation/cloudtrail-coverage-check.py`](automation/cloudtrail-coverage-check.py) | Reviews AWS CloudTrail logging coverage, including multi-region status, logging status, log file validation, KMS metadata, management event selectors, and recent event-history lookup availability. |

## Runbooks

This project includes operational runbooks that connect guardrail detections to response workflows.

| Runbook                                                                                          | Purpose                                                                                                                                          |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`docs/runbooks/credential-exposure-response.md`](docs/runbooks/credential-exposure-response.md) | Defines the response workflow for suspected hardcoded secrets, API keys, AWS credentials, GitHub tokens, and related credential exposure events. |

## Project Phases

### Phase 0: Documentation Skeleton

Create the project charter, architecture, threat model, control matrix, assessment methodology, and remediation templates.

### Phase 1: Terraform Security Baselines

Build reusable AWS guardrail modules for CloudTrail, GuardDuty, Security Hub, AWS Config, S3 public access blocking, IAM least privilege examples, and budget/anomaly alerts.

### Phase 2: CI/CD Security Checks

Add GitHub Actions workflows for Terraform validation, IaC scanning, and secrets scanning.

### Phase 3: Python Assessment Scripts

Create small review scripts for IAM key age, public S3 exposure, risky security groups, and normalized findings.

### Phase 4: Evidence and Reporting

Produce sample findings, remediation backlog, executive summary, and evidence checklist.

## Portfolio Value

This project demonstrates the ability to move from cloud security findings to automated guardrails, remediation evidence, and business-readable reporting.
