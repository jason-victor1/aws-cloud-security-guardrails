# Live-Lab Reporting Redaction Notes

## Purpose

This document records the redaction and non-commit rules used for the live-lab reporting validation milestone.

## Redaction Rules

| Data Type | Handling |
|---|---|
| AWS account ID | Redacted or omitted |
| AWS credentials | Never committed |
| Access key ID | Redacted or omitted |
| Secret access key | Never committed |
| Session token | Never committed |
| IAM user name | Redacted or omitted |
| IAM role ARN | Redacted or omitted |
| Bucket name | Redacted or omitted |
| Security group ID | Redacted or omitted |
| VPC ID | Redacted or omitted |
| Subnet ID | Redacted or omitted |
| Public IP or CIDR | Redacted or omitted |
| CloudTrail ARN | Redacted or omitted |
| CloudTrail log bucket | Redacted or omitted |
| Raw finding body | Not committed |
| Normalized live finding | Not committed |
| Live remediation ticket | Not committed |
| Live executive report | Not committed |

## Explicit Non-Commit Confirmation

The following were not committed:

- [x] AWS credentials
- [x] AWS account IDs
- [x] real ARNs
- [x] real IAM names
- [x] real bucket names
- [x] real security group IDs
- [x] real VPC/subnet IDs
- [x] real CloudTrail ARNs
- [x] raw live-lab JSON outputs
- [x] normalized live-lab findings
- [x] combined normalized live-lab findings
- [x] remediation backlog from the real account
- [x] remediation ticket JSON from the real account
- [x] executive summary from the real account
- [x] unredacted screenshots
- [x] Terraform state
- [x] AWS CLI credential files
- [x] `.env` files

## Review Result

```text
Sensitive values reviewed before commit: yes
Generated live-lab reports committed: no
Evidence sanitized for repository use: yes
```
