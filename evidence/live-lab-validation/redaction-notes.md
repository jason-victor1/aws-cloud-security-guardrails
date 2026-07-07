# Live AWS Lab Redaction Notes

## Purpose

This document records the redaction rules used before committing sanitized live-lab validation evidence.

The goal is to preserve validation value while preventing sensitive AWS account, identity, network, resource, and finding data from entering the repository.

## Redaction Boundary

Only sanitized notes may be committed to this repository.

Raw live-lab outputs must remain outside the repository.

## Data Removed or Replaced

The following data types must be removed or replaced before evidence is committed:

| Data Type | Required Treatment |
|---|---|
| AWS account IDs | Replace with `<ACCOUNT_ID_REDACTED>` |
| IAM user names | Replace with `<IAM_USER_REDACTED>` |
| IAM role ARNs | Replace with `<IAM_ROLE_ARN_REDACTED>` |
| STS caller ARN | Replace with `<ASSESSMENT_PRINCIPAL_ARN_REDACTED>` |
| User IDs | Replace with `<USER_ID_REDACTED>` |
| Access key IDs | Replace with `<ACCESS_KEY_ID_REDACTED>` |
| Secret access keys | Remove entirely |
| Session tokens | Remove entirely |
| Bucket names | Replace with `<BUCKET_NAME_REDACTED>` |
| Security group IDs | Replace with `<SECURITY_GROUP_ID_REDACTED>` |
| VPC IDs | Replace with `<VPC_ID_REDACTED>` |
| Subnet IDs | Replace with `<SUBNET_ID_REDACTED>` |
| IP addresses and CIDR ranges | Replace with `<IP_OR_CIDR_REDACTED>` |
| CloudTrail ARNs | Replace with `<CLOUDTRAIL_ARN_REDACTED>` |
| Raw scan outputs | Do not commit |
| Normalized real-account findings | Do not commit |
| Screenshots | Commit only if fully redacted |
| Terraform state | Do not commit |
| AWS credential files | Do not commit |
| Environment files | Do not commit |

## Approved Sanitized Evidence

The following sanitized evidence types may be committed:

- High-level validation notes
- Checklist completion status
- Sanitized command patterns
- Redacted identity confirmation notes
- Sanitized script execution status
- Sanitized finding counts
- No-change confirmation
- Redaction methodology notes

## Prohibited Evidence

The following evidence types must not be committed:

- Raw AWS CLI output
- Raw boto3 output
- Full JSON scan output from real accounts
- Real account identifiers
- Real resource identifiers
- Real IAM principal names
- Real network allowlists
- Unredacted screenshots
- Terraform state files
- AWS credential files
- `.env` files

## Review Checklist

Before committing evidence, confirm:

- [ ] No AWS account IDs are present
- [ ] No access keys are present
- [ ] No secret keys are present
- [ ] No session tokens are present
- [ ] No real IAM user names are present
- [ ] No real IAM role ARNs are present
- [ ] No real bucket names are present
- [ ] No real security group IDs are present
- [ ] No real VPC or subnet IDs are present
- [ ] No real IP allowlists are present
- [ ] No raw scan outputs are present
- [ ] No Terraform state files are present
- [ ] No AWS credential files are present
- [ ] No `.env` files are present

## Redaction Confirmation

Redaction review completed: `<yes/no>`

Reviewer notes:

Add sanitized notes here.

