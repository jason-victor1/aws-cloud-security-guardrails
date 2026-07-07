# Live AWS Lab Validation Evidence

This directory contains sanitized evidence notes for the AWS Cloud Security Guardrails live-lab validation milestone.

## Purpose

The purpose of this evidence set is to document that the read-only AWS posture review workflow was validated in a controlled AWS lab account using least-privilege assessment permissions.

## Evidence Boundary

This directory must contain sanitized notes only.

Do not commit:

- AWS account IDs
- access keys
- secret access keys
- session tokens
- IAM user names from real accounts
- IAM role ARNs from real accounts
- real bucket names
- real security group IDs
- real VPC IDs
- real subnet IDs
- real IP allowlists
- real CloudTrail ARNs
- raw scan outputs
- normalized findings from real accounts
- remediation tickets from real accounts
- executive reports from real accounts
- unredacted screenshots
- Terraform state
- AWS CLI credential files
- `.env` files

## Files

    evidence/live-lab-validation/
      README.md
      validation-notes.md
      redaction-notes.md

## Validation Mode

- Validation mode: read-only
- Terraform apply used: no
- AWS mutation/remediation APIs intentionally used: no
- Infrastructure deployed: no
- Raw outputs committed: no

## Related Documentation

- `docs/workflows/live-aws-lab-validation.md`
- `docs/iam/read-only-assessment-policy.md`
- `docs/iam/read-only-assessment-policy.json`

