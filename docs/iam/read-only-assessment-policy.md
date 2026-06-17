# Read-Only IAM Assessment Policy

## Purpose

This document defines a read-only IAM policy example for running the AWS Cloud Security Guardrails assessment scripts without administrator access.

The policy is intended for a dedicated assessment principal, such as a lab-only IAM role or IAM user, that needs to review selected AWS security posture areas without creating, modifying, deleting, or deploying cloud resources.

## Supported Scripts

This policy is designed to support the current read-only assessment scripts:

```text
automation/iam-key-age-check.py
automation/security-group-risk-check.py
automation/public-s3-check.py
automation/cloudtrail-coverage-check.py
Security Intent

The intent is least privilege for review-only assessment work.

The policy allows metadata and configuration review for:

IAM access key age and last-used metadata
EC2 security group ingress posture
S3 Public Access Block, bucket policy status, and ACL posture
CloudTrail trail coverage and event history lookup
STS caller identity confirmation

The policy should not be used as a general-purpose cloud administration policy.

Policy File

See:

docs/iam/read-only-assessment-policy.json
Permissions Summary
Area	Allowed Purpose
STS	Confirm which AWS principal is running the assessment
IAM	List IAM users, list access keys, and check access key last-used metadata
EC2	Describe Regions and security groups
S3	List buckets and review public exposure posture metadata
CloudTrail	Review trail configuration, trail status, event selectors, and event history
What This Policy Does Not Allow

This policy does not grant permissions to:

create IAM users, roles, groups, or policies
create, update, deactivate, or delete access keys
attach or detach IAM policies
create, update, or delete security groups
authorize or revoke security group ingress or egress
create, update, or delete S3 buckets
put or delete S3 bucket policies
put or delete S3 Public Access Block settings
modify S3 ACLs
create, update, start, stop, or delete CloudTrail trails
deploy infrastructure
run Terraform
remediate findings automatically
Recommended Setup

Use a dedicated assessment principal instead of an administrator user.

Recommended pattern:

Dedicated assessment role or IAM user
→ attach read-only assessment policy
→ run scripts locally or from a controlled workstation
→ export findings locally
→ normalize findings
→ generate remediation tickets
→ generate executive summary

Do not attach this policy to a daily-use administrator principal. The goal is to keep assessment activity separate from administrative change activity.

Example Setup Flow

High-level setup:

1. Create a dedicated lab assessment IAM role or IAM user.
2. Attach docs/iam/read-only-assessment-policy.json as a customer managed policy.
3. Configure a local AWS CLI profile for that assessment principal.
4. Run only the read-only assessment scripts.
5. Store raw outputs outside the repository unless using synthetic data.
6. Redact account-specific details before sharing screenshots or reports.
Local Execution Reminder

Before running live checks, confirm the active identity:

aws sts get-caller-identity --profile <assessment-profile>

Then run assessment scripts with the intended read-only profile.

Safety Notes

Do not commit:

real AWS account IDs
access keys
secret keys
session tokens
real bucket names
real security group IDs
real CloudTrail ARNs
raw scan output from real accounts
normalized findings from real accounts
remediation tickets from real accounts
executive reports from real accounts

Use synthetic fixtures under samples/ for public demo output.

Lab Use Only Until Validated

This policy is a V1 read-only assessment policy example for lab and portfolio use.

Validate it in a controlled AWS lab account before using it in any shared, client, employer, or production environment.

If scripts are changed to call additional AWS APIs, update this policy and review the permissions again before running the updated scripts.

Relationship to Existing Guardrails

This policy supports assessment and evidence collection only. It does not deploy or enforce guardrails.

Preventive controls, such as the S3 Public Access Block Terraform guardrail, should remain separate from read-only assessment permissions.
