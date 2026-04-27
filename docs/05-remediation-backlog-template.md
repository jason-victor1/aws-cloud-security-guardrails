# Remediation Backlog Template

| ID | Finding | Severity | Owner | Affected Resource | Recommended Fix | Evidence | Status | Due Date |
|---|---|---|---|---|---|---|---|---|
| FINDING-001 | Public S3 bucket allows read access | High | Platform | `aws_s3_bucket.example` | Enable S3 Block Public Access | `sample-findings.json` | Open | TBD |
| FINDING-002 | IAM user has old access key | Medium | Security | `iam_user.demo` | Rotate key and migrate to role-based access | `iam-key-age-report.json` | Open | TBD |
| FINDING-003 | Security group exposes SSH to internet | High | Infrastructure | `sg-123456` | Restrict ingress to approved source range | `security-group-risk-report.json` | Open | TBD |

## Backlog Rules

- Every finding must have an owner.
- Every high-severity finding must have a remediation plan.
- Findings affecting public exposure or privileged access should be prioritized first.
- Evidence must be attached before a finding is marked closed.
