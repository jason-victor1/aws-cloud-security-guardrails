# Assessment Methodology

## Purpose

This methodology defines a repeatable AWS cloud security review workflow.

## Assessment Stages

### 1. Inventory

Collect account, region, service, IAM, logging, and CI/CD context.

### 2. Identity and Credential Review

Review:

- IAM users
- access keys
- MFA coverage
- admin policies
- wildcard permissions
- unused credentials
- role trust policies

### 3. Public Exposure Review

Review:

- S3 public access
- security groups
- public IP exposure
- database exposure
- overly broad network rules

### 4. Logging and Detection Review

Review whether the environment has:

- CloudTrail enabled in all regions
- GuardDuty enabled
- Security Hub enabled
- AWS Config enabled
- centralized log retention

### 5. CI/CD and IaC Review

Review:

- Terraform validation
- IaC scanning
- secrets scanning
- GitHub Actions permissions
- branch protection
- deployment approval controls

### 6. Findings Normalization

Normalize findings into a shared schema:

```json
{
  "id": "FINDING-001",
  "title": "Public S3 bucket detected",
  "severity": "High",
  "domain": "Public Exposure",
  "resource": "aws_s3_bucket.example",
  "risk": "Sensitive data may be exposed",
  "recommended_fix": "Enable S3 Block Public Access",
  "evidence": "scan-output.json",
  "owner": "platform-team",
  "status": "open"
}
```

### 7. Remediation Backlog

Convert findings into owner-ready remediation work.

### 8. Evidence Pack

Produce:

- executive summary
- control matrix
- remediation backlog
- technical findings
- screenshots or CLI outputs
- runbook references
