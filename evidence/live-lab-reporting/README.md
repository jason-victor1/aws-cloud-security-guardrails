# Live-Lab Reporting Evidence

This directory contains sanitized evidence notes for the live-lab reporting validation milestone.

## Purpose

This evidence set documents that downstream reporting processors were validated against live-lab AWS assessment JSON outputs while keeping real-account outputs and generated reports outside the repository.

## Evidence Boundary

This directory contains sanitized workflow-level notes only.

Do not commit:

- raw live-lab JSON outputs
- normalized live-lab findings
- combined normalized findings
- remediation backlog generated from a real account
- remediation ticket JSON generated from a real account
- executive summary generated from a real account
- AWS credentials
- AWS account IDs
- real ARNs
- real IAM names
- real bucket names
- real security group IDs
- real VPC or subnet IDs
- real CloudTrail ARNs
- unredacted screenshots

## Files

```text
evidence/live-lab-reporting/
  README.md
  reporting-validation-notes.md
  redaction-notes.md
```

## Related Issues

- Issue #46: live AWS lab validation and sanitized evidence
- Issue #48: JSON output mode fix for live AWS assessment scripts
- Issue #50: normalized live-lab reporting workflow validation
