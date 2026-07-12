# Changelog

## v1.0.0 - Portfolio Release

### Added

- Read-only AWS assessment scripts for:
  - IAM access key age review
  - security group public ingress review
  - public S3 exposure review
  - CloudTrail coverage review
- Finding normalization workflow
- Remediation backlog generation
- Remediation ticket JSON generation
- Executive summary generation
- Synthetic sample fixtures
- Synthetic demo output regeneration script
- Local assessment orchestrator
- Synthetic orchestrator mode
- Live AWS lab validation guide
- Read-only IAM assessment policy example
- Sanitized live-lab validation evidence
- Sanitized live-lab reporting evidence
- Credential exposure response runbook

### CI and Validation

- Terraform formatting, validation, and Checkov IaC scanning
- Gitleaks secret scanning
- Python automation syntax validation
- Sample JSON syntax validation
- Synthetic demo regeneration drift check
- Local workflow processor unit tests
- Synthetic orchestrator validation workflow

### Security Boundaries

- No automated remediation in v1.0
- Live-lab raw outputs remain outside the repository
- Normalized live-lab findings remain outside the repository
- Generated live-lab reports remain outside the repository
- Repository evidence is sanitized and workflow-level only
