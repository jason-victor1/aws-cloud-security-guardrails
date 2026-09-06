# AWS Cloud Security Guardrails

Validation-first AWS security assessment toolkit for read-only posture review, finding normalization, remediation reporting, executive summaries, and CI-enforced guardrail validation.

## Project Status

| Area                                          | Status             |
| --------------------------------------------- | ------------------ |
| Portfolio-ready V1                            | Complete           |
| Synthetic demo workflow                       | Complete           |
| Read-only live-lab validation                 | Complete           |
| Local assessment orchestrator                 | Complete           |
| Synthetic orchestrator mode                   | Complete           |
| CI-enforced synthetic orchestrator validation | Complete           |
| Automated remediation                         | Not included in V1 |

This repository is designed as a portfolio-grade cloud security, DevSecOps, and security automation project. It focuses on safe assessment, evidence handling, and repeatable reporting rather than production remediation.

## What This Project Does

AWS Cloud Security Guardrails demonstrates a practical workflow for identifying,
assessing, and documenting common AWS security risks, with selected preventive
guardrail examples:

- long-lived IAM access keys
- risky public security group ingress
- public S3 exposure paths
- weak or incomplete CloudTrail coverage
- weak CI/CD and repository guardrails
- missing evidence trails for remediation and security assurance

The project converts assessment results into normalized findings, remediation backlog artifacts, remediation ticket JSON, and executive summaries.

## Quick Start: Synthetic Mode

Synthetic mode validates the downstream workflow without AWS credentials or live AWS API calls.

```bash
scripts/run-guardrails-assessment.sh \
  --mode synthetic \
  --output-dir ~/aws-guardrails-lab-evidence/synthetic-orchestrator-test
```

Synthetic mode uses sample fixtures from `samples/raw/`, writes generated artifacts outside the repository, validates JSON outputs, runs normalization, and generates reports.

## Live-Lab Mode

Live mode is intended for controlled read-only AWS lab validation.

```bash
scripts/run-guardrails-assessment.sh \
  --profile guardrails-readonly \
  --output-dir ~/aws-guardrails-lab-evidence/orchestrated-run \
  --region us-east-1
```

Live mode requires an explicit AWS profile and writes raw outputs, normalized findings, and generated reports outside the repository.

## Capabilities

| Capability                     | Implementation                                                                      |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| IAM access key age review      | `automation/iam-key-age-check.py`                                                   |
| Security group exposure review | `automation/security-group-risk-check.py`                                           |
| Public S3 posture review       | `automation/public-s3-check.py`                                                     |
| CloudTrail coverage review     | `automation/cloudtrail-coverage-check.py`                                           |
| Finding normalization          | `automation/finding-normalizer.py`                                                  |
| Remediation backlog generation | `automation/remediation-ticket-generator.py`                                        |
| Executive summary generation   | `automation/executive-summary-generator.py`                                         |
| Full local orchestration       | `scripts/run-guardrails-assessment.sh`                                              |
| Synthetic fixture validation   | `samples/raw/` and synthetic orchestrator mode                                      |
| Terraform guardrails           | S3 Public Access Block implementation plus design-stage concepts under `terraform/` |
| CI/CD validation               | `.github/workflows/`                                                                |
| Sanitized evidence notes       | `evidence/`                                                                         |

## Validation and CI Controls

The main branch is protected by required GitHub Actions checks:

| Check                                   | Purpose                                               |
| --------------------------------------- | ----------------------------------------------------- |
| Terraform fmt, validate, and IaC scan   | Validates Terraform and scans IaC with Checkov        |
| Gitleaks secret scan                    | Detects committed secrets                             |
| Python automation syntax check          | Compiles automation scripts                           |
| Sample JSON syntax check                | Validates sample JSON fixtures and generated JSON     |
| Synthetic demo regeneration drift check | Confirms demo outputs can be regenerated consistently |
| Local workflow processor tests          | Runs local unit tests                                 |
| Synthetic orchestrator validation       | Runs the full synthetic orchestrator pipeline in CI   |

## Safety Boundary

This project is assessment-focused. V1 does not perform automated remediation.

Do not commit:

- AWS credentials
- AWS account IDs
- real ARNs
- IAM names from real accounts
- bucket names from real accounts
- security group IDs
- VPC or subnet IDs
- CloudTrail ARNs
- raw live-lab JSON outputs
- normalized live-lab findings
- generated live-lab reports
- Terraform state
- AWS CLI credential files
- `.env` files

## Limitations and Evidence Boundaries

This repository demonstrates a controlled portfolio and lab implementation. Its
evidence should be interpreted within the following boundaries:

1. **Not a production AWS deployment.** The documented live validation used a
   controlled read-only AWS lab and does not establish production deployment,
   enterprise-scale operation, or multi-account landing-zone coverage.

2. **Assessment and reporting are the primary V1 automation scope.** Findings
   are converted into reporting and remediation-tracking artifacts for human
   review and action. V1 does not perform unattended or destructive remediation
   of AWS resources.

3. **Terraform implementation is intentionally mixed-state.** The S3 Public
   Access Block guardrail is implemented and statically validated. The
   CloudTrail, GuardDuty, Security Hub, AWS Config, budget/anomaly, and IAM
   least-privilege Terraform directories remain design-stage placeholders.

4. **The S3 Terraform guardrail was not applied in the documented live AWS
   validation.** The project therefore does not claim that this Terraform
   configuration was deployed or that it empirically prevented public S3
   exposure.

5. **Raw live AWS evidence remains private.** Raw JSON outputs, normalized live
   findings, and generated live reports are retained outside Git. Public
   evidence is intentionally sanitized.

6. **Detector validation is bounded.** The detector behavioral test suite
   validates defined representative cases, including positive and negative
   cases and an explicit IAM threshold-boundary case. It does not establish
   exhaustive correctness across all possible AWS configurations, regions,
   policies, or edge cases.

7. **Security evidence is not external assurance.** The repository supports
   security review, assurance, remediation tracking, and evidence-producing
   workflows. It does not establish formal compliance or conformity with SOC 2,
   HIPAA, NIST, or other frameworks or regulatory regimes, and it is not an
   external audit, certification, or attestation.

## Evidence and Documentation

| Resource                                                                                         | Purpose                              |
| ------------------------------------------------------------------------------------------------ | ------------------------------------ |
| [`docs/iam/read-only-assessment-policy.md`](docs/iam/read-only-assessment-policy.md)             | Read-only IAM policy guidance        |
| [`docs/iam/read-only-assessment-policy.json`](docs/iam/read-only-assessment-policy.json)         | Example read-only assessment policy  |
| [`docs/workflows/live-aws-lab-validation.md`](docs/workflows/live-aws-lab-validation.md)         | Live-lab validation workflow         |
| [`evidence/live-lab-validation/`](evidence/live-lab-validation/)                                 | Sanitized live-lab validation notes  |
| [`evidence/live-lab-reporting/`](evidence/live-lab-reporting/)                                   | Sanitized live-lab reporting notes   |
| [`docs/runbooks/credential-exposure-response.md`](docs/runbooks/credential-exposure-response.md) | Credential exposure response runbook |

## Target Use Cases

This project maps to practical cloud security and DevSecOps work:

- AWS cloud security hardening
- IAM and credential risk review
- public exposure assessment and guardrail validation
- cloud logging and security-assurance validation
- CI/CD security guardrails
- security automation reporting
- contractor/consultant evidence packages

## Repo Structure

```text
aws-cloud-security-guardrails/
  .github/workflows/
  automation/
  diagrams/
  docs/
  evidence/
  samples/
  scripts/
  terraform/
  tests/
  README.md
```

## Automation

This project includes read-only assessment and non-remediating reporting automation scripts.

| Script                                                                                   | Purpose                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [automation/iam-key-age-check.py](automation/iam-key-age-check.py)                       | Reviews IAM user access key age and flags long-lived keys without printing secret access key values.                                                                                                 |
| [automation/security-group-risk-check.py](automation/security-group-risk-check.py)       | Reviews AWS security group ingress rules and flags risky public exposure patterns such as public SSH, RDP, database, Kubernetes API, Redis, and broad port ranges.                                   |
| [automation/public-s3-check.py](automation/public-s3-check.py)                           | Reviews S3 bucket public exposure posture, including account-level and bucket-level Public Access Block, public bucket policy status, and public ACL grants.                                         |
| [automation/cloudtrail-coverage-check.py](automation/cloudtrail-coverage-check.py)       | Reviews AWS CloudTrail logging coverage, including multi-region status, logging status, log file validation, KMS metadata, management event selectors, and recent event-history lookup availability. |
| [automation/finding-normalizer.py](automation/finding-normalizer.py)                     | Normalizes JSON output from automation scripts into a consistent finding schema for evidence collection, reporting, remediation backlog creation, and future ticket generation.                      |
| [automation/remediation-ticket-generator.py](automation/remediation-ticket-generator.py) | Converts normalized findings into structured Markdown or JSON remediation tickets for backlog creation and security-assurance evidence workflows.                                                    |
| [automation/executive-summary-generator.py](automation/executive-summary-generator.py)   | Generates a client-style Markdown executive summary from normalized findings, including severity counts, top risks, affected resource types, remediation themes, and recommended next actions.       |

## Local Tests

Local tests under [tests/](tests/) include detector behavioral validation,
JSON output-contract checks, and workflow processor tests.

The detector tests exercise defined representative positive and negative cases
and an explicit IAM threshold-boundary case without requiring live AWS API
calls.

Run:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## Read-Only Assessment Policy

A read-only IAM assessment policy example is available for running the AWS posture review scripts without administrator access:

- [docs/iam/read-only-assessment-policy.md](docs/iam/read-only-assessment-policy.md)
- [docs/iam/read-only-assessment-policy.json](docs/iam/read-only-assessment-policy.json)

The policy is intended for lab and portfolio validation of the read-only scripts. It does not grant permissions to create, modify, delete, deploy, or remediate AWS resources.

## Runbooks

This project includes operational runbooks that connect guardrail detections to response workflows.

| Runbook                                                                                        | Purpose                                                                                                                                          |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| [docs/runbooks/credential-exposure-response.md](docs/runbooks/credential-exposure-response.md) | Defines the response workflow for suspected hardcoded secrets, API keys, AWS credentials, GitHub tokens, and related credential exposure events. |

## Synthetic Demo Workflow

This repository includes synthetic sample fixtures that demonstrate the end-to-end local workflow without AWS credentials or real account data.

```text
samples/raw/
→ automation/finding-normalizer.py
→ samples/normalized/normalized-findings.json
→ automation/remediation-ticket-generator.py
→ samples/reports/remediation-backlog.md
→ automation/executive-summary-generator.py
→ samples/reports/executive-summary.md
```

The full synthetic demo workflow can be regenerated with:

```bash
./scripts/regenerate-demo-outputs.sh
```

## Local Assessment Orchestrator

A local orchestrator is available for running the full AWS guardrails assessment pipeline from one command:

- [scripts/run-guardrails-assessment.sh](scripts/run-guardrails-assessment.sh)

Example:

```bash
scripts/run-guardrails-assessment.sh \
  --profile guardrails-readonly \
  --output-dir ~/aws-guardrails-lab-evidence/orchestrated-run \
  --region us-east-1
```

### Synthetic Orchestrator Mode

The local assessment orchestrator also supports a synthetic mode for validating the downstream workflow without AWS credentials or AWS API calls.

Example:

```bash
scripts/run-guardrails-assessment.sh \
  --mode synthetic \
  --output-dir ~/aws-guardrails-lab-evidence/synthetic-orchestrator-test
```

Synthetic mode uses the existing sample fixtures under `samples/raw/`, writes generated artifacts outside the repository, runs normalization and reporting, and prints a sanitized workflow-level summary.

Live mode remains available for controlled read-only AWS lab validation:

```bash
scripts/run-guardrails-assessment.sh \
  --profile guardrails-readonly \
  --output-dir ~/aws-guardrails-lab-evidence/orchestrated-run \
  --region us-east-1
```

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

## Live AWS Lab Validation

A live-lab validation guide is available for safely running the read-only AWS posture review scripts against a controlled AWS lab account:

- [`docs/workflows/live-aws-lab-validation.md`](docs/workflows/live-aws-lab-validation.md)

The guide covers pre-run safety checks, read-only profile verification, script execution order, raw output handling, redaction rules, sanitized evidence, and no-change confirmation.
