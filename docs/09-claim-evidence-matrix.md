# Claim-Evidence Matrix

## Purpose

This matrix maps the material claims made by the AWS Cloud Security Guardrails
project to the evidence that supports them.

The matrix is intended to keep project claims bounded by demonstrated,
validated, observed, or designed project state. It does not establish external
audit, certification, regulatory compliance, or production assurance.

## Claim Classification

### Claim Maturity

- **Designed** — documented design or intended control exists, but implementation
  has not been established.
- **Implemented** — the capability exists in the project.
- **Validated** — the capability has been exercised against a defined validation
  procedure.
- **Demonstrated** — validation evidence is inspectable or reproducible by a
  reviewer.

### Evidence Basis

- **Tested** — a defined procedure or test produced supporting evidence.
- **Observed** — the supporting state can be directly inspected in project
  artifacts or repository configuration.
- **Documentation-supported** — supported primarily by authoritative
  documentation.
- **Design inference** — supported by design reasoning rather than implementation
  evidence.
- **Unverified** — sufficient supporting evidence has not been established.

### Evidence Visibility

- **Public** — directly available in the repository or public project history.
- **Sanitized** — public evidence derived from sensitive/private source material
  with identifying details removed.
- **Private** — retained outside the public repository.
- **None** — no retained evidence.

## Material Claim-Evidence Matrix

| ID   | Claim                                                                                                                                                                                                                                                                     | Claim Maturity | Evidence Basis | Evidence Visibility | Evidence                                                                                                                                                                                                                                              | Limitation                                                                                                                                   |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | -------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| C-01 | Synthetic assessment mode exercises the downstream assessment and reporting workflow without requiring AWS credentials or live AWS API calls.                                                                                                                             | Demonstrated   | Tested         | Public              | `scripts/run-guardrails-assessment.sh`; repository synthetic validation tests and CI                                                                                                                                                                  | Synthetic execution does not establish live AWS behavior.                                                                                    |
| C-02 | The controlled live AWS assessment used a dedicated read-only assessment principal after representative write or administrative actions were denied and required read actions were allowed.                                                                               | Demonstrated   | Tested         | Sanitized           | `evidence/live-lab-validation/validation-notes.md`; `docs/iam/read-only-assessment-policy.json`                                                                                                                                                       | Controlled lab validation only; not an exhaustive least-privilege proof or production IAM design.                                            |
| C-03 | The IAM key-age, security-group, S3-posture, and CloudTrail assessment scripts executed successfully in the controlled read-only AWS lab and wrote their raw outputs outside the repository.                                                                              | Demonstrated   | Tested         | Sanitized           | `evidence/live-lab-validation/validation-notes.md`                                                                                                                                                                                                    | Establishes controlled live execution and output generation, not exhaustive detector correctness.                                            |
| C-04 | Controlled live execution exposed a JSON serialization defect in the original `--format json` output path.                                                                                                                                                                | Demonstrated   | Tested         | Sanitized           | `evidence/live-lab-validation/validation-notes.md`                                                                                                                                                                                                    | Demonstrates one observed implementation defect; it does not identify every possible failure mode.                                           |
| C-05 | After the JSON output correction, live detector outputs were successfully consumed through normalization and downstream reporting workflows.                                                                                                                              | Demonstrated   | Tested         | Sanitized           | `evidence/live-lab-reporting/reporting-validation-notes.md`                                                                                                                                                                                           | Validated against the documented controlled-lab workflow and inputs, not every possible input schema or AWS state.                           |
| C-06 | The documented live reporting workflow processed five normalized findings and generated downstream reporting artifacts outside Git.                                                                                                                                       | Demonstrated   | Tested         | Sanitized           | `evidence/live-lab-reporting/reporting-validation-notes.md`                                                                                                                                                                                           | One controlled validation workflow; does not establish production-scale reporting capacity.                                                  |
| C-07 | The project contains an implemented S3 Public Access Block Terraform guardrail defining the four Public Access Block settings.                                                                                                                                            | Implemented    | Observed       | Public              | `terraform/s3-public-access-block/`; `docs/03-control-matrix.md`                                                                                                                                                                                      | Configuration existence does not establish deployment or runtime prevention.                                                                 |
| C-08 | The S3 Public Access Block Terraform implementation passes the project's defined static Terraform and IaC validation.                                                                                                                                                     | Validated      | Tested         | Public              | `terraform/s3-public-access-block/`; repository Terraform/IaC CI validation                                                                                                                                                                           | Static validation only; the guardrail was not applied during the documented live AWS validation.                                             |
| C-09 | Pull requests to the protected `main` branch were observed running seven required GitHub Actions checks covering Terraform/IaC validation, secrets scanning, Python validation, JSON validation, demo-regeneration validation, synthetic orchestration, and unit testing. | Demonstrated   | Observed       | Public              | GitHub PR #64 and PR #65; repository workflow definitions                                                                                                                                                                                             | Evidence is tied to the observed repository configuration and pull requests; future branch-protection configuration can change.              |
| C-10 | Raw real-account validation outputs and generated live reports are retained outside Git while sanitized validation evidence is published in the repository.                                                                                                               | Demonstrated   | Tested         | Sanitized           | `evidence/live-lab-validation/validation-notes.md`; `evidence/live-lab-validation/redaction-notes.md`; `evidence/live-lab-reporting/reporting-validation-notes.md`; `evidence/live-lab-reporting/redaction-notes.md`; `docs/08-evidence-checklist.md` | This evidence-handling model is not an external chain-of-custody system, audit attestation, or regulatory evidence package.                  |
| C-11 | The CloudTrail, GuardDuty, Security Hub, AWS Config, budget/anomaly, and IAM least-privilege Terraform directories represent design-stage concepts rather than implemented baselines.                                                                                     | Designed       | Observed       | Public              | `terraform/cloudtrail-all-region/`; `terraform/guardduty-baseline/`; `terraform/security-hub-baseline/`; `terraform/aws-config-baseline/`; `terraform/budget-and-anomaly-alerts/`; `terraform/iam-least-privilege-demo/`; `docs/03-control-matrix.md` | Directory presence does not establish implementation, deployment, or validation.                                                             |
| C-12 | The four AWS posture detectors classify the defined representative behavioral cases in `tests/test_detector_behavior.py` as expected, including positive and negative cases and an explicit IAM threshold-boundary case.                                                  | Demonstrated   | Tested         | Public              | `tests/test_detector_behavior.py`; GitHub PR #64 required CI; merged `main`                                                                                                                                                                           | Defined deterministic cases only; does not establish exhaustive correctness across all AWS configurations, policies, regions, or edge cases. |

## Evidence Boundary

The evidence in this project supports only the bounded claims stated above.

In particular:

- successful live execution does not by itself establish exhaustive detector
  correctness;
- passing deterministic behavioral tests does not establish correctness across
  every possible AWS state or edge case;
- static Terraform validation does not establish successful deployment or
  runtime prevention;
- design-stage Terraform concepts are not implemented controls;
- sanitized evidence does not substitute for an external audit or attestation;
- project evidence does not establish formal compliance with SOC 2, HIPAA,
  NIST, or another framework or regulatory regime.

## Reviewer Verification

A reviewer can inspect or reproduce material portions of the evidence through:

- repository source code and Terraform configuration;
- deterministic local tests under `tests/`;
- repository-defined GitHub Actions validation;
- sanitized live-lab validation notes;
- sanitized live-lab reporting validation notes;
- control-state documentation in `docs/03-control-matrix.md`.

Raw real-account evidence is intentionally retained outside the public
repository.

## Maintenance

This matrix should be reviewed when a material claim changes, when its evidence
basis changes, or when new validation materially strengthens or weakens the
claim.

A new capability should not be assigned or promoted to a Claim Maturity solely
because it appears elsewhere in project documentation. Its maturity should
remain bounded by the supporting project evidence.
