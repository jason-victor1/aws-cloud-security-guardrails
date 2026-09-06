# Control Matrix

This matrix distinguishes controls and project elements that are currently
implemented from those that remain design-stage or out of scope.

The matrix uses the project's evidence taxonomy:

- **Build State**
  - `Designed` — security intent or design exists, but executable implementation
    is not present.
  - `Implemented` — executable code, configuration, workflow, or other working
    implementation exists.
  - `Deferred` — intentionally postponed beyond the current project scope.
  - `Out of scope` — explicitly excluded from the current project.

- **Verification State**
  - `Unvalidated` — no defined validation has been completed.
  - `Simulated` — behavior has been exercised through simulation or synthetic
    inputs.
  - `Validated` — defined validation procedures or tests have passed.
  - `Demonstrated` — validated behavior is supported by inspectable or
    reproducible execution evidence.
  - `Not applicable` — verification does not apply to an out-of-scope element.

A `Demonstrated` assessment or detection capability does not imply exhaustive
correctness across every possible AWS configuration. Validation claims are
limited to the documented live-lab, synthetic, CI, and deterministic test cases.

| Control Area                   | Risk                                                                                              | Current Project Element                                                     | Build State  | Verification State | Evidence                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------ | ------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| IAM access keys                | Long-lived access keys may increase credential-abuse exposure                                     | Read-only IAM access-key age assessment                                     | Implemented  | Demonstrated       | `automation/iam-key-age-check.py`; `tests/test_detector_behavior.py`; sanitized live-lab evidence                                 |
| IAM permissions                | Over-permissive IAM policies may increase blast radius                                            | IAM least-privilege Terraform concept                                       | Designed     | Unvalidated        | `terraform/iam-least-privilege-demo/` design placeholder                                                                          |
| S3 exposure assessment         | Public policies, ACLs, or incomplete Public Access Block settings may increase data-exposure risk | Read-only S3 public-exposure posture assessment                             | Implemented  | Demonstrated       | `automation/public-s3-check.py`; `tests/test_detector_behavior.py`; sanitized live-lab evidence                                   |
| S3 preventive guardrail        | Accidental public access may expose S3 buckets or objects                                         | S3 Public Access Block Terraform guardrail                                  | Implemented  | Validated          | `terraform/s3-public-access-block/`; Terraform fmt/validate; Checkov static analysis                                              |
| Security groups                | Public ingress on risky ports or broad ranges may increase network attack surface                 | Read-only security-group exposure assessment                                | Implemented  | Demonstrated       | `automation/security-group-risk-check.py`; `tests/test_detector_behavior.py`; sanitized live-lab evidence                         |
| CloudTrail coverage            | Missing or incomplete logging may weaken detection and investigation                              | Read-only CloudTrail coverage assessment                                    | Implemented  | Demonstrated       | `automation/cloudtrail-coverage-check.py`; `tests/test_detector_behavior.py`; sanitized live-lab evidence                         |
| CloudTrail preventive baseline | Incomplete trail configuration may weaken organization-wide audit coverage                        | All-region CloudTrail Terraform concept                                     | Designed     | Unvalidated        | `terraform/cloudtrail-all-region/` design placeholder                                                                             |
| Threat detection services      | Missing managed threat-detection services may reduce security visibility                          | GuardDuty baseline concept                                                  | Designed     | Unvalidated        | `terraform/guardduty-baseline/` design placeholder                                                                                |
| Security findings aggregation  | Lack of centralized findings may reduce security visibility and workflow consistency              | Security Hub baseline concept                                               | Designed     | Unvalidated        | `terraform/security-hub-baseline/` design placeholder                                                                             |
| Configuration history          | Missing configuration history may weaken investigation and assurance evidence                     | AWS Config baseline concept                                                 | Designed     | Unvalidated        | `terraform/aws-config-baseline/` design placeholder                                                                               |
| CI/CD secrets                  | Secrets committed to source control may expose credentials or tokens                              | Gitleaks pull-request scanning                                              | Implemented  | Demonstrated       | `.github/workflows/gitleaks.yml`; successful required PR checks                                                                   |
| IaC validation                 | Invalid or insecure Terraform may introduce infrastructure defects or misconfiguration            | Terraform fmt/validate plus Checkov static analysis in CI                   | Implemented  | Demonstrated       | `.github/workflows/terraform-validate.yml`; successful required PR checks                                                         |
| Cost abuse                     | Compromised credentials or unintended resources may create unexpected cloud spend                 | Budget and anomaly-alerting Terraform concept                               | Designed     | Unvalidated        | `terraform/budget-and-anomaly-alerts/` design placeholder                                                                         |
| Finding remediation workflow   | Security findings may not be consistently prioritized or tracked                                  | Remediation backlog and ticket generation                                   | Implemented  | Demonstrated       | `automation/remediation-ticket-generator.py`; synthetic and controlled live reporting workflow                                    |
| Security reporting             | Technical findings may not be communicated consistently to stakeholders                           | Finding normalization and executive-summary generation                      | Implemented  | Demonstrated       | `automation/finding-normalizer.py`; `automation/executive-summary-generator.py`; synthetic and controlled live reporting workflow |
| Evidence handling              | Raw cloud evidence may expose account-specific information or lose traceability                   | Raw live evidence retained outside Git with sanitized public evidence notes | Implemented  | Demonstrated       | `evidence/live-lab-validation/`; `evidence/live-lab-reporting/`; documented evidence-handling workflow                            |
| Automated remediation          | Unattended changes could create excessive blast radius or unintended service impact               | Automated AWS remediation                                                   | Out of scope | Not applicable     | V1 explicitly limits automation to assessment and reporting                                                                       |

## Current-State Boundaries

### Implemented and demonstrated

The current project demonstrates:

- read-only IAM access-key age assessment
- read-only security-group exposure assessment
- read-only S3 public-exposure posture assessment
- read-only CloudTrail coverage assessment
- finding normalization
- remediation backlog and ticket generation
- executive-summary generation
- synthetic end-to-end workflow execution
- controlled read-only live-lab execution
- CI/CD validation and secret scanning
- sanitized evidence handling

The four AWS posture detectors have also been exercised with deterministic
representative behavioral tests, including positive and negative cases and an
explicit IAM threshold-boundary case, under
`tests/test_detector_behavior.py`.

These tests validate only the defined cases in the suite. They do not establish
exhaustive detector correctness across all AWS services, configurations,
policies, regions, or edge cases.

### Implemented and statically validated

The S3 Public Access Block Terraform guardrail is implemented and passes the
project's defined Terraform and IaC static-validation workflow.

The documented V1 validation did **not** apply this Terraform configuration to
the controlled live AWS lab. Therefore, the project does not claim that the
Terraform guardrail was deployed or that public S3 exposure was empirically
prevented by that deployment.

### Designed but unvalidated

The following Terraform directories currently represent design intent rather
than implemented baselines:

- `terraform/aws-config-baseline/`
- `terraform/budget-and-anomaly-alerts/`
- `terraform/cloudtrail-all-region/`
- `terraform/guardduty-baseline/`
- `terraform/iam-least-privilege-demo/`
- `terraform/security-hub-baseline/`

Their presence documents intended control areas. It does not establish that
those controls were built, deployed, or validated.

### Out of scope

V1 does not perform unattended or destructive remediation of AWS resources.
Assessment findings are converted into reporting and remediation-tracking
artifacts for human review and action.

## Control Prioritization Criteria

Findings should be prioritized by:

1. public exposure
2. credential abuse potential
3. privilege level
4. data sensitivity
5. exploitability
6. detection coverage
7. remediation complexity
8. compliance or assurance impact
