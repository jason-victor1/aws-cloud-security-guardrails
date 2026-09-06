# Threat Model

## Scope

This threat model covers common AWS cloud security failure modes addressed by
the project's implemented assessment and CI/CD capabilities, selected preventive
guardrail implementation, and design-stage control concepts.

Threat disposition reflects the **current V1 project state**, not target-state
architecture or future implementation intent.

## Disposition Definitions

- **Mitigated** — an implemented and validated control materially reduces the
  threat within the documented scope.
- **Partially mitigated** — implemented controls reduce part of the threat, but
  meaningful residual risk remains.
- **Detected** — implemented controls can identify defined threat conditions,
  but the project does not claim prevention or automatic remediation.
- **Accepted** — the risk is explicitly retained without additional treatment.
- **Deferred** — treatment is intentionally postponed beyond the current V1
  implementation.
- **Out of scope** — the threat or treatment is explicitly excluded from the
  current project.

A `Detected` disposition does not imply prevention. A `Partially mitigated`
disposition does not imply elimination of the underlying risk.

## Assets

| Asset                    | Why it matters                                               |
| ------------------------ | ------------------------------------------------------------ |
| AWS access keys          | Can be abused to access data or create resources             |
| IAM roles and policies   | Control blast radius and privilege boundaries                |
| S3 buckets               | Common source of accidental public exposure                  |
| Security groups          | Can expose sensitive services to the internet                |
| CloudTrail logs          | Needed for investigation and accountability                  |
| GitHub repositories      | Source of IaC, app code, and possible secrets                |
| CI/CD tokens             | Can be abused to alter deployments or access cloud resources |
| Budget and cost controls | Reduce impact of compromised credentials                     |

## Threats

| Threat                  | Attack Path                                                                                          | Current Control Response                                                                                         | Disposition         | Current-State Basis                                                                                                                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Leaked AWS key          | Key committed to GitHub or exposed in app/frontend asset                                             | Gitleaks pull-request scanning, IAM access-key age assessment, credential-response guidance                      | Partially mitigated | Repository secret scanning and access-key review reduce exposure and response risk, but they do not prevent all credential compromise or misuse. IAM least-privilege Terraform remains design-stage. |
| Public S3 exposure      | Bucket policy, ACL, or access configuration permits unintended public access                         | Read-only S3 posture assessment; S3 Public Access Block Terraform guardrail; Terraform/Checkov static validation | Detected            | Public-exposure conditions can be identified. The preventive S3 Terraform guardrail is implemented and statically validated, but it was not applied in the documented live AWS validation.           |
| Over-permissive IAM     | Wildcard or excessive permissions allow broad access or privilege escalation                         | IAM least-privilege Terraform concept                                                                            | Deferred            | V1 does not implement a general IAM policy-analysis or wildcard-permission detector. The least-privilege Terraform directory remains a design placeholder.                                           |
| Missing CloudTrail      | Attacker activity cannot be reconstructed because trail coverage or logging is missing or incomplete | Read-only CloudTrail coverage assessment                                                                         | Detected            | The implemented detector evaluates defined CloudTrail coverage and logging conditions. The all-region CloudTrail Terraform baseline remains design-stage and unvalidated.                            |
| Weak security groups    | Public ingress exposes administrative, database, or other sensitive services                         | Read-only security-group exposure assessment                                                                     | Detected            | The implemented detector identifies defined risky public-ingress conditions. V1 does not automatically modify or remediate security groups.                                                          |
| CI/CD token abuse       | GitHub Actions token or deployment secret is compromised or misused                                  | Restricted workflow permissions, Gitleaks scanning, required pull-request checks                                 | Partially mitigated | Repository controls reduce several secret-exposure and unauthorized-change paths, but they do not eliminate CI/CD credential compromise or abuse.                                                    |
| Cost abuse              | Compromised credentials are used for crypto mining or unintended resource creation                   | Credential-response guidance; budget and anomaly-alerting Terraform concept                                      | Deferred            | The dedicated budget and anomaly-alerting control remains design-stage and unvalidated in V1.                                                                                                        |
| Compliance evidence gap | Security controls or validation activity cannot be supported with traceable evidence                 | Control matrix, sanitized validation evidence, reporting workflow, evidence-handling process                     | Partially mitigated | V1 provides evidence-producing and traceability mechanisms for security review, but does not claim external audit, certification, regulatory attestation, or complete compliance coverage.           |

## Abuse Cases

### Abuse Case 1: Leaked Developer AWS Key

1. Developer commits an AWS access key.
2. Attacker discovers the key.
3. Attacker enumerates permissions.
4. Attacker creates expensive resources or accesses data.
5. Organization lacks rapid revoke and evidence workflow.

### Abuse Case 2: Overly Open Security Group

1. Terraform creates a security group with broad ingress.
2. CI/CD does not block or identify the risky change.
3. Sensitive service becomes reachable from the internet.
4. Attacker probes and attempts exploitation.

### Abuse Case 3: Missing CloudTrail Coverage

1. Attacker performs suspicious AWS actions.
2. Logs are missing in one or more regions.
3. Security team cannot reconstruct the timeline.
4. Remediation and disclosure are delayed.

## V1 Threat-Model Constraints

V1 is primarily an assessment, validation, reporting, and evidence-producing
project.

The project includes selected preventive controls, including an implemented and
statically validated S3 Public Access Block Terraform guardrail, but the
documented live AWS validation did not apply that Terraform configuration.

Design-stage Terraform directories are not treated as active threat
mitigations.

V1 does not perform unattended or destructive remediation of AWS resources.

Threat dispositions describe the current evidenced project state and should
be revised if implementation or validation evidence materially changes.
