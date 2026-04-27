# Threat Model

## Scope

This threat model covers common AWS cloud security failure modes that can be detected or reduced through guardrails, CI/CD controls, IAM reviews, and lightweight automation.

## Assets

| Asset | Why it matters |
|---|---|
| AWS access keys | Can be abused to access data or create resources |
| IAM roles and policies | Control blast radius and privilege boundaries |
| S3 buckets | Common source of accidental public exposure |
| Security groups | Can expose sensitive services to the internet |
| CloudTrail logs | Needed for investigation and accountability |
| GitHub repositories | Source of IaC, app code, and possible secrets |
| CI/CD tokens | Can be abused to alter deployments or access cloud resources |
| Budget and cost controls | Reduce impact of compromised credentials |

## Threats

| Threat | Attack Path | Control Response |
|---|---|---|
| Leaked AWS key | Key committed to GitHub or exposed in app/frontend asset | CI secrets scanning, key rotation runbook, IAM least privilege |
| Public S3 exposure | Bucket allows public read/write access | S3 public access block, IaC checks |
| Over-permissive IAM | Wildcard permissions allow broad access or privilege escalation | IAM policy review, least-privilege examples |
| Missing CloudTrail | Attacker activity cannot be reconstructed | CloudTrail all-region Terraform baseline |
| Weak security groups | Public ingress exposes admin services or databases | Security group risk scanner |
| CI/CD token abuse | GitHub Actions token or deployment secret is compromised | Restricted permissions, branch protection, artifact integrity checks |
| Cost abuse | Compromised credentials used for crypto mining or resource abuse | Budget alerts, anomaly detection, rapid key revoke runbook |
| Compliance evidence gap | Controls exist but cannot be proven | Evidence checklist, control matrix, remediation report |

## Abuse Cases

### Abuse Case 1: Leaked Developer AWS Key

1. Developer commits an AWS access key.
2. Attacker discovers the key.
3. Attacker enumerates permissions.
4. Attacker creates expensive resources or accesses data.
5. Organization lacks rapid revoke and evidence workflow.

### Abuse Case 2: Overly Open Security Group

1. Terraform creates a security group with broad ingress.
2. CI/CD does not block the change.
3. Sensitive service becomes reachable from the internet.
4. Attacker probes and attempts exploitation.

### Abuse Case 3: Missing CloudTrail Coverage

1. Attacker performs suspicious AWS actions.
2. Logs are missing in one or more regions.
3. Security team cannot reconstruct the timeline.
4. Remediation and disclosure are delayed.

## V1 Threat-Model Constraints

V1 focuses on detection, prevention, and evidence. It does not perform destructive auto-remediation.
