# Control Matrix

| Control Area | Risk | Guardrail | Evidence Artifact |
|---|---|---|---|
| IAM keys | Long-lived keys may be leaked or abused | Detect old keys, unused keys, and missing MFA | IAM key-age report |
| IAM permissions | Over-permissive policies increase blast radius | Flag wildcard `Action:*` and `Resource:*` | IAM policy review output |
| S3 exposure | Public buckets may expose sensitive data | Block public access baseline | Terraform config + scan result |
| Security groups | Overly open ingress creates attack surface | Flag `0.0.0.0/0` on risky ports | Security group risk report |
| Logging | Missing logs weaken detection and investigation | CloudTrail all-region baseline | CloudTrail evidence output |
| Detection | Missing GuardDuty/Security Hub reduces visibility | Enable detection services | GuardDuty/Security Hub baseline |
| AWS Config | Missing config history weakens compliance evidence | Enable AWS Config baseline | Config recorder evidence |
| CI/CD secrets | Secrets may enter repositories or pipelines | Gitleaks/checks in CI | GitHub Actions scan result |
| IaC misconfig | Bad Terraform can deploy insecure resources | Checkov/Trivy IaC scan | CI scan artifact |
| Cost abuse | Leaked keys may trigger cloud spend spikes | Budget/anomaly alert baseline | Budget alert config |
| Remediation | Findings may not be tracked to closure | Remediation backlog template | CSV/Markdown backlog |

## Control Prioritization Criteria

Findings should be prioritized by:

1. public exposure
2. credential abuse potential
3. privilege level
4. data sensitivity
5. exploitability
6. detection coverage
7. remediation complexity
8. compliance impact
