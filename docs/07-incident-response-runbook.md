# Incident Response Runbook: Suspected AWS Credential Exposure

## Trigger Conditions

Use this runbook when:

- an AWS access key is found in GitHub
- a secret scanner flags AWS credentials
- suspicious AWS API activity is detected
- unexpected cloud spend appears
- GuardDuty reports credential misuse

## Immediate Actions

1. Identify the exposed credential.
2. Disable or revoke the key.
3. Identify the IAM principal and attached permissions.
4. Review CloudTrail activity for the principal.
5. Check for new resources, users, roles, policies, and access keys.
6. Review billing and budget anomalies.
7. Preserve evidence.

## Investigation Checklist

- Was the key active?
- What permissions did it have?
- Was it used after exposure?
- Which regions show activity?
- Were new resources created?
- Was data accessed?
- Were logs modified?
- Was cost abuse observed?

## Containment

- Disable exposed keys.
- Rotate related credentials.
- Remove excessive IAM permissions.
- Block public exposure if found.
- Add or update budget alerts.

## Recovery

- Replace long-lived access keys with role-based access where possible.
- Add CI/CD secrets scanning.
- Add key age monitoring.
- Update developer guidance.
- Record evidence and lessons learned.

## Evidence to Collect

- secret scanner output
- IAM user/role policy output
- CloudTrail events
- billing/cost anomaly data
- remediation actions
- screenshots or CLI outputs
