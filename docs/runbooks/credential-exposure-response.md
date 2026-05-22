# Credential Exposure Response Runbook

## Purpose

This runbook defines the response workflow for suspected credential exposure, including hardcoded secrets, API keys, tokens, AWS access keys, GitHub tokens, and other sensitive values detected by Gitleaks or another secrets-scanning control.

This runbook supports the AWS Cloud Security Guardrails project by connecting detection to response:

```text
secret detected
→ validate safely
→ triage severity
→ revoke or rotate
→ investigate possible misuse
→ preserve evidence
→ create remediation backlog
→ prevent recurrence
```

## Scope

This runbook applies to suspected exposure of:

- AWS access keys
- AWS session tokens
- GitHub personal access tokens
- GitHub Actions secrets
- API keys
- cloud provider credentials
- service account credentials
- database passwords
- private keys
- webhook URLs
- authentication tokens
- other sensitive values detected in source code, documentation, logs, pull requests, or CI output

## Out of Scope

This runbook does not cover:

- full incident response program design
- malware investigation
- endpoint forensics
- legal breach determination
- customer notification decisions
- production auto-remediation
- live AWS containment without human approval

## Security Rules

Never paste secret values into:

- GitHub issues
- pull requests
- commit messages
- Slack/Teams messages
- screenshots
- documentation
- logs
- tickets
- AI tools
- public forums

When documenting a secret, refer only to safe metadata such as:

```text
secret type
source file path
commit hash
line number
detector name
affected system
credential owner
revocation status
```

Do not include the secret value itself.

## Trigger Sources

This runbook may be triggered by:

- Gitleaks finding in GitHub Actions
- manual code review
- GitHub secret scanning alert
- AWS GuardDuty credential finding
- CloudTrail anomaly
- unexpected AWS billing activity
- developer report
- exposed `.env` file
- leaked Terraform variable file
- pasted secret in documentation or chat
- public repository exposure

## Severity Model

| Severity      | Condition                                                                        | Example                                                        |
| ------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Critical      | Confirmed active production credential exposed publicly or used suspiciously     | AWS key committed to public repo and CloudTrail shows activity |
| High          | Active credential exposed in private repo, PR, CI log, or internal documentation | AWS key detected in pull request                               |
| Medium        | Expired, revoked, or fake-looking credential pattern with unclear validity       | Old token detected in archived file                            |
| Low           | Clearly fake sample secret with safe placeholder context                         | `example_api_key = "replace-me"`                               |
| Informational | Scanner false positive with documented rationale                                 | Random string matched token pattern                            |

## Response Phases

1. Detection
2. Safe validation
3. Triage
4. Containment
5. Investigation
6. Recovery
7. Evidence preservation
8. Remediation backlog
9. Prevention

---

# 1. Detection

## Gitleaks Detection

When Gitleaks reports a finding, collect only safe metadata:

```text
finding ID
scanner rule
file path
line number
commit hash
branch
pull request number
secret type
author if available
timestamp
```

Do not copy the secret value into the ticket or documentation.

## Initial Detection Checklist

- [ ] Identify detector source
- [ ] Identify affected file path
- [ ] Identify affected branch or commit
- [ ] Identify suspected secret type
- [ ] Confirm whether the repository is public or private
- [ ] Confirm whether the finding came from a pull request, existing history, or new commit
- [ ] Avoid exposing the secret value during investigation

---

# 2. Safe Validation

The purpose of validation is to determine whether the finding is likely real without spreading the secret.

## Validation Rules

Do:

- review scanner metadata
- review the file context
- determine whether the value resembles a real credential
- determine whether the value is in current code or Git history
- determine whether the credential owner/system can be identified
- validate through the owning platform when safe

Do not:

- paste the secret into a terminal unless required by an approved response process
- test the secret against production services
- use the secret to authenticate
- share the secret with others
- copy the secret into notes or tickets

## Validation Outcomes

| Outcome                 | Meaning                                            | Next Action                                |
| ----------------------- | -------------------------------------------------- | ------------------------------------------ |
| Confirmed active secret | Secret is valid or presumed valid                  | Contain immediately                        |
| Likely secret           | Strong pattern match but validity unknown          | Treat as active until disproven            |
| Historical secret       | Secret appears in Git history but not current code | Revoke/rotate if not already done          |
| False positive          | Value is not a secret                              | Document rationale and close               |
| Safe placeholder        | Value is intentionally fake                        | Replace with clearer placeholder if needed |

---

# 3. Triage

Use this triage flow:

```text
Is the credential active?
  yes → Critical/High
  unknown → High until proven otherwise
  no → Medium/Low depending on exposure

Is the repository public?
  yes → increase severity
  no → evaluate internal exposure

Does the credential provide cloud, production, billing, CI/CD, or data access?
  yes → increase severity

Is there evidence of use after exposure?
  yes → Critical
```

## Triage Checklist

- [ ] Is the credential active?
- [ ] Is the repo public or private?
- [ ] Is the secret in current code or Git history?
- [ ] Does the credential grant AWS/cloud access?
- [ ] Does the credential grant GitHub or CI/CD access?
- [ ] Does the credential grant production/data access?
- [ ] Was the secret exposed in CI logs?
- [ ] Was the secret copied into an issue, PR, or comment?
- [ ] Is there suspicious activity after exposure?
- [ ] Is there potential cloud cost abuse?

---

# 4. Containment

Containment should happen quickly once a credential is confirmed or likely real.

## General Containment Steps

- [ ] Identify credential owner/system
- [ ] Revoke or disable credential
- [ ] Rotate replacement credential if required
- [ ] Remove secret from active code
- [ ] Remove secret from CI/CD variables if compromised
- [ ] Confirm applications using the credential still function after rotation
- [ ] Preserve evidence before destructive cleanup
- [ ] Create remediation ticket

## AWS Access Key Containment

For suspected AWS access key exposure:

- [ ] Identify IAM user or principal
- [ ] Disable the exposed access key
- [ ] Rotate the access key if still required
- [ ] Prefer replacing long-lived keys with IAM roles where possible
- [ ] Review attached IAM policies
- [ ] Check for administrative or wildcard permissions
- [ ] Review recent CloudTrail activity
- [ ] Check for new resources created after exposure
- [ ] Check for billing anomalies
- [ ] Confirm no unauthorized users, roles, policies, or access keys were created

## GitHub Token Containment

For suspected GitHub token exposure:

- [ ] Revoke the token
- [ ] Rotate dependent automation secrets
- [ ] Review token scopes
- [ ] Review recent repository activity
- [ ] Review GitHub Actions workflow changes
- [ ] Review branch protection settings
- [ ] Review new deploy keys or webhooks
- [ ] Review organization audit logs if available

## API Key Containment

For suspected third-party API key exposure:

- [ ] Revoke or rotate the API key
- [ ] Review account usage logs
- [ ] Review billing or quota usage
- [ ] Restrict key scopes if supported
- [ ] Restrict source IPs, referrers, or service accounts if supported
- [ ] Update applications with new credential securely
- [ ] Confirm old credential no longer works

---

# 5. AWS Investigation Checklist

Use this section for suspected AWS credential exposure.

## CloudTrail Review

Review CloudTrail for the exposed principal.

Look for:

- `GetCallerIdentity`
- `ListBuckets`
- `ListUsers`
- `ListRoles`
- `ListPolicies`
- `CreateUser`
- `CreateAccessKey`
- `AttachUserPolicy`
- `PutUserPolicy`
- `CreateRole`
- `AssumeRole`
- `RunInstances`
- `CreateBucket`
- `PutBucketPolicy`
- `AuthorizeSecurityGroupIngress`
- `CreateLoginProfile`
- `UpdateAssumeRolePolicy`
- `DeleteTrail`
- `StopLogging`
- `PutEventSelectors`

## Investigation Questions

- [ ] Was the credential used after exposure?
- [ ] Which source IPs used the credential?
- [ ] Which AWS regions show activity?
- [ ] Were new IAM users, roles, policies, or keys created?
- [ ] Were security groups modified?
- [ ] Were S3 buckets accessed or modified?
- [ ] Were compute resources launched?
- [ ] Were logs disabled or modified?
- [ ] Were billing alarms triggered?
- [ ] Was GuardDuty enabled?
- [ ] Did GuardDuty report credential misuse?
- [ ] Was CloudTrail enabled in all regions?

## Cost-Abuse Review

Check for:

- sudden EC2 usage
- GPU instance launches
- unusual regional usage
- new RDS databases
- new NAT gateways
- large data transfer
- unexplained storage growth
- unexpected marketplace subscriptions
- new IAM activity tied to resource creation

Document:

```text
time window reviewed
services checked
regions checked
billing changes found
resources created
resources terminated
remaining open questions
```

---

# 6. Recovery

Recovery ensures the environment returns to a safe operating state.

## Recovery Checklist

- [ ] Confirm exposed credential is revoked
- [ ] Confirm replacement credential is stored securely
- [ ] Confirm application/service functionality
- [ ] Confirm no unauthorized resources remain
- [ ] Confirm no unauthorized IAM principals remain
- [ ] Confirm logging is enabled
- [ ] Confirm detection controls are enabled
- [ ] Confirm Gitleaks passes after cleanup
- [ ] Confirm remediation ticket is updated
- [ ] Confirm evidence is preserved

---

# 7. Evidence Preservation

Preserve evidence before cleanup where possible.

## Evidence to Capture

- Gitleaks finding metadata
- file path and commit hash
- pull request number
- branch name
- timestamp of detection
- credential type
- revocation timestamp
- rotation timestamp
- CloudTrail query summary
- suspicious API calls if any
- billing/cost review summary
- screenshots of relevant security console status
- remediation actions taken
- final validation result

## Evidence Log Template

```markdown
## Credential Exposure Evidence Log

### Detection

- Detection source:
- Date/time detected:
- Repository:
- Branch:
- Pull request:
- File path:
- Commit hash:
- Secret type:
- Secret value recorded? No

### Triage

- Severity:
- Active credential suspected? Yes/No/Unknown
- Public exposure? Yes/No
- Production access? Yes/No/Unknown
- Cloud access? Yes/No/Unknown

### Containment

- Credential revoked? Yes/No
- Revocation time:
- Credential rotated? Yes/No
- Rotation time:
- Owner notified? Yes/No

### Investigation

- CloudTrail reviewed? Yes/No/N/A
- Billing reviewed? Yes/No/N/A
- Unauthorized activity found? Yes/No/Unknown
- Summary:

### Recovery

- Secret removed from active code? Yes/No
- Secret removed from Git history? Yes/No/Deferred
- Gitleaks passing? Yes/No
- Follow-up tickets:
```

---

# 8. Remediation Backlog

Every confirmed or likely credential exposure should create remediation work.

## Example Backlog Items

| ID      | Finding                                   | Severity | Owner       | Recommended Fix                                  | Evidence                               | Status |
| ------- | ----------------------------------------- | -------- | ----------- | ------------------------------------------------ | -------------------------------------- | ------ |
| SEC-001 | AWS access key detected in pull request   | High     | Security    | Revoke key, rotate credential, review CloudTrail | Gitleaks metadata + CloudTrail summary | Open   |
| SEC-002 | Long-lived IAM key used by automation     | Medium   | Platform    | Replace with role-based access                   | IAM review output                      | Open   |
| SEC-003 | Secret committed to documentation         | Medium   | Engineering | Remove secret, rewrite docs with placeholder     | PR diff                                | Open   |
| SEC-004 | No branch protection for secrets scanning | Medium   | DevSecOps   | Require Gitleaks workflow before merge           | GitHub settings evidence               | Open   |

---

# 9. Prevention

After containment and recovery, reduce recurrence.

## Preventive Controls

- Enable Gitleaks in pull request CI
- Add pre-commit secrets scanning
- Use `.env.example` placeholders
- Keep `.env` files out of Git
- Avoid long-lived IAM users
- Prefer IAM roles over static access keys
- Rotate credentials regularly
- Use AWS Secrets Manager or approved secret store
- Use least privilege for CI/CD credentials
- Restrict GitHub Actions token permissions
- Require branch protection
- Require security workflow checks before merge
- Train developers on secret-handling rules

## Safe Placeholder Examples

Use placeholders like:

```text
AWS_ACCESS_KEY_ID="replace-with-access-key-id"
AWS_SECRET_ACCESS_KEY="replace-with-secret-access-key"
API_KEY="replace-with-api-key"
DATABASE_URL="replace-with-database-url"
TOKEN="replace-with-token"
```

Do not use realistic-looking fake secrets unless required for a scanner test, and never use real credentials.

---

# 10. Communication Guidance

## Internal Security Update Template

```text
A suspected credential exposure was detected by secrets scanning.

Current status:
- Secret type: [type only, no secret value]
- Source: [file path / PR / commit]
- Severity: [severity]
- Containment: [revoked/rotated/in progress]
- Investigation: [CloudTrail/billing/GitHub logs reviewed or pending]
- Next steps: [remediation actions]

No secret values are included in this update.
```

## Developer Follow-Up Template

```text
A secret-like value was detected in your change.

Please do not repost or paste the secret value.

Required actions:
1. Confirm whether this was a real credential or safe placeholder.
2. If real or uncertain, revoke/rotate the credential.
3. Replace the value with a safe placeholder.
4. Confirm the secret is not present in current code or documentation.
5. Rerun the secrets scan.

Security will help review CloudTrail, billing, and related evidence if cloud access may be involved.
```

---

# 11. Closure Criteria

A credential exposure case can be closed when:

- [ ] credential is revoked or confirmed fake
- [ ] replacement credential is stored securely if needed
- [ ] source code/documentation no longer contains the secret
- [ ] CI secrets scan passes
- [ ] CloudTrail/GitHub/API usage reviewed where applicable
- [ ] billing/cost abuse reviewed where applicable
- [ ] evidence log is completed
- [ ] remediation backlog items are created
- [ ] preventive action is documented

---

# Related Project Documentation

- [`../08-evidence-checklist.md`](../08-evidence-checklist.md)
- [`../05-remediation-backlog-template.md`](../05-remediation-backlog-template.md)
- [`../07-incident-response-runbook.md`](../07-incident-response-runbook.md)
