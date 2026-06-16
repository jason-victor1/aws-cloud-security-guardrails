# Remediation Backlog

Generated at: `2026-01-01T00:00:00+00:00`

Ticket count: `9`

## Summary by Severity

| Severity | Count |
|---|---:|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 1 |
| LOW | 1 |

## Tickets

### CRITICAL

#### REM-0001-CRITICAL-PUBLIC-S3-CHECK-S3-BUCKET-PUBLIC-BUCKET-POLICY: [CRITICAL] public bucket policy on s3_bucket demo-public-assets-bucket

| Field | Value |
|---|---|
| Status | Open |
| Severity | CRITICAL |
| Source | `public-s3-check` |
| Resource Type | `s3_bucket` |
| Resource ID | `demo-public-assets-bucket` |
| Resource Name | demo-public-assets-bucket |
| Region | us-east-1 |
| Finding Type | `public_bucket_policy` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

S3 reports that the bucket policy is public.

**Recommended Remediation**

Review the bucket policy, remove unintended public principals, and confirm that account-level and bucket-level Public Access Block controls are enabled.

**Evidence Summary**

```json
{
  "bucket_name": "demo-public-assets-bucket",
  "region": "us-east-1",
  "finding_type": "public bucket policy",
  "evidence": "PolicyStatus.IsPublic=true"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

#### REM-0002-CRITICAL-SECURITY-GROUP-RISK-CHECK-SECURITY-GROUP-PUBLIC-SSH-EXPOSURE: [CRITICAL] public ssh exposure on security_group sg-demo0001

| Field | Value |
|---|---|
| Status | Open |
| Severity | CRITICAL |
| Source | `security-group-risk-check` |
| Resource Type | `security_group` |
| Resource ID | `sg-demo0001` |
| Resource Name | demo-public-admin-sg |
| Region | N/A |
| Finding Type | `public_ssh_exposure` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

Security group exposes SSH on port 22 to 0.0.0.0/0.

**Recommended Remediation**

Restrict SSH exposure to approved administrative CIDRs, use a VPN or bastion pattern if required, or prefer AWS Systems Manager Session Manager.

**Evidence Summary**

```json
{
  "group_id": "sg-demo0001",
  "group_name": "demo-public-admin-sg",
  "vpc_id": "vpc-demo0001",
  "protocol": "tcp",
  "from_port": 22,
  "to_port": 22,
  "source_type": "ipv4",
  "source": "0.0.0.0/0",
  "rule_description": "synthetic demo rule"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

### HIGH

#### REM-0003-HIGH-CLOUDTRAIL-COVERAGE-CHECK-CLOUDTRAIL-TRAIL-NO-MULTI-REGION-TRAIL-FOUND: [HIGH] no multi-region trail found on cloudtrail_trail ACCOUNT_REGION

| Field | Value |
|---|---|
| Status | Open |
| Severity | HIGH |
| Source | `cloudtrail-coverage-check` |
| Resource Type | `cloudtrail_trail` |
| Resource ID | `ACCOUNT_REGION` |
| Resource Name | ACCOUNT_REGION |
| Region | N/A |
| Finding Type | `no_multi-region_trail_found` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

No CloudTrail trail returned by this region is configured as multi-region.

**Recommended Remediation**

Configure at least one multi-region trail so activity across enabled AWS Regions is captured.

**Evidence Summary**

```json
{
  "trail_name": "ACCOUNT_REGION",
  "finding_type": "no multi-region trail found",
  "evidence": "trails_checked=1"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

#### REM-0004-HIGH-IAM-KEY-AGE-CHECK-IAM-ACCESS-KEY-LONG-LIVED-IAM-ACCESS-KEY: [HIGH] long lived iam access key on iam_access_key ****DEMO

| Field | Value |
|---|---|
| Status | Open |
| Severity | HIGH |
| Source | `iam-key-age-check` |
| Resource Type | `iam_access_key` |
| Resource ID | `****DEMO` |
| Resource Name | demo-ci-user |
| Region | N/A |
| Finding Type | `long_lived_iam_access_key` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

IAM access key for user demo-ci-user is 140 days old. Threshold is 90 days.

**Recommended Remediation**

Review whether this IAM access key is still required. Rotate or retire long-lived keys, prefer role-based access where possible, and confirm recent usage before removal.

**Evidence Summary**

```json
{
  "user_name": "demo-ci-user",
  "access_key_id_suffix": "****DEMO",
  "status": "Active",
  "age_days": 140,
  "threshold_days": 90,
  "last_used_date": "2026-05-01T10:30:00+00:00",
  "last_used_service": "s3",
  "last_used_region": "us-east-1",
  "create_date": "2025-01-15T12:00:00+00:00",
  "exceeds_threshold": true
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

#### REM-0005-HIGH-PUBLIC-S3-CHECK-AWS-ACCOUNT-INCOMPLETE-ACCOUNT-LEVEL-S3-PUBLIC-ACCESS-BLOCK: [HIGH] incomplete account-level S3 Public Access Block on aws_account ACCOUNT_LEVEL

| Field | Value |
|---|---|
| Status | Open |
| Severity | HIGH |
| Source | `public-s3-check` |
| Resource Type | `aws_account` |
| Resource ID | `ACCOUNT_LEVEL` |
| Resource Name | ACCOUNT_LEVEL |
| Region | N/A |
| Finding Type | `incomplete_account-level_S3_Public_Access_Block` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

Account-level S3 Public Access Block exists but not all four settings are enabled.

**Recommended Remediation**

Enable all four account-level S3 Public Access Block settings unless a documented exception exists.

**Evidence Summary**

```json
{
  "bucket_name": "ACCOUNT_LEVEL",
  "finding_type": "incomplete account-level S3 Public Access Block",
  "evidence": "RestrictPublicBuckets"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

#### REM-0006-HIGH-PUBLIC-S3-CHECK-S3-BUCKET-PUBLIC-ACL-GRANT: [HIGH] public ACL grant on s3_bucket demo-legacy-acl-bucket

| Field | Value |
|---|---|
| Status | Open |
| Severity | HIGH |
| Source | `public-s3-check` |
| Resource Type | `s3_bucket` |
| Resource ID | `demo-legacy-acl-bucket` |
| Resource Name | demo-legacy-acl-bucket |
| Region | us-west-2 |
| Finding Type | `public_ACL_grant` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

Bucket ACL includes a public group grant.

**Recommended Remediation**

Review the S3 exposure finding, confirm whether public access is intentional, and apply Public Access Block or least-privilege policy controls.

**Evidence Summary**

```json
{
  "bucket_name": "demo-legacy-acl-bucket",
  "region": "us-west-2",
  "finding_type": "public ACL grant",
  "evidence": "AllUsers:READ"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

#### REM-0007-HIGH-SECURITY-GROUP-RISK-CHECK-SECURITY-GROUP-PUBLIC-MYSQL-MARIADB-EXPOSURE: [HIGH] public mysql/mariadb exposure on security_group sg-demo0002

| Field | Value |
|---|---|
| Status | Open |
| Severity | HIGH |
| Source | `security-group-risk-check` |
| Resource Type | `security_group` |
| Resource ID | `sg-demo0002` |
| Resource Name | demo-db-sg |
| Region | N/A |
| Finding Type | `public_mysql/mariadb_exposure` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

Security group exposes MySQL/MariaDB on port 3306 to 0.0.0.0/0.

**Recommended Remediation**

Remove public database exposure. Restrict access to application security groups, private subnets, or approved administrative CIDRs.

**Evidence Summary**

```json
{
  "group_id": "sg-demo0002",
  "group_name": "demo-db-sg",
  "vpc_id": "vpc-demo0001",
  "protocol": "tcp",
  "from_port": 3306,
  "to_port": 3306,
  "source_type": "ipv4",
  "source": "0.0.0.0/0",
  "rule_description": "synthetic demo rule"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

### MEDIUM

#### REM-0008-MEDIUM-CLOUDTRAIL-COVERAGE-CHECK-CLOUDTRAIL-TRAIL-LOG-FILE-VALIDATION-DISABLED: [MEDIUM] log file validation disabled on cloudtrail_trail arn:aws:cloudtrail:us-east-1:...

| Field | Value |
|---|---|
| Status | Open |
| Severity | MEDIUM |
| Source | `cloudtrail-coverage-check` |
| Resource Type | `cloudtrail_trail` |
| Resource ID | `arn:aws:cloudtrail:us-east-1:123456789012:trail/demo-audit-trail` |
| Resource Name | demo-audit-trail |
| Region | us-east-1 |
| Finding Type | `log_file_validation_disabled` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

CloudTrail log file validation is not enabled for this trail.

**Recommended Remediation**

Enable CloudTrail log file validation to support integrity verification of delivered CloudTrail logs.

**Evidence Summary**

```json
{
  "trail_name": "demo-audit-trail",
  "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/demo-audit-trail",
  "home_region": "us-east-1",
  "finding_type": "log file validation disabled",
  "evidence": "LogFileValidationEnabled=False"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

### LOW

#### REM-0009-LOW-CLOUDTRAIL-COVERAGE-CHECK-CLOUDTRAIL-TRAIL-CLOUDWATCH-LOGS-DELIVERY-NOT-CONFIGURED: [LOW] CloudWatch Logs delivery not configured on cloudtrail_trail arn:aws:cloudtrail:us...

| Field | Value |
|---|---|
| Status | Open |
| Severity | LOW |
| Source | `cloudtrail-coverage-check` |
| Resource Type | `cloudtrail_trail` |
| Resource ID | `arn:aws:cloudtrail:us-east-1:123456789012:trail/demo-audit-trail` |
| Resource Name | demo-audit-trail |
| Region | us-east-1 |
| Finding Type | `CloudWatch_Logs_delivery_not_configured` |
| Normalized At | 2026-01-01T00:00:00+00:00 |
| Generated At | 2026-01-01T00:00:00+00:00 |

**Reason**

Trail does not show CloudWatch Logs delivery metadata.

**Recommended Remediation**

Review the CloudTrail coverage finding and update trail configuration to improve investigation and audit evidence readiness.

**Evidence Summary**

```json
{
  "trail_name": "demo-audit-trail",
  "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/demo-audit-trail",
  "home_region": "us-east-1",
  "finding_type": "CloudWatch Logs delivery not configured",
  "evidence": "CloudWatchLogsLogGroupArn not present"
}
```

**Closure Checklist**

- [ ] Owner assigned
- [ ] Finding validated
- [ ] Remediation plan approved
- [ ] Change implemented
- [ ] Evidence captured
- [ ] Finding retested
- [ ] Ticket closed

