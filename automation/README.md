# Automation Scripts

This directory contains detection-only automation scripts for the **AWS Cloud Security Guardrails** project.

## IAM Access Key Age Review

### Script

```text
automation/iam-key-age-check.py
```

### Purpose

Detect long-lived IAM user access keys that may increase credential exposure risk.

### Security Model

This script is detection-only and uses a read-only security model:

- Read-only IAM API calls
- No key creation
- No key rotation
- No key deletion
- No secret access key values printed
- Access key IDs are masked to suffix only

### Usage

Run the script with the default threshold:

```bash
python automation/iam-key-age-check.py --threshold-days 90 --format table
```

Run the script with an AWS profile:

```bash
python automation/iam-key-age-check.py --profile lab-profile --threshold-days 90 --format table
```

Generate JSON output:

```bash
python automation/iam-key-age-check.py --threshold-days 90 --format json
```

Include access-key last-used metadata:

```bash
python automation/iam-key-age-check.py --threshold-days 90 --include-last-used
```

### Exit Codes

| Code | Meaning                                 |
| ---: | --------------------------------------- |
|    0 | No keys exceeded the threshold          |
|    1 | One or more keys exceeded the threshold |
|    2 | Runtime or AWS configuration error      |

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "*"
    }
  ]
}
```

### Security Warning

Do not commit AWS credentials, profile files, access keys, secret keys, account IDs, or output containing sensitive environment details.

## Security Group Risk Review

Script:

```text
automation/security-group-risk-check.py
```

Purpose:

Detect risky public ingress rules in AWS security groups.

Security model:

- read-only EC2 API calls
- no security group creation
- no security group modification
- no ingress rule revocation
- no egress rule modification
- no infrastructure deployment

Usage:

```bash
python automation/security-group-risk-check.py --region us-east-1 --format table
```

With an AWS profile:

```bash
python automation/security-group-risk-check.py --profile lab-profile --region us-east-1 --format table
```

JSON output:

```bash
python automation/security-group-risk-check.py --region us-east-1 --format json
```

Include informational HTTP/HTTPS findings:

```bash
python automation/security-group-risk-check.py --region us-east-1 --include-info
```

Fail with exit code `1` when findings are detected:

```bash
python automation/security-group-risk-check.py --region us-east-1 --fail-on-findings
```

Risk categories include:

- public SSH exposure
- public RDP exposure
- public database exposure
- public Kubernetes API exposure
- public Redis exposure
- public Elasticsearch/OpenSearch exposure
- all-port public exposure
- broad public port ranges
- informational HTTP/HTTPS exposure when `--include-info` is used

Exit codes:

| Code | Meaning                                             |
| ---: | --------------------------------------------------- |
|    0 | Script completed successfully                       |
|    1 | Findings detected and `--fail-on-findings` was used |
|    2 | Runtime or AWS configuration error                  |

Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:DescribeSecurityGroups"],
      "Resource": "*"
    }
  ]
}
```

Do not commit AWS credentials, profile files, access keys, secret keys, account IDs, or output containing sensitive environment details.

## Public S3 Exposure Review

Script:

```text
automation/public-s3-check.py
```

Purpose:

Review S3 bucket public exposure posture and report risky bucket-level configurations.

Security model:

- read-only S3 API calls
- read-only S3 Control API calls
- read-only STS identity lookup if `--account-id` is not supplied
- no object reads
- no object downloads
- no bucket creation
- no bucket modification
- no bucket policy changes
- no infrastructure deployment

Usage:

```bash
python automation/public-s3-check.py --format table
```

With an AWS profile:

```bash
python automation/public-s3-check.py --profile lab-profile --format table
```

With an explicit account ID:

```bash
python automation/public-s3-check.py --account-id 123456789012 --format table
```

JSON output:

```bash
python automation/public-s3-check.py --format json
```

Fail with exit code `1` when high or critical findings are detected:

```bash
python automation/public-s3-check.py --fail-on-findings
```

Risk categories include:

- missing account-level S3 Public Access Block
- incomplete account-level S3 Public Access Block
- missing bucket-level S3 Public Access Block
- incomplete bucket-level S3 Public Access Block
- public bucket policy
- public ACL grant
- unable to evaluate account or bucket configuration

Exit codes:

| Code | Meaning                                                              |
| ---: | -------------------------------------------------------------------- |
|    0 | Script completed successfully                                        |
|    1 | High or critical findings detected and `--fail-on-findings` was used |
|    2 | Runtime or AWS configuration error                                   |

Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:HeadBucket",
        "s3control:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Do not commit AWS credentials, profile files, access keys, secret keys, account IDs, bucket contents, or output containing sensitive environment details.
