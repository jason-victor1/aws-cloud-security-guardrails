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
