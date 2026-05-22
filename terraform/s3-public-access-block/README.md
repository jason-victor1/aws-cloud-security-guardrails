# S3 Public Access Block Guardrail

## Purpose

This Terraform guardrail configures Amazon S3 Block Public Access controls to reduce accidental public exposure of S3 buckets and objects.

## Security Intent

Public S3 exposure is a common cloud misconfiguration risk. This guardrail enables the four S3 Block Public Access settings at the account level and demonstrates bucket-level protection for an example bucket.

AWS S3 Block Public Access can be applied at the account, bucket, access point, and organization levels. AWS recommends enabling all four settings for the account, and also enabling the settings for each bucket when possible. S3 applies the most restrictive combination when account-level and bucket-level settings differ.

## Controls Implemented

This module enables:

- `block_public_acls`
- `ignore_public_acls`
- `block_public_policy`
- `restrict_public_buckets`
- example bucket versioning

## Files

```text
terraform/s3-public-access-block/
  README.md
  versions.tf
  variables.tf
  main.tf
  outputs.tf
  terraform.tfvars.example
```

## Usage

From this module directory:

```bash
cd terraform/s3-public-access-block
terraform fmt
terraform init
terraform validate
```

To review the planned changes without applying them:

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars and set a globally unique example_bucket_name.
terraform plan
```

Do not run `terraform apply` until the plan has been reviewed.

For this V1 implementation task, stop at `terraform validate` unless deployment has been explicitly approved.

## Security Notes

This guardrail is preventive. It is designed to reduce accidental public S3 exposure by blocking or ignoring public ACLs and restricting public bucket policies.

Before applying in a real environment, confirm that no required workload depends on public S3 access, such as static website hosting or intentionally public asset delivery.

## Validation

After applying, validate account-level settings with:

```bash
aws s3control get-public-access-block --account-id <account-id>
```

For the example bucket, validate bucket-level settings with:

```bash
aws s3api get-public-access-block --bucket <bucket-name>
```

Expected settings:

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }
}
```

## Evidence Produced

This guardrail can produce the following evidence:

- Terraform configuration
- `terraform fmt` output
- `terraform validate` output
- `terraform plan` output
- AWS CLI public access block output
- screenshots or terminal logs showing the guardrail is active

## Related Project Documentation

- [`../../docs/03-control-matrix.md`](../../docs/03-control-matrix.md)
- [`../../docs/08-evidence-checklist.md`](../../docs/08-evidence-checklist.md)

## Static Analysis Scope

This module is scoped to the S3 Public Access Block guardrail.

The example bucket also includes versioning to demonstrate a stronger baseline. Broader production controls such as KMS encryption, access logging, lifecycle rules, cross-region replication, and event notifications are intentionally deferred to future guardrail modules.

Checkov skips for these deferred controls are documented in the root `.checkov.yml`.
