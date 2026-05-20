output "account_public_access_block_enabled" {
  description = "Whether account-level S3 Public Access Block is managed by this configuration."
  value       = var.enable_account_public_access_block
}

output "example_bucket_name" {
  description = "Name of the example bucket, if created."
  value       = var.create_example_bucket ? aws_s3_bucket.example[0].bucket : null
}

output "bucket_public_access_block_enabled" {
  description = "Whether bucket-level S3 Public Access Block is configured for the example bucket."
  value       = var.create_example_bucket
}