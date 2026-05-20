variable "aws_region" {
  description = "AWS region used by the provider."
  type        = string
  default     = "us-east-1"
}

variable "enable_account_public_access_block" {
  description = "Whether to create the account-level S3 Public Access Block configuration."
  type        = bool
  default     = true
}

variable "create_example_bucket" {
  description = "Whether to create an example S3 bucket with bucket-level Public Access Block configuration."
  type        = bool
  default     = true
}

variable "example_bucket_name" {
  description = "Globally unique name for the example S3 bucket. Required when create_example_bucket is true."
  type        = string
  default     = null

  validation {
    condition = (
      var.example_bucket_name == null ||
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.example_bucket_name))
    )
    error_message = "example_bucket_name must be null or a valid S3 bucket-style name using lowercase letters, numbers, dots, and hyphens."
  }
}

variable "tags" {
  description = "Common tags applied to supported resources."
  type        = map(string)

  default = {
    Project     = "aws-cloud-security-guardrails"
    Environment = "lab"
    ManagedBy   = "terraform"
    Control     = "s3-public-access-block"
  }
}