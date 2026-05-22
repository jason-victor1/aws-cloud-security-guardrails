resource "aws_s3_account_public_access_block" "this" {
  count = var.enable_account_public_access_block ? 1 : 0

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "example" {
  count = var.create_example_bucket ? 1 : 0

  bucket = var.example_bucket_name

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "example" {
  count = var.create_example_bucket ? 1 : 0

  bucket = aws_s3_bucket.example[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "example" {
  count = var.create_example_bucket ? 1 : 0

  bucket = aws_s3_bucket.example[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}