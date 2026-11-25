# -----------------------------------------------------------------------------
# S3 bucket for "company data". Secure by default:
#   - all four Block Public Access settings on
#   - ACLs disabled (bucket owner owns every object)
#   - default encryption with SSE-S3 (AWS-managed key, free)
#   - versioning on (protects against accidental overwrite/delete)
#   - bucket policy that refuses any non-HTTPS request
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data" {
  bucket = "${local.name}-data-${local.suffix}"

  # Lab convenience: lets `terraform destroy` delete a bucket that still has
  # objects in it. Do not use this on real production buckets.
  force_destroy = true

  tags = { Name = "${local.name}-data" }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3: free, AWS manages the key
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Deny every request that does not use HTTPS (CIS AWS Foundations 2.1.1).
data "aws_iam_policy_document" "data_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.data.arn,
      "${aws_s3_bucket.data.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = data.aws_iam_policy_document.data_bucket.json

  # The public access block must exist first, otherwise AWS can briefly
  # evaluate the policy without it.
  depends_on = [aws_s3_bucket_public_access_block.data]
}

# Keep old object versions for 30 days only, so versioning does not slowly
# grow storage cost. Also cleans up half-finished multipart uploads.
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}
