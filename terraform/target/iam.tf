# -----------------------------------------------------------------------------
# IAM role for the EC2 instance (least privilege).
# The instance can only:
#   - read/write objects in the lab bucket
#   - read the one lab parameter in SSM Parameter Store
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${local.name}-app-role"
  description        = "Role assumed by the lab EC2 instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

data "aws_iam_policy_document" "app_permissions" {
  statement {
    sid       = "LabBucketObjects"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
  }

  statement {
    sid       = "LabBucketList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.data.arn]
  }

  statement {
    sid       = "ReadLabParameter"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.db_password.arn]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "${local.name}-app-least-privilege"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app_permissions.json
}

# An instance profile is the "wrapper" that lets EC2 use the role.
resource "aws_iam_instance_profile" "app" {
  name = "${local.name}-app-profile"
  role = aws_iam_role.app.name
}
