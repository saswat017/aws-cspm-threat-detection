# -----------------------------------------------------------------------------
# A "database password" stored as an SSM Parameter Store SecureString.
# Free alternative to Secrets Manager + a KMS customer-managed key:
#   - Standard-tier parameters cost nothing
#   - SecureString is encrypted with the AWS-managed key aws/ssm (free)
#   - every read is still logged in CloudTrail (ssm:GetParameter and
#     kms:Decrypt), so the detection module can watch for access spikes
#
# Note: the generated value is also saved in the local Terraform state file,
# which is why *.tfstate is gitignored.
# -----------------------------------------------------------------------------

resource "random_password" "db" {
  length  = 24
  special = true
}

resource "aws_ssm_parameter" "db_password" {
  name        = "/${local.name}/db-password"
  description = "Lab database password (demo secret)"
  type        = "SecureString"
  tier        = "Standard"
  value       = random_password.db.result
}
