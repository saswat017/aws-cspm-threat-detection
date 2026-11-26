# -----------------------------------------------------------------------------
# Module 1: Target environment
# A small "company" environment that the monitoring, scanner and detection
# modules protect. It is secure by default and uses only free-tier services:
#   - No KMS customer-managed key  -> AWS-managed encryption keys (free)
#   - No Secrets Manager secret    -> SSM Parameter Store SecureString (free)
#   - No public IPv4 address       -> instance is private (public IPv4 is billed)
# -----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # State is kept locally in this folder (gitignored). The monitoring module
  # reads it with terraform_remote_state to find the VPC ID.
}

provider "aws" {
  region = var.aws_region

  # Real AWS: log in with the named CLI profile.
  # Emulator: no profile; the run script sets dummy keys ("testing").
  profile = var.use_emulator ? null : var.aws_profile

  # The emulator cannot validate credentials or look up the account,
  # so these checks are skipped only in emulator mode.
  skip_credentials_validation = var.use_emulator
  skip_requesting_account_id  = var.use_emulator
  s3_use_path_style           = var.use_emulator

  # Send every API call to the local emulator instead of AWS.
  # null = use the normal AWS endpoint.
  endpoints {
    ec2 = local.endpoint
    iam = local.endpoint
    s3  = local.endpoint
    ssm = local.endpoint
    sts = local.endpoint
  }

  # Every resource gets these tags, so the scanner and the AWS console can
  # tell lab resources apart from anything else in the account.
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "lab"
      ManagedBy   = "terraform"
    }
  }
}

# Short random suffix so globally unique names (the S3 bucket) do not clash.
resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name     = var.project_name
  suffix   = random_id.suffix.hex
  endpoint = var.use_emulator ? var.emulator_endpoint : null
}
