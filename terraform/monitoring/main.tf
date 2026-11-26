# -----------------------------------------------------------------------------
# Module 2: Monitoring foundation
# Collects the evidence that posture scanning and threat detection need:
#   CloudTrail (every API call) -> S3 + CloudWatch Logs
#   VPC Flow Logs (network traffic) -> CloudWatch Logs
#   GuardDuty / Security Hub (optional, cost money after the trial)
#   SNS email topic for alerts, and a $1 budget alert
# Reads the VPC ID from the target environment's Terraform state.
# -----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Same switch as terraform/target: named profile on real AWS,
  # dummy keys and local endpoints in the emulator.
  profile                     = var.use_emulator ? null : var.aws_profile
  skip_credentials_validation = var.use_emulator
  skip_requesting_account_id  = var.use_emulator
  s3_use_path_style           = var.use_emulator

  endpoints {
    budgets     = local.endpoint
    cloudtrail  = local.endpoint
    cloudwatch  = local.endpoint
    ec2         = local.endpoint
    events      = local.endpoint
    guardduty   = local.endpoint
    iam         = local.endpoint
    logs        = local.endpoint
    s3          = local.endpoint
    securityhub = local.endpoint
    sns         = local.endpoint
    sts         = local.endpoint
  }

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "lab"
      ManagedBy   = "terraform"
    }
  }
}

# Outputs of terraform/target (same workspace: "default" for real AWS,
# "emulator" for the local emulator).
data "terraform_remote_state" "target" {
  backend   = "local"
  workspace = terraform.workspace
  config = {
    path          = "${path.module}/../target/terraform.tfstate"
    workspace_dir = "${path.module}/../target/terraform.tfstate.d"
  }
}

data "aws_caller_identity" "current" {}

locals {
  name       = var.project_name
  endpoint   = var.use_emulator ? var.emulator_endpoint : null
  account_id = data.aws_caller_identity.current.account_id
  vpc_id     = data.terraform_remote_state.target.outputs.vpc_id
}
