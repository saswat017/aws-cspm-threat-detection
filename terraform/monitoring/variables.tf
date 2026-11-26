variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_profile" {
  description = "Named AWS CLI profile (real AWS only)."
  type        = string
  default     = "cspm-lab"
}

variable "project_name" {
  type    = string
  default = "cspm-lab"
}

variable "alert_email" {
  description = "Email that receives security alerts and budget alerts. Leave empty to skip the email subscription."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "How long CloudWatch Logs and CloudTrail S3 objects are kept (short = cheap)."
  type        = number
  default     = 14
}

variable "monthly_budget_usd" {
  description = "Budget alert threshold in US dollars."
  type        = number
  default     = 1
}

variable "enable_guardduty" {
  description = "Turn on GuardDuty (30-day free trial, then paid)."
  type        = bool
  default     = false
}

variable "enable_securityhub" {
  description = "Turn on Security Hub with the CIS benchmark (needs AWS Config, which is paid)."
  type        = bool
  default     = false
}

variable "use_emulator" {
  description = "true = deploy into the local AWS emulator (moto) instead of real AWS."
  type        = bool
  default     = false
}

variable "emulator_endpoint" {
  type    = string
  default = "http://127.0.0.1:5001"
}
