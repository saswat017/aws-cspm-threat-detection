# -----------------------------------------------------------------------------
# CloudWatch Logs groups. Short retention keeps them inside the free tier.
#   /cspm/cloudtrail     every AWS API call (from CloudTrail)
#   /cspm/vpc-flow-logs  network connections in the VPC
#   /security/alerts     one entry per fired detection (used to measure MTTD)
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cspm/cloudtrail"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/cspm/vpc-flow-logs"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "alerts" {
  name              = "/security/alerts"
  retention_in_days = var.log_retention_days
}
