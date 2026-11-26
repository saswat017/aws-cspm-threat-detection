output "cloudtrail_name" {
  value = "${local.name}-trail"
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.trail.bucket
}

output "cloudtrail_log_group" {
  value = aws_cloudwatch_log_group.cloudtrail.name
}

output "flow_log_group" {
  value = aws_cloudwatch_log_group.flow_logs.name
}

output "alerts_log_group" {
  value = aws_cloudwatch_log_group.alerts.name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "detection_rules_deployed" {
  value = {
    eventbridge_rules = sort(keys(aws_cloudwatch_event_rule.detection))
    metric_alarms     = sort(keys(aws_cloudwatch_metric_alarm.detection))
  }
}
