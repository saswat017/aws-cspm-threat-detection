# -----------------------------------------------------------------------------
# Module 4 (deployment): turns the rule files in detection/rules/ into native
# AWS detections. Adding a rule folder adds a detection; no Terraform edits.
#
#   type: event              -> EventBridge rule (CloudTrail event pattern)
#                               targets: SNS topic (email) + /security/alerts
#   type: threshold          -> CloudWatch Logs metric filter on CloudTrail
#   type: flowlog_threshold  -> metric filter on VPC Flow Logs
#                               + CloudWatch alarm (count >= N in W minutes) -> SNS
#   type: new_value          -> Python engine only (CloudWatch has no first-seen logic)
#
# Alarm state changes are also copied to /security/alerts, so every fired
# detection has a timestamp there (used to measure Mean Time To Detect).
# -----------------------------------------------------------------------------

locals {
  rules_dir  = "${path.module}/../../detection/rules"
  rule_files = fileset(local.rules_dir, "*/rule.yaml")
  rules      = { for f in local.rule_files : dirname(f) => yamldecode(file("${local.rules_dir}/${f}")) }

  event_rules  = { for k, r in local.rules : k => r if r.type == "event" }
  metric_rules = { for k, r in local.rules : k => r if contains(["threshold", "flowlog_threshold"], r.type) }
}

# --- event rules -> EventBridge ---------------------------------------------

resource "aws_cloudwatch_event_rule" "detection" {
  for_each      = local.event_rules
  name          = "${local.name}-${each.key}"
  description   = "${each.value.id}: ${each.value.name} (MITRE ${each.value.mitre.technique_id})"
  event_pattern = file("${local.rules_dir}/${each.key}/pattern.json")
}

resource "aws_cloudwatch_event_target" "detection_sns" {
  for_each = local.event_rules
  rule     = aws_cloudwatch_event_rule.detection[each.key].name
  arn      = aws_sns_topic.alerts.arn
}

resource "aws_cloudwatch_event_target" "detection_log" {
  for_each = local.event_rules
  rule     = aws_cloudwatch_event_rule.detection[each.key].name
  arn      = aws_cloudwatch_log_group.alerts.arn
}

# Allow EventBridge to write into the /security/alerts log group.
data "aws_iam_policy_document" "alerts_log_writers" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.alerts.arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "alerts" {
  policy_name     = "${local.name}-eventbridge-to-alerts"
  policy_document = data.aws_iam_policy_document.alerts_log_writers.json
}

# --- threshold rules -> metric filter + alarm --------------------------------

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each       = local.metric_rules
  name           = "${local.name}-${each.key}"
  log_group_name = each.value.source == "flowlogs" ? aws_cloudwatch_log_group.flow_logs.name : aws_cloudwatch_log_group.cloudtrail.name
  pattern        = trimspace(file("${local.rules_dir}/${each.key}/filter.txt"))

  metric_transformation {
    name      = each.value.id
    namespace = "CSPM/Detections"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each            = local.metric_rules
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = "${each.value.id}: ${each.value.name} (MITRE ${each.value.mitre.technique_id})"
  namespace           = "CSPM/Detections"
  metric_name         = each.value.id
  statistic           = "Sum"
  period              = each.value.threshold.window_minutes * 60
  evaluation_periods  = 1
  threshold           = each.value.threshold.count
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.detection]
}

# Copy every detection alarm that goes into ALARM to /security/alerts.
resource "aws_cloudwatch_event_rule" "alarm_state" {
  name        = "${local.name}-detection-alarm-fired"
  description = "Detection alarms entering ALARM state"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = [{ prefix = "${local.name}-" }]
      state     = { value = ["ALARM"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "alarm_state_log" {
  rule = aws_cloudwatch_event_rule.alarm_state.name
  arn  = aws_cloudwatch_log_group.alerts.arn
}
