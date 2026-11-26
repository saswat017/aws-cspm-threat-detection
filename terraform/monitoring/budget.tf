# -----------------------------------------------------------------------------
# Budget alert: emails you when the month's AWS bill reaches 80% of the limit
# (actual) or is forecast to pass it. The first two budgets are free.
# -----------------------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  # Skipped in the emulator: it has no bill, and moto does not implement the
  # Budgets notification APIs that Terraform needs.
  count = var.use_emulator ? 0 : 1

  account_id   = local.account_id
  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.alert_email == "" ? [] : [
      { type = "ACTUAL", threshold = 80 },
      { type = "FORECASTED", threshold = 100 },
    ]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.alert_email]
    }
  }
}
