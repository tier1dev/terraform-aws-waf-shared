locals {
  production_alarm_required_tag_keys = [
    "Customer",
    "Application",
    "Environment",
    "Owner",
    "Costcenter",
  ]

  production_alarm_tags_valid = alltrue([
    for key in local.production_alarm_required_tag_keys :
    trimspace(lookup(var.tags, key, "")) != ""
  ]) && lookup(var.tags, "Environment", "") == "prod"

  web_acl_alarm_dimensions = merge(
    {
      WebACL = var.name
      Rule   = "ALL"
    },
    var.scope == "REGIONAL" ? {
      Region = data.aws_region.current.region
    } : {}
  )

  rate_limit_alarm_dimensions = merge(
    {
      WebACL = var.name
      Rule   = "${var.name}-rate-limit"
    },
    var.scope == "REGIONAL" ? {
      Region = data.aws_region.current.region
    } : {}
  )
}

resource "aws_cloudwatch_metric_alarm" "blocked_requests" {
  count = var.enable_production_alarms ? 1 : 0

  alarm_name          = "${var.name}-waf-blocked-requests-prod"
  alarm_description   = "Shared WAF blocked-request volume exceeded its production threshold."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = var.blocked_requests_alarm_threshold
  treat_missing_data  = "notBreaching"
  dimensions          = local.web_acl_alarm_dimensions

  # When a rate-limit child also exists, the composite alarm is the single
  # notification path. A one-child composite would add cost without reducing noise.
  actions_enabled = !local.rate_limit_enabled && length(var.alarm_action_arns) > 0
  alarm_actions   = local.rate_limit_enabled ? [] : var.alarm_action_arns

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "rate_limit_blocks" {
  count = var.enable_production_alarms && local.rate_limit_enabled ? 1 : 0

  alarm_name          = "${var.name}-waf-rate-limit-blocks-prod"
  alarm_description   = "Shared WAF rate-limit blocks exceeded their production threshold."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = var.rate_limit_blocks_alarm_threshold
  treat_missing_data  = "notBreaching"
  dimensions          = local.rate_limit_alarm_dimensions

  actions_enabled = false

  tags = var.tags
}

resource "aws_cloudwatch_composite_alarm" "security_events" {
  count = var.enable_production_alarms && local.rate_limit_enabled ? 1 : 0

  alarm_name        = "${var.name}-waf-security-events-prod"
  alarm_description = "Notification alarm for aggregate or rate-limit WAF blocking activity."
  alarm_rule = join(" OR ", [
    "ALARM(\"${aws_cloudwatch_metric_alarm.blocked_requests[0].alarm_name}\")",
    "ALARM(\"${aws_cloudwatch_metric_alarm.rate_limit_blocks[0].alarm_name}\")",
  ])

  actions_enabled = length(var.alarm_action_arns) > 0
  alarm_actions   = var.alarm_action_arns

  tags = var.tags
}
