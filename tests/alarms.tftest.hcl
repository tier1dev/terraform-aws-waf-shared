mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      name   = "us-east-1"
      region = "us-east-1"
    }
  }

  mock_resource "aws_cloudwatch_metric_alarm" {
    defaults = {
      arn = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:mock-metric-alarm"
    }
  }

  mock_resource "aws_cloudwatch_composite_alarm" {
    defaults = {
      arn = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:mock-composite-alarm"
    }
  }
}

variables {
  name = "shared-web"
  tags = {
    Customer    = "example"
    Application = "shared-web"
    Environment = "prod"
    Owner       = "security@example.com"
    Costcenter  = "security"
  }
}

run "alarms_are_disabled_by_default" {
  command = plan

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.blocked_requests) == 0 &&
      length(aws_cloudwatch_metric_alarm.rate_limit_blocks) == 0 &&
      length(aws_cloudwatch_composite_alarm.security_events) == 0
    )
    error_message = "The module must not create alarms unless explicitly enabled."
  }

  assert {
    condition     = output.notification_alarm_name == null
    error_message = "The notification alarm output must be null when alarms are disabled."
  }
}

run "one_aggregate_alarm_without_rate_limiting" {
  command = plan

  variables {
    enable_production_alarms = true
    alarm_action_arns        = ["arn:aws:sns:us-east-1:123456789012:waf-alerts"]
    rate_limit_per_5_minutes = 0
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.blocked_requests) == 1 &&
      length(aws_cloudwatch_metric_alarm.rate_limit_blocks) == 0 &&
      length(aws_cloudwatch_composite_alarm.security_events) == 0
    )
    error_message = "Without rate limiting, only the aggregate metric alarm should exist."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.blocked_requests[0].actions_enabled &&
      contains(
        aws_cloudwatch_metric_alarm.blocked_requests[0].alarm_actions,
        "arn:aws:sns:us-east-1:123456789012:waf-alerts"
      )
    )
    error_message = "The single aggregate alarm must own notification actions."
  }

  assert {
    condition     = output.notification_alarm_name == "shared-web-waf-blocked-requests-prod"
    error_message = "The aggregate alarm must be exposed as the notification alarm."
  }
}

run "composite_alarm_owns_actions_with_rate_limiting" {
  command = plan

  variables {
    enable_production_alarms = true
    alarm_action_arns        = ["arn:aws:sns:us-east-1:123456789012:waf-alerts"]
    rate_limit_per_5_minutes = 2000
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.blocked_requests) == 1 &&
      length(aws_cloudwatch_metric_alarm.rate_limit_blocks) == 1 &&
      length(aws_cloudwatch_composite_alarm.security_events) == 1
    )
    error_message = "Rate limiting must add its metric alarm and a composite notification alarm."
  }

  assert {
    condition = (
      !aws_cloudwatch_metric_alarm.blocked_requests[0].actions_enabled &&
      !aws_cloudwatch_metric_alarm.rate_limit_blocks[0].actions_enabled &&
      length(aws_cloudwatch_metric_alarm.blocked_requests[0].alarm_actions) == 0 &&
      aws_cloudwatch_composite_alarm.security_events[0].actions_enabled &&
      contains(
        aws_cloudwatch_composite_alarm.security_events[0].alarm_actions,
        "arn:aws:sns:us-east-1:123456789012:waf-alerts"
      )
    )
    error_message = "Only the composite alarm may send notifications when both child alarms exist."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.blocked_requests[0].treat_missing_data == "notBreaching" &&
      aws_cloudwatch_metric_alarm.rate_limit_blocks[0].treat_missing_data == "notBreaching"
    )
    error_message = "Sparse WAF metrics must not leave production alarms in INSUFFICIENT_DATA."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.blocked_requests[0].dimensions.Region == "us-east-1" &&
      aws_cloudwatch_metric_alarm.blocked_requests[0].dimensions.Rule == "ALL" &&
      aws_cloudwatch_metric_alarm.rate_limit_blocks[0].dimensions.Rule == "shared-web-rate-limit"
    )
    error_message = "Regional WAF alarms must use the documented Region, WebACL, and Rule dimensions."
  }

  assert {
    condition     = output.notification_alarm_name == "shared-web-waf-security-events-prod"
    error_message = "The composite alarm must be exposed as the notification alarm."
  }
}

run "cloudfront_alarm_omits_region_dimension" {
  command = plan

  variables {
    scope                    = "CLOUDFRONT"
    enable_production_alarms = true
    rate_limit_per_5_minutes = 0
  }

  assert {
    condition     = !contains(keys(aws_cloudwatch_metric_alarm.blocked_requests[0].dimensions), "Region")
    error_message = "CloudFront WAF metrics must omit the Region dimension."
  }
}

run "production_alarms_require_governance_tags" {
  command = plan

  variables {
    enable_production_alarms = true
    tags = {
      Environment = "dev"
    }
  }

  expect_failures = [
    aws_wafv2_web_acl.this,
  ]
}
