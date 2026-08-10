data "aws_region" "current" {}

locals {
  geo_allowlist_enabled = length(var.allowed_country_codes) > 0
  geo_blocklist_enabled = length(var.blocked_country_codes) > 0
  ip_allowlist_enabled  = length(var.allowed_ip_cidrs) > 0
  rate_limit_enabled    = var.rate_limit_per_5_minutes > 0
}

resource "aws_wafv2_ip_set" "allowlist" {
  count = local.ip_allowlist_enabled ? 1 : 0

  name               = "${var.name}-allowlist"
  description        = "IP ranges that bypass the ${var.name} web ACL rules."
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.allowed_ip_cidrs
  tags               = var.tags
}

resource "aws_wafv2_web_acl" "this" {
  name        = var.name
  description = "Shared web ACL managed by terraform-aws-waf-shared."
  scope       = var.scope

  lifecycle {
    precondition {
      condition     = !(local.geo_allowlist_enabled && local.geo_blocklist_enabled)
      error_message = "Set allowed_country_codes or blocked_country_codes, not both."
    }

    precondition {
      condition     = var.scope == "REGIONAL" || data.aws_region.current.region == "us-east-1"
      error_message = "CLOUDFRONT-scoped web ACLs must be created in us-east-1. Pass a us-east-1 provider to this module."
    }

    precondition {
      condition     = var.scope == "REGIONAL" || length(var.association_resource_arns) == 0
      error_message = "association_resource_arns only supports REGIONAL resources. Attach CloudFront distributions via their web_acl_id argument."
    }

    precondition {
      condition     = !var.enable_production_alarms || local.production_alarm_tags_valid
      error_message = "Production alarms require non-empty Customer, Application, Environment, Owner, and Costcenter tags, with Environment set to prod."
    }
  }

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }

    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  dynamic "rule" {
    for_each = local.ip_allowlist_enabled ? [1] : []
    content {
      name     = "ip-allowlist"
      priority = 0

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowlist[0].arn
        }
      }

      visibility_config {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-ip-allowlist"
      }
    }
  }

  dynamic "rule" {
    for_each = local.geo_blocklist_enabled ? [1] : []
    content {
      name     = "geo-blocklist"
      priority = 10

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_country_codes
        }
      }

      visibility_config {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-geo-blocklist"
      }
    }
  }

  dynamic "rule" {
    for_each = local.geo_allowlist_enabled ? [1] : []
    content {
      name     = "geo-allowlist"
      priority = 10

      action {
        block {}
      }

      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = var.allowed_country_codes
            }
          }
        }
      }

      visibility_config {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-geo-allowlist"
      }
    }
  }

  dynamic "rule" {
    for_each = local.rate_limit_enabled ? [1] : []
    content {
      name     = "rate-limit"
      priority = 20

      action {
        block {}
      }

      statement {
        rate_based_statement {
          aggregate_key_type = "IP"
          limit              = var.rate_limit_per_5_minutes
        }
      }

      visibility_config {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-rate-limit"
      }
    }
  }

  dynamic "rule" {
    for_each = { for i, g in var.managed_rule_groups : g.name => merge(g, { priority = 100 + i * 10 }) }
    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }

        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = rule.value.vendor_name
        }
      }

      visibility_config {
        sampled_requests_enabled   = true
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-${rule.value.name}"
      }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
  }

  tags = var.tags
}

resource "aws_wafv2_web_acl_association" "this" {
  count = length(var.association_resource_arns)

  resource_arn = var.association_resource_arns[count.index]
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

resource "aws_cloudwatch_log_group" "waf" {
  count = var.enable_logging ? 1 : 0

  # WAFv2 CloudWatch destinations must be named aws-waf-logs-*.
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = var.enable_logging ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]
}
