data "aws_region" "current" {}

locals {
  geo_allowlist_enabled = length(var.allowed_country_codes) > 0
  geo_blocklist_enabled = length(var.blocked_country_codes) > 0
  ip_allowlist_enabled  = length(var.allowed_ip_cidrs) > 0
  rate_limit_enabled    = var.rate_limit_per_5_minutes > 0
  managed_response_inspection_enabled = anytrue(flatten([
    for group in var.managed_rule_groups : [
      try(group.account_takeover_prevention.response_inspection != null, false),
      try(group.account_creation_fraud_prevention.response_inspection != null, false),
    ]
  ]))
}

resource "aws_wafv2_ip_set" "allowlist" {
  count = local.ip_allowlist_enabled ? 1 : 0

  name               = "${var.name}-allowlist"
  description        = "IP ranges allowed by the ${var.name} web ACL."
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
      condition     = var.ip_allowlist_bypass_rules || (local.ip_allowlist_enabled && var.default_action == "block")
      error_message = "ip_allowlist_bypass_rules=false requires allowed_ip_cidrs and default_action=block so requests outside the allowlist cannot fall through to an allow action."
    }

    precondition {
      condition     = !local.managed_response_inspection_enabled || var.scope == "CLOUDFRONT"
      error_message = "ATP and ACFP response inspection is supported only for CLOUDFRONT-scoped web ACLs."
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
      priority = var.ip_allowlist_bypass_rules ? 0 : 100 + length(var.managed_rule_groups) * 10

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
          version     = rule.value.version

          dynamic "rule_action_override" {
            for_each = rule.value.rule_action_overrides
            content {
              name = rule_action_override.key

              action_to_use {
                dynamic "allow" {
                  for_each = rule_action_override.value == "allow" ? [1] : []
                  content {}
                }

                dynamic "block" {
                  for_each = rule_action_override.value == "block" ? [1] : []
                  content {}
                }

                dynamic "captcha" {
                  for_each = rule_action_override.value == "captcha" ? [1] : []
                  content {}
                }

                dynamic "challenge" {
                  for_each = rule_action_override.value == "challenge" ? [1] : []
                  content {}
                }

                dynamic "count" {
                  for_each = rule_action_override.value == "count" ? [1] : []
                  content {}
                }
              }
            }
          }

          dynamic "managed_rule_group_configs" {
            for_each = anytrue([
              rule.value.bot_control != null,
              rule.value.account_takeover_prevention != null,
              rule.value.account_creation_fraud_prevention != null,
              rule.value.anti_ddos != null,
            ]) ? [1] : []
            content {
              dynamic "aws_managed_rules_bot_control_rule_set" {
                for_each = rule.value.bot_control == null ? [] : [rule.value.bot_control]
                content {
                  inspection_level        = aws_managed_rules_bot_control_rule_set.value.inspection_level
                  enable_machine_learning = aws_managed_rules_bot_control_rule_set.value.enable_machine_learning
                }
              }

              dynamic "aws_managed_rules_atp_rule_set" {
                for_each = rule.value.account_takeover_prevention == null ? [] : [rule.value.account_takeover_prevention]
                content {
                  login_path           = aws_managed_rules_atp_rule_set.value.login_path
                  enable_regex_in_path = aws_managed_rules_atp_rule_set.value.enable_regex_in_path

                  dynamic "request_inspection" {
                    for_each = aws_managed_rules_atp_rule_set.value.request_inspection == null ? [] : [aws_managed_rules_atp_rule_set.value.request_inspection]
                    content {
                      payload_type = request_inspection.value.payload_type

                      username_field {
                        identifier = request_inspection.value.username_field_identifier
                      }

                      password_field {
                        identifier = request_inspection.value.password_field_identifier
                      }
                    }
                  }

                  dynamic "response_inspection" {
                    for_each = aws_managed_rules_atp_rule_set.value.response_inspection == null ? [] : [aws_managed_rules_atp_rule_set.value.response_inspection]
                    content {
                      dynamic "body_contains" {
                        for_each = response_inspection.value.type == "BODY_CONTAINS" ? [1] : []
                        content {
                          success_strings = response_inspection.value.success_strings
                          failure_strings = response_inspection.value.failure_strings
                        }
                      }

                      dynamic "header" {
                        for_each = response_inspection.value.type == "HEADER" ? [1] : []
                        content {
                          name           = response_inspection.value.header_name
                          success_values = response_inspection.value.success_strings
                          failure_values = response_inspection.value.failure_strings
                        }
                      }

                      dynamic "json" {
                        for_each = response_inspection.value.type == "JSON" ? [1] : []
                        content {
                          identifier     = response_inspection.value.json_identifier
                          success_values = response_inspection.value.success_strings
                          failure_values = response_inspection.value.failure_strings
                        }
                      }

                      dynamic "status_code" {
                        for_each = response_inspection.value.type == "STATUS_CODE" ? [1] : []
                        content {
                          success_codes = response_inspection.value.success_codes
                          failure_codes = response_inspection.value.failure_codes
                        }
                      }
                    }
                  }
                }
              }

              dynamic "aws_managed_rules_acfp_rule_set" {
                for_each = rule.value.account_creation_fraud_prevention == null ? [] : [rule.value.account_creation_fraud_prevention]
                content {
                  creation_path          = aws_managed_rules_acfp_rule_set.value.creation_path
                  registration_page_path = aws_managed_rules_acfp_rule_set.value.registration_page_path
                  enable_regex_in_path   = aws_managed_rules_acfp_rule_set.value.enable_regex_in_path

                  request_inspection {
                    payload_type = aws_managed_rules_acfp_rule_set.value.request_inspection.payload_type

                    dynamic "username_field" {
                      for_each = aws_managed_rules_acfp_rule_set.value.request_inspection.username_field_identifier == null ? [] : [1]
                      content {
                        identifier = aws_managed_rules_acfp_rule_set.value.request_inspection.username_field_identifier
                      }
                    }

                    dynamic "password_field" {
                      for_each = aws_managed_rules_acfp_rule_set.value.request_inspection.password_field_identifier == null ? [] : [1]
                      content {
                        identifier = aws_managed_rules_acfp_rule_set.value.request_inspection.password_field_identifier
                      }
                    }

                    dynamic "email_field" {
                      for_each = aws_managed_rules_acfp_rule_set.value.request_inspection.email_field_identifier == null ? [] : [1]
                      content {
                        identifier = aws_managed_rules_acfp_rule_set.value.request_inspection.email_field_identifier
                      }
                    }

                    dynamic "address_fields" {
                      for_each = length(aws_managed_rules_acfp_rule_set.value.request_inspection.address_field_identifiers) == 0 ? [] : [1]
                      content {
                        identifiers = aws_managed_rules_acfp_rule_set.value.request_inspection.address_field_identifiers
                      }
                    }

                    dynamic "phone_number_fields" {
                      for_each = length(aws_managed_rules_acfp_rule_set.value.request_inspection.phone_number_field_identifiers) == 0 ? [] : [1]
                      content {
                        identifiers = aws_managed_rules_acfp_rule_set.value.request_inspection.phone_number_field_identifiers
                      }
                    }
                  }

                  dynamic "response_inspection" {
                    for_each = aws_managed_rules_acfp_rule_set.value.response_inspection == null ? [] : [aws_managed_rules_acfp_rule_set.value.response_inspection]
                    content {
                      dynamic "body_contains" {
                        for_each = response_inspection.value.type == "BODY_CONTAINS" ? [1] : []
                        content {
                          success_strings = response_inspection.value.success_strings
                          failure_strings = response_inspection.value.failure_strings
                        }
                      }

                      dynamic "header" {
                        for_each = response_inspection.value.type == "HEADER" ? [1] : []
                        content {
                          name           = response_inspection.value.header_name
                          success_values = response_inspection.value.success_strings
                          failure_values = response_inspection.value.failure_strings
                        }
                      }

                      dynamic "json" {
                        for_each = response_inspection.value.type == "JSON" ? [1] : []
                        content {
                          identifier     = response_inspection.value.json_identifier
                          success_values = response_inspection.value.success_strings
                          failure_values = response_inspection.value.failure_strings
                        }
                      }

                      dynamic "status_code" {
                        for_each = response_inspection.value.type == "STATUS_CODE" ? [1] : []
                        content {
                          success_codes = response_inspection.value.success_codes
                          failure_codes = response_inspection.value.failure_codes
                        }
                      }
                    }
                  }
                }
              }

              dynamic "aws_managed_rules_anti_ddos_rule_set" {
                for_each = rule.value.anti_ddos == null ? [] : [rule.value.anti_ddos]
                content {
                  sensitivity_to_block = aws_managed_rules_anti_ddos_rule_set.value.sensitivity_to_block

                  client_side_action_config {
                    challenge {
                      usage_of_action = aws_managed_rules_anti_ddos_rule_set.value.client_side_challenge.usage_of_action
                      sensitivity     = aws_managed_rules_anti_ddos_rule_set.value.client_side_challenge.sensitivity

                      dynamic "exempt_uri_regular_expression" {
                        for_each = aws_managed_rules_anti_ddos_rule_set.value.client_side_challenge.exempt_uri_regexes
                        content {
                          regex_string = exempt_uri_regular_expression.value
                        }
                      }
                    }
                  }
                }
              }
            }
          }
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
