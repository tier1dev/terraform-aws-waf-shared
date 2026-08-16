mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      name   = "us-east-1"
      region = "us-east-1"
    }
  }

  mock_resource "aws_wafv2_ip_set" {
    defaults = {
      arn = "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/mock/00000000-0000-0000-0000-000000000000"
    }
  }
}

variables {
  name                = "managed-rules-test"
  managed_rule_groups = []
}

run "all_standard_aws_managed_groups_are_available" {
  command = plan

  variables {
    managed_rule_groups = [
      {
        name    = "AWSManagedRulesCommonRuleSet"
        version = "Version_1.0"
        rule_action_overrides = {
          SizeRestrictions_BODY = "count"
        }
      },
      { name = "AWSManagedRulesAdminProtectionRuleSet" },
      { name = "AWSManagedRulesKnownBadInputsRuleSet" },
      { name = "AWSManagedRulesSQLiRuleSet" },
      { name = "AWSManagedRulesLinuxRuleSet" },
      { name = "AWSManagedRulesUnixRuleSet" },
      { name = "AWSManagedRulesWindowsRuleSet" },
      { name = "AWSManagedRulesPHPRuleSet" },
      { name = "AWSManagedRulesWordPressRuleSet" },
      { name = "AWSManagedRulesAmazonIpReputationList" },
      { name = "AWSManagedRulesAnonymousIpList" },
    ]
  }

  assert {
    condition = alltrue([
      for expected in [
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesAdminProtectionRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesSQLiRuleSet",
        "AWSManagedRulesLinuxRuleSet",
        "AWSManagedRulesUnixRuleSet",
        "AWSManagedRulesWindowsRuleSet",
        "AWSManagedRulesPHPRuleSet",
        "AWSManagedRulesWordPressRuleSet",
        "AWSManagedRulesAmazonIpReputationList",
        "AWSManagedRulesAnonymousIpList",
      ] : contains([for rule in aws_wafv2_web_acl.this.rule : rule.name], expected)
    ])
    error_message = "Every standard AWS managed rule group must be renderable through managed_rule_groups."
  }

  assert {
    condition = (
      one([
        for rule in aws_wafv2_web_acl.this.rule : rule
        if rule.name == "AWSManagedRulesCommonRuleSet"
      ]).statement[0].managed_rule_group_statement[0].version == "Version_1.0" &&
      one([
        for rule in aws_wafv2_web_acl.this.rule : rule
        if rule.name == "AWSManagedRulesCommonRuleSet"
      ]).statement[0].managed_rule_group_statement[0].rule_action_override[0].name == "SizeRestrictions_BODY"
    )
    error_message = "Managed group versions and per-rule action overrides must be preserved."
  }
}

run "all_premium_aws_managed_groups_are_configurable" {
  command = plan

  variables {
    scope = "CLOUDFRONT"
    managed_rule_groups = [
      {
        name            = "AWSManagedRulesBotControlRuleSet"
        override_action = "count"
        bot_control = {
          inspection_level        = "TARGETED"
          enable_machine_learning = true
        }
      },
      {
        name            = "AWSManagedRulesATPRuleSet"
        override_action = "count"
        account_takeover_prevention = {
          login_path = "/login"
          request_inspection = {
            payload_type              = "JSON"
            username_field_identifier = "/email"
            password_field_identifier = "/password"
          }
          response_inspection = {
            type          = "STATUS_CODE"
            success_codes = [200]
            failure_codes = [401, 403]
          }
        }
      },
      {
        name            = "AWSManagedRulesACFPRuleSet"
        override_action = "count"
        account_creation_fraud_prevention = {
          creation_path          = "/register"
          registration_page_path = "/signup"
          request_inspection = {
            payload_type              = "JSON"
            username_field_identifier = "/username"
            password_field_identifier = "/password"
            email_field_identifier    = "/email"
          }
        }
      },
      {
        name            = "AWSManagedRulesAntiDDoSRuleSet"
        override_action = "count"
        anti_ddos = {
          sensitivity_to_block = "LOW"
          client_side_challenge = {
            usage_of_action    = "ENABLED"
            sensitivity        = "HIGH"
            exempt_uri_regexes = ["^/api/webhooks/"]
          }
        }
      },
    ]
  }

  assert {
    condition = alltrue([
      for expected in [
        "AWSManagedRulesBotControlRuleSet",
        "AWSManagedRulesATPRuleSet",
        "AWSManagedRulesACFPRuleSet",
        "AWSManagedRulesAntiDDoSRuleSet",
      ] : contains([for rule in aws_wafv2_web_acl.this.rule : rule.name], expected)
    ])
    error_message = "Every premium AWS managed rule group must be renderable with its required configuration."
  }

  assert {
    condition = one([
      for rule in aws_wafv2_web_acl.this.rule : rule
      if rule.name == "AWSManagedRulesBotControlRuleSet"
    ]).statement[0].managed_rule_group_statement[0].managed_rule_group_configs[0].aws_managed_rules_bot_control_rule_set[0].inspection_level == "TARGETED"
    error_message = "Bot Control configuration must be passed to the provider."
  }

  assert {
    condition = one([
      for rule in aws_wafv2_web_acl.this.rule : rule
      if rule.name == "AWSManagedRulesATPRuleSet"
    ]).statement[0].managed_rule_group_statement[0].managed_rule_group_configs[0].aws_managed_rules_atp_rule_set[0].login_path == "/login"
    error_message = "ATP login configuration must be passed to the provider."
  }

  assert {
    condition = one([
      for rule in aws_wafv2_web_acl.this.rule : rule
      if rule.name == "AWSManagedRulesACFPRuleSet"
    ]).statement[0].managed_rule_group_statement[0].managed_rule_group_configs[0].aws_managed_rules_acfp_rule_set[0].creation_path == "/register"
    error_message = "ACFP registration configuration must be passed to the provider."
  }

  assert {
    condition = one([
      for rule in aws_wafv2_web_acl.this.rule : rule
      if rule.name == "AWSManagedRulesAntiDDoSRuleSet"
    ]).statement[0].managed_rule_group_statement[0].managed_rule_group_configs[0].aws_managed_rules_anti_ddos_rule_set[0].client_side_action_config[0].challenge[0].usage_of_action == "ENABLED"
    error_message = "Anti-DDoS client challenge configuration must be passed to the provider."
  }
}

run "strict_ip_allowlist_runs_security_rules_before_allow" {
  command = plan

  variables {
    default_action            = "block"
    allowed_ip_cidrs          = ["203.0.113.10/32"]
    ip_allowlist_bypass_rules = false
    rate_limit_per_5_minutes  = 1000
    managed_rule_groups = [
      { name = "AWSManagedRulesCommonRuleSet" },
    ]
  }

  assert {
    condition = one([
      for rule in aws_wafv2_web_acl.this.rule : rule
      if rule.name == "ip-allowlist"
    ]).priority == 110
    error_message = "Strict allowlist mode must evaluate rate and managed rules before allowing listed IPs."
  }
}

run "strict_ip_allowlist_requires_default_block" {
  command = plan

  variables {
    allowed_ip_cidrs          = ["203.0.113.10/32"]
    ip_allowlist_bypass_rules = false
  }

  expect_failures = [
    aws_wafv2_web_acl.this,
  ]
}

run "premium_group_requires_matching_configuration" {
  command = plan

  variables {
    managed_rule_groups = [
      { name = "AWSManagedRulesBotControlRuleSet" },
    ]
  }

  expect_failures = [
    var.managed_rule_groups,
  ]
}
