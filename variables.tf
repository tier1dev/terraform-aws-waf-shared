variable "name" {
  description = "Name of the web ACL. Also used as a prefix for related resources (IP set, log group, metrics)."
  type        = string
}

variable "scope" {
  description = "Scope of the web ACL: CLOUDFRONT (requires the us-east-1 provider) or REGIONAL (ALB, API Gateway, AppSync)."
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.scope)
    error_message = "The scope must be CLOUDFRONT or REGIONAL."
  }
}

variable "default_action" {
  description = "Default action for requests that match no rule: allow or block."
  type        = string
  default     = "allow"

  validation {
    condition     = contains(["allow", "block"], var.default_action)
    error_message = "The default_action must be allow or block."
  }
}

variable "managed_rule_groups" {
  description = "Managed rule groups to attach, evaluated in list order. Standard AWS and Marketplace groups need only name/vendor_name. AWS premium groups require their matching configuration object."
  type = list(object({
    name                  = string
    vendor_name           = optional(string, "AWS")
    version               = optional(string)
    override_action       = optional(string, "none")
    rule_action_overrides = optional(map(string), {})
    bot_control = optional(object({
      inspection_level        = string
      enable_machine_learning = optional(bool, false)
    }))
    account_takeover_prevention = optional(object({
      login_path           = string
      enable_regex_in_path = optional(bool, false)
      request_inspection = optional(object({
        payload_type              = string
        username_field_identifier = string
        password_field_identifier = string
      }))
      response_inspection = optional(object({
        type            = string
        success_strings = optional(set(string), [])
        failure_strings = optional(set(string), [])
        success_codes   = optional(set(number), [])
        failure_codes   = optional(set(number), [])
        header_name     = optional(string)
        json_identifier = optional(string)
      }))
    }))
    account_creation_fraud_prevention = optional(object({
      creation_path          = string
      registration_page_path = string
      enable_regex_in_path   = optional(bool, false)
      request_inspection = object({
        payload_type                   = string
        username_field_identifier      = optional(string)
        password_field_identifier      = optional(string)
        email_field_identifier         = optional(string)
        address_field_identifiers      = optional(list(string), [])
        phone_number_field_identifiers = optional(list(string), [])
      })
      response_inspection = optional(object({
        type            = string
        success_strings = optional(set(string), [])
        failure_strings = optional(set(string), [])
        success_codes   = optional(set(number), [])
        failure_codes   = optional(set(number), [])
        header_name     = optional(string)
        json_identifier = optional(string)
      }))
    }))
    anti_ddos = optional(object({
      sensitivity_to_block = optional(string, "LOW")
      client_side_challenge = object({
        usage_of_action    = string
        sensitivity        = optional(string, "HIGH")
        exempt_uri_regexes = optional(list(string), [])
      })
    }))
  }))
  default = [
    { name = "AWSManagedRulesCommonRuleSet" },
    { name = "AWSManagedRulesKnownBadInputsRuleSet" },
    { name = "AWSManagedRulesAmazonIpReputationList" },
  ]

  validation {
    condition     = alltrue([for g in var.managed_rule_groups : contains(["none", "count"], g.override_action)])
    error_message = "Each managed rule group override_action must be none or count."
  }

  validation {
    condition = alltrue(flatten([
      for g in var.managed_rule_groups : [
        for action in values(g.rule_action_overrides) :
        contains(["allow", "block", "captcha", "challenge", "count"], action)
      ]
    ]))
    error_message = "Each rule_action_overrides value must be allow, block, captcha, challenge, or count."
  }

  validation {
    condition     = length(distinct([for g in var.managed_rule_groups : g.name])) == length(var.managed_rule_groups)
    error_message = "Each managed rule group name may appear only once."
  }

  validation {
    condition = alltrue([
      for g in var.managed_rule_groups :
      (g.vendor_name == "AWS" && g.name == "AWSManagedRulesBotControlRuleSet") == (g.bot_control != null) &&
      (g.vendor_name == "AWS" && g.name == "AWSManagedRulesATPRuleSet") == (g.account_takeover_prevention != null) &&
      (g.vendor_name == "AWS" && g.name == "AWSManagedRulesACFPRuleSet") == (g.account_creation_fraud_prevention != null) &&
      (g.vendor_name == "AWS" && g.name == "AWSManagedRulesAntiDDoSRuleSet") == (g.anti_ddos != null)
    ])
    error_message = "Bot Control, ATP, ACFP, and Anti-DDoS groups require their matching configuration object, and those objects may only be used with the matching AWS group name."
  }

  validation {
    condition = alltrue([
      for g in var.managed_rule_groups : try(
        contains(["COMMON", "TARGETED"], g.bot_control.inspection_level) &&
        (g.bot_control.inspection_level == "TARGETED" || !g.bot_control.enable_machine_learning),
        true
      )
    ])
    error_message = "Bot Control inspection_level must be COMMON or TARGETED; machine learning is only valid for TARGETED inspection."
  }

  validation {
    condition = alltrue([
      for g in var.managed_rule_groups : try(
        contains(["JSON", "FORM_ENCODED"], g.account_takeover_prevention.request_inspection.payload_type),
        true
        ) && try(
        contains(["JSON", "FORM_ENCODED"], g.account_creation_fraud_prevention.request_inspection.payload_type),
        true
      )
    ])
    error_message = "ATP and ACFP request payload_type must be JSON or FORM_ENCODED."
  }

  validation {
    condition = alltrue(flatten([
      for g in var.managed_rule_groups : [
        for response in [
          try(g.account_takeover_prevention.response_inspection, null),
          try(g.account_creation_fraud_prevention.response_inspection, null),
          ] : (
          response.type == "STATUS_CODE" ? length(response.success_codes) > 0 && length(response.failure_codes) > 0 :
          response.type == "HEADER" ? response.header_name != null && length(response.success_strings) > 0 && length(response.failure_strings) > 0 :
          response.type == "JSON" ? response.json_identifier != null && length(response.success_strings) > 0 && length(response.failure_strings) > 0 :
          response.type == "BODY_CONTAINS" ? length(response.success_strings) > 0 && length(response.failure_strings) > 0 :
          false
        ) if response != null
      ]
    ]))
    error_message = "Response inspection type must be STATUS_CODE, HEADER, JSON, or BODY_CONTAINS and include the matching success/failure values and identifier."
  }

  validation {
    condition = alltrue([
      for g in var.managed_rule_groups : try(
        contains(["LOW", "MEDIUM", "HIGH"], g.anti_ddos.sensitivity_to_block) &&
        contains(["LOW", "MEDIUM", "HIGH"], g.anti_ddos.client_side_challenge.sensitivity) &&
        contains(["ENABLED", "DISABLED"], g.anti_ddos.client_side_challenge.usage_of_action),
        true
      )
    ])
    error_message = "Anti-DDoS sensitivities must be LOW, MEDIUM, or HIGH, and usage_of_action must be ENABLED or DISABLED."
  }
}

variable "allowed_country_codes" {
  description = "ISO 3166-1 alpha-2 country codes to allow. When non-empty, requests from any other country are blocked. Mutually exclusive with blocked_country_codes."
  type        = list(string)
  default     = []
}

variable "blocked_country_codes" {
  description = "ISO 3166-1 alpha-2 country codes to block. Mutually exclusive with allowed_country_codes."
  type        = list(string)
  default     = []
}

variable "allowed_ip_cidrs" {
  description = "IPv4 CIDR blocks for the allowlist IP set. They bypass later rules by default; set ip_allowlist_bypass_rules=false with default_action=block to inspect them before the final allow."
  type        = list(string)
  default     = []
}

variable "ip_allowlist_bypass_rules" {
  description = "When true, allowed IPs bypass all other rules. Set false with default_action=block to inspect and rate-limit allowed IPs before allowing them; non-allowed IPs then reach the default block action."
  type        = bool
  default     = true
}

variable "rate_limit_per_5_minutes" {
  description = "Maximum requests allowed from a single IP per 5-minute window before it is blocked. Set to 0 to disable rate limiting."
  type        = number
  default     = 0
}

variable "association_resource_arns" {
  description = "ARNs of REGIONAL resources (ALBs, API Gateway stages, AppSync APIs) to associate with the web ACL. Must be empty for CLOUDFRONT scope — attach via the distribution's web_acl_id instead."
  type        = list(string)
  default     = []
}

variable "enable_logging" {
  description = "Send WAF request logs to a CloudWatch log group. Disabled by default to keep costs down."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention in days for the WAF CloudWatch log group."
  type        = number
  default     = 14
}

variable "log_kms_key_arn" {
  description = "Optional KMS key ARN to encrypt the WAF log group."
  type        = string
  default     = null
}

variable "enable_production_alarms" {
  description = "Create cost-incurring production CloudWatch alarms for blocked requests. Disabled by default and rejected unless the required Environment tag is prod."
  type        = bool
  default     = false
}

variable "alarm_action_arns" {
  description = "SNS topic or other CloudWatch action ARNs notified by the production alarm. Keep actions in the module provider region; CloudFront alarms use us-east-1."
  type        = list(string)
  default     = []
}

variable "blocked_requests_alarm_threshold" {
  description = "Blocked requests across the shared web ACL in one 5-minute period that can trigger the production alarm. Tune for aggregate traffic across every association."
  type        = number
  default     = 100

  validation {
    condition     = var.blocked_requests_alarm_threshold > 0
    error_message = "The blocked_requests_alarm_threshold must be greater than zero."
  }
}

variable "rate_limit_blocks_alarm_threshold" {
  description = "Requests blocked by the rate-limit rule in one 5-minute period that can trigger the production alarm. Used only when rate limiting is enabled."
  type        = number
  default     = 10

  validation {
    condition     = var.rate_limit_blocks_alarm_threshold > 0
    error_message = "The rate_limit_blocks_alarm_threshold must be greater than zero."
  }
}

variable "tags" {
  description = "Tags applied to all resources created by this module."
  type        = map(string)
  default     = {}
}
