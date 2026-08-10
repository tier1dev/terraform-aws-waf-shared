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
  description = "AWS managed rule groups to attach, evaluated in list order. Set override_action to count to run a group in detection-only mode."
  type = list(object({
    name            = string
    vendor_name     = optional(string, "AWS")
    override_action = optional(string, "none")
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
  description = "IPv4 CIDR blocks that bypass all subsequent rules (admin/office exceptions). Creates an IP set and an allow rule at the highest priority."
  type        = list(string)
  default     = []
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
