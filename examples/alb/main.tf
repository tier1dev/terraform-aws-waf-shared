terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# One REGIONAL web ACL shared across every ALB (and API Gateway stage) in the
# region — pass all their ARNs to association_resource_arns.
module "waf" {
  source = "../.."

  name  = "shared-regional"
  scope = "REGIONAL"

  allowed_ip_cidrs         = ["203.0.113.0/24"]
  rate_limit_per_5_minutes = 2000

  managed_rule_groups = [
    { name = "AWSManagedRulesCommonRuleSet" },
    { name = "AWSManagedRulesKnownBadInputsRuleSet" },
    { name = "AWSManagedRulesAmazonIpReputationList" },
    { name = "AWSManagedRulesSQLiRuleSet", override_action = "count" },
  ]

  association_resource_arns = [
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188",
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/api/9e8f0a1b2c3d4e5f",
  ]

  tags = {
    Application = "waf-shared"
    Environment = "prod"
  }
}
