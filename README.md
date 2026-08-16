# terraform-aws-waf-shared

One WAFv2 web ACL, shared across many CloudFront distributions or ALBs.

WAF pricing is per web ACL ($5/mo), per custom rule or managed group reference
($1/mo), and per million requests — but associating an existing ACL with
another resource is free. AWS-managed groups cost one $1 reference regardless
of their internal rule count; premium groups add subscriptions and usage fees.
This module leans into sharing: define the rules once, attach the ACL everywhere.

The module creates a single web ACL in one scope. Instantiate it twice if you
need both CloudFront and regional coverage.

## Audience and companion guides

This module is for platform, security, and DevSecOps engineers who want one
reviewable AWS WAFv2 policy shared across CloudFront distributions, ALBs, API
Gateway stages, or AppSync APIs. It is the tested Terraform companion for:

- [AWS WAF and CloudFront: Enterprise Application Protection](https://www.red-team.sh/posts/aws-waf-cloudfront-application-protection/)
- [CloudFront Geo-Restriction with AWS WAF: Block Countries](https://www.red-team.sh/posts/aws-cloudfront-geographic-access-control/)

## Prerequisites

- Terraform 1.5 or newer and AWS provider 6.x.
- AWS credentials supplied through the standard provider chain, such as AWS
  IAM Identity Center, environment variables, or a named profile. Confirm the
  selected identity with `aws sts get-caller-identity`; never commit credentials.
- Least-privilege IAM permissions for the features you enable:
  - WAFv2 web ACL and IP set create/read/update/delete/tag operations.
  - `wafv2:AssociateWebACL` and `wafv2:DisassociateWebACL` for regional
    associations, or CloudFront distribution read/update permissions when the
    calling stack attaches a global ACL.
  - WAFv2 logging configuration and CloudWatch Logs group operations when
    `enable_logging = true`. The first logging setup can also require
    `iam:CreateServiceLinkedRole` for the WAF logging service-linked role.
  - CloudWatch alarm create/read/delete/tag operations when
    `enable_production_alarms = true`.
  - Access to reference any KMS key or SNS topic supplied to the module, plus
    resource policies that allow the relevant AWS service to use them.

Exact resource ARNs depend on your account and associations. Scope IAM policies
to the intended ACL, log group, alarm, KMS key, and notification topic wherever
the AWS API supports resource-level permissions.

## Quickstart

Add the module to your Terraform configuration, replace the example values,
and review the plan before applying it:

```sh
terraform init
terraform validate
terraform plan -out=waf.tfplan
terraform apply waf.tfplan
```

`terraform apply` creates billable AWS resources. Start managed rule groups in
count mode, test in a non-production environment, and only enforce them after
reviewing sampled requests and logs.

## Usage

### CloudFront (scope = CLOUDFRONT)

CLOUDFRONT-scoped ACLs must be created in us-east-1, and CloudFront
distributions attach them via their own `web_acl_id` argument (the
`aws_wafv2_web_acl_association` resource does not support CloudFront).

```hcl
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

module "waf" {
  source = "git::https://github.com/tier1dev/terraform-aws-waf-shared.git?ref=v0.3.0"

  providers = { aws = aws.us_east_1 }

  name  = "shared-cloudfront"
  scope = "CLOUDFRONT"

  blocked_country_codes    = ["RU", "KP", "IR"]
  rate_limit_per_5_minutes = 2000
}

resource "aws_cloudfront_distribution" "site" {
  web_acl_id = module.waf.web_acl_arn
  # ...
}
```

### ALB / API Gateway (scope = REGIONAL)

Regional resources associate directly — pass every ALB or stage ARN in the
region to `association_resource_arns`.

```hcl
module "waf" {
  source = "git::https://github.com/tier1dev/terraform-aws-waf-shared.git?ref=v0.3.0"

  name  = "shared-regional"
  scope = "REGIONAL"

  rate_limit_per_5_minutes = 2000

  association_resource_arns = [
    aws_lb.web.arn,
    aws_lb.api.arn,
  ]
}
```

See [examples/](examples/) for complete, validated configurations.

### Strict IP allowlist with security inspection

`allowed_ip_cidrs` defaults to an administrative bypass: listed IPs are allowed
at priority 0 and skip every later rule. For a private application where only
your networks may connect **and** their requests must still pass rate and
managed security rules, use block-by-default inspection mode:

```hcl
module "waf" {
  source = "git::https://github.com/tier1dev/terraform-aws-waf-shared.git?ref=v0.3.0"

  name  = "private-internal-app"
  scope = "REGIONAL"

  default_action            = "block"
  allowed_ip_cidrs          = ["203.0.113.10/32", "198.51.100.0/24"]
  ip_allowlist_bypass_rules = false
  rate_limit_per_5_minutes  = 1000

  managed_rule_groups = [
    {
      name            = "AWSManagedRulesCommonRuleSet"
      override_action = "count"
    },
  ]
}
```

With `ip_allowlist_bypass_rules = false`, rate and managed rules run first,
the IP allow rule runs last, and every non-allowed source reaches the Web ACL's
default block. The module rejects this mode unless `default_action = "block"`
and at least one IPv4 CIDR is configured. Start managed groups in `count`,
review logs, then change them to `none` to enforce their native actions.

## Rule evaluation order

| Priority | Rule | Enabled by |
|----------|------|------------|
| 0 | IP allowlist administrative bypass | `allowed_ip_cidrs` with `ip_allowlist_bypass_rules = true` |
| 10 | Geo blocklist or geo allowlist | `blocked_country_codes` / `allowed_country_codes` |
| 20 | Rate limit per source IP | `rate_limit_per_5_minutes` |
| 100+ | AWS managed rule groups, in list order | `managed_rule_groups` |
| After managed groups | IP allowlist after inspection | `allowed_ip_cidrs` with `ip_allowlist_bypass_rules = false` |

Set `override_action = "count"` on a managed rule group to run it in
detection-only mode before enforcing it. Use `rule_action_overrides` to tune an
individual rule without disabling the entire group:

```hcl
managed_rule_groups = [{
  name = "AWSManagedRulesCommonRuleSet"
  rule_action_overrides = {
    SizeRestrictions_BODY = "count"
  }
}]
```

## Managed rule catalog and selection guidance

The module supports all groups in the current [AWS Managed Rules
catalog](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html).
The 11 standard groups need only `name`; the four premium groups also require
the matching nested configuration shown below. An AWS-managed group is one
billable group reference even when it contains many internal rules.

| AWS managed group name | Cost class | Use when |
|------------------------|------------|----------|
| `AWSManagedRulesCommonRuleSet` | Standard | Nearly every public dynamic site or API; broad XSS, file-inclusion, SSRF, size, and OWASP-related coverage. |
| `AWSManagedRulesAdminProtectionRuleSet` | Standard | A CMS or application exposes administrative paths; prefer authentication and network restrictions as the primary control. |
| `AWSManagedRulesKnownBadInputsRuleSet` | Standard | Public applications and APIs need coverage for known exploit inputs such as Log4j, deserialization, and vulnerable paths. |
| `AWSManagedRulesSQLiRuleSet` | Standard | Untrusted request data can reach a SQL database. |
| `AWSManagedRulesLinuxRuleSet` | Standard | The application exposes Linux filesystem or local-file-inclusion attack surface; do not add it merely because Lambda runs on Linux. |
| `AWSManagedRulesUnixRuleSet` | Standard | The application interacts with POSIX paths, commands, or shells. |
| `AWSManagedRulesWindowsRuleSet` | Standard | The origin uses IIS, Windows Server, PowerShell, or Windows-hosted .NET. |
| `AWSManagedRulesPHPRuleSet` | Standard | The application executes PHP, including Laravel, Drupal, Joomla, or WordPress. |
| `AWSManagedRulesWordPressRuleSet` | Standard | WordPress only; normally combine with PHP and SQLi protection. |
| `AWSManagedRulesAmazonIpReputationList` | Standard | A public site or API should reject sources AWS associates with bots, reconnaissance, or malicious activity. |
| `AWSManagedRulesAnonymousIpList` | Standard | Product policy permits blocking VPN, proxy, Tor, and hosting-provider traffic; avoid it for privacy-sensitive consumer or remote-work applications. |
| `AWSManagedRulesBotControlRuleSet` | Premium | A public property has measured scraping, automated abuse, inventory abuse, or bot-driven cost. |
| `AWSManagedRulesATPRuleSet` | Premium | A public login endpoint has credential-stuffing or account-takeover risk. |
| `AWSManagedRulesACFPRuleSet` | Premium | A public registration flow has fake-account or signup-bonus abuse. |
| `AWSManagedRulesAntiDDoSRuleSet` | Premium | A high-value public application needs advanced Layer 7 DDoS mitigation beyond rate limits and Shield Standard. |

Recommended starting combinations:

| Application type | Start with | Add only when applicable |
|------------------|------------|--------------------------|
| Private dev, staging, or internal | Strict IP allowlist + rate limit | CRS in count mode for defense in depth |
| Static CloudFront/S3 site | Rate limit + Amazon IP reputation | CRS for dynamic routes; Bot Control only after measured scraping |
| Public REST, GraphQL, or serverless API | CRS + Known Bad Inputs + IP reputation + rate limit | SQLi for a SQL backend; tune CRS user-agent and body-size rules for API clients |
| Public SaaS | CRS + Known Bad Inputs + IP reputation + rate limit | SQLi, ATP, or ACFP according to data store and observed auth abuse |
| Ecommerce | CRS + Known Bad Inputs + SQLi + IP reputation + rate limit | Bot Control for scraping/inventory abuse; ATP/ACFP for account fraud |
| WordPress | CRS + Known Bad Inputs + SQLi + PHP + WordPress + IP reputation + rate limit | Admin Protection after verifying legitimate admin paths |
| Linux/POSIX service | CRS + Known Bad Inputs + Linux/POSIX + rate limit | SQLi when request data reaches SQL |
| Windows/IIS/.NET service | CRS + Known Bad Inputs + Windows + rate limit | SQLi when request data reaches SQL |

Do not stack groups just to fill a checklist. Overlap consumes Web ACL capacity,
increases false-positive risk, and can push the ACL beyond the 1,500 WCUs
included in base request pricing. Test each new group in count mode and promote
it independently.

### Premium managed group configuration

Premium groups are deliberately explicit so a name-only configuration cannot
reach apply and fail with a missing AWS managed-rule configuration. The module
also validates inspection levels, payload types, response selectors, and
Anti-DDoS sensitivities.

```hcl
managed_rule_groups = [
  {
    name            = "AWSManagedRulesBotControlRuleSet"
    override_action = "count"
    bot_control = {
      inspection_level        = "TARGETED" # COMMON or TARGETED
      enable_machine_learning = true       # TARGETED only
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
      # Response inspection is optional and CloudFront-only.
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
      registration_page_path = "/signup"
      creation_path          = "/register"
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
```

ATP and ACFP response inspection supports `STATUS_CODE`, `HEADER`, `JSON`, or
`BODY_CONTAINS`, and AWS supports it only on CloudFront-protected applications.
Request `payload_type` is `JSON` or `FORM_ENCODED`. Do not enable all premium
groups together as a default; scope paid inspection to the relevant login,
registration, or bot-sensitive traffic wherever AWS permits it.

## Optional production alarms

Production alarms are disabled by default. Enabling them requires non-empty
`Customer`, `Application`, `Environment`, `Owner`, and `Costcenter` tags, with
`Environment = "prod"`; Terraform rejects dev or untagged alarm plans.

```hcl
module "waf" {
  # ...the normal module arguments...

  enable_production_alarms           = true
  blocked_requests_alarm_threshold  = 100
  rate_limit_blocks_alarm_threshold = 10
  alarm_action_arns = [
    "arn:aws:sns:us-east-1:123456789012:waf-alerts",
  ]

  tags = {
    Customer    = "example"
    Application = "shared-web"
    Environment = "prod"
    Owner       = "security@example.com"
    Costcenter  = "security"
  }
}
```

The thresholds are starting points for a five-minute period. Because this is a
shared ACL, tune them against aggregate traffic from every association. A high
block count can also be expected for a geo blocklist or a block-by-default ACL.

When rate limiting is off, one aggregate metric alarm owns the notification
actions. When it is on, two metric alarms feed one composite alarm so only the
composite sends notifications. Missing WAF datapoints are treated as healthy
because WAF publishes these metrics only when the value is nonzero. CloudFront
alarms and their SNS topics must use the module's us-east-1 provider.

CloudWatch alarm charges apply only after opting in. At current us-east-1 list
prices, the aggregate-only setup is about $0.10/month; the two metric alarms and
one composite alarm are about $0.70/month. Verify current pricing on the
[CloudWatch pricing page](https://aws.amazon.com/cloudwatch/pricing/).

> **Version note:** `v0.3.0` adds the alarm inputs, premium managed-group
> configuration, per-rule overrides, and inspected IP allowlist mode described
> in this README.

## Safe smoke test

Use the included script only against an HTTPS health or other read-only endpoint
you own:

```sh
python scripts/waf_smoke_test.py \
  --url https://staging.example.com/health \
  --expected-status 200
```

It sends exactly one GET, does not download the response body, refuses redirects
and embedded URL credentials, and never sends attack payloads or enough traffic
to exercise rate limiting. This verifies reachability through the protected
endpoint, not that every rule blocks correctly. Confirm the ACL attachment with
AWS read APIs, then use count mode, sampled requests, and the report below to
tune enforcement safely.

## Reading count mode results

Count mode only helps if you read the counts. `scripts/waf_count_report.py`
answers the question that decides whether a group is safe to enforce: how much
real traffic it would have blocked, which rule fired, and against which URIs.

Requires `enable_logging = true` — the script reads the log group this module
creates.

```sh
pip install boto3

# What would enforcing these groups have blocked in the last 24 hours?
./scripts/waf_count_report.py --name my-acl

# A week, as JSON
./scripts/waf_count_report.py --name my-acl --hours 168 --format json

# CLOUDFRONT-scoped ACLs log to us-east-1 wherever the origin runs
./scripts/waf_count_report.py --name my-acl --region us-east-1
```

Sample output:

```
Total requests logged:          20000
Requests matching a count rule: 66
Would be newly blocked:         61 (0.30% of traffic)

  RULE GROUP                                             MATCHED  NEW BLOCKS  % TRAFFIC
  ---------------------------------------------------- --------- ----------- ----------
  AWS#AWSManagedRulesCommonRuleSet                            52          52      0.26%
  AWS#AWSManagedRulesKnownBadInputsRuleSet                     5           0      0.00%

  AWS#AWSManagedRulesCommonRuleSet / SQLi_BODY
    matches: 52   would newly block: 52   distinct client IPs: 4
    top URIs:       /api/graphql (40), /upload (12)
    e.g. POST /api/graphql from 10.0.0.0 (US) currently ALLOW
```

Read that as: `SQLi_BODY` is about to start blocking your own GraphQL endpoint.
Add it to `rule_action_overrides` before flipping the group to `none`.

**Matched and new blocks differ on purpose.** A request can match several count
rules at once, and a request some other rule already blocks would not change
outcome if a counted rule started enforcing too. Summing rule match counts
overstates the impact, sometimes by a lot. The report deduplicates by request,
and `NEW BLOCKS` is the number that matters. In the sample above,
KnownBadInputs matched 5 requests but would block 0 new ones — all 5 were
already blocked by an enforcing rule.

To gate a pipeline on it, set a budget:

```sh
./scripts/waf_count_report.py --name my-acl --max-block-percent 0.25
```

Exits 1 when the projected new block rate exceeds the threshold, 0 when it is
at or under it, and 2 when the log group does not exist.

Note that Insights caps a query at 10,000 rows. The report warns when it hits
that ceiling, in which case the counts are a floor rather than a total — narrow
the window with `--hours`.

### Costs

Insights bills per GB scanned. The report runs two queries per invocation (one
counting total requests, one fetching count matches), both bounded by
`--hours`. On a busy ACL, prefer short windows over a week-long lookback.

## Repository validation

The same core checks run in CI:

```sh
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate
terraform test
python -m pytest tests/ -q
ruff check --line-length 100 scripts/ tests/
```

CI also initializes and validates both configurations under `examples/`, then
runs TFLint and Trivy configuration scanning.

## Cost warning

WAF charges a fixed monthly fee the moment the ACL exists — **you pay even
with zero traffic**. As of 2026-08-15, us-east-1 list pricing for the base WAF
components is:

| Component | Price |
|-----------|------:|
| Web ACL | $5/month |
| Custom rule, rate rule, or managed group reference | $1/month each |
| IP set | No separate charge |
| Requests at up to 1,500 WCUs | $0.60/million |
| Each additional 500 WCUs above 1,500 | Additional $0.20/million |

AWS charges one $1 managed-group reference for an AWS-managed group, not $1
for every internal rule in that group. Rules inside a customer-created rule
group remain $1 each, plus $1 for attaching that customer-created group.

The four premium AWS groups add the following charges on top of the $1 managed
group reference, $5 ACL, and ordinary WAF request fee:

| Premium group | Fixed addition on an existing ACL | Premium request fee |
|---------------|----------------------------------:|--------------------:|
| Bot Control — Common | $11/month | First 10M inspected requests included, then $1/million |
| Bot Control — Targeted | $11/month | First 1M inspected requests included, then $10/million |
| Account Takeover Prevention (ATP) | $11/month | First 10K Fraud Control requests included, then tiered from $1/1,000 |
| Account Creation Fraud Prevention (ACFP) | $11/month | Same combined Fraud Control tiers |
| Anti-DDoS | $21/month | $0.15/million inspected requests |

The fixed premium additions include the normal $1 group reference plus a $10
Bot Control/ATP/ACFP subscription or $20 Anti-DDoS subscription. If ATP and
ACFP are both enabled, each has its own subscription and group reference; their
analyzed requests share the Fraud Control usage tiers:

| Combined ATP/ACFP requests per month | Fraud Control price |
|--------------------------------------|--------------------:|
| First 10,000 | Included |
| 10K–2M | $1.00/1,000 |
| 2M–5M | $0.70/1,000 |
| 5M–15M | $0.40/1,000 |
| 15M–30M | $0.20/1,000 |
| Above 30M | $0.05/1,000 |

Low-traffic fixed-cost examples, before request and logging charges:

| Configuration | Estimated monthly baseline |
|---------------|---------------------------:|
| ACL + IP allow rule | $6 |
| ACL + IP allow + rate limit + CRS | $8 |
| Previous row + Known Bad Inputs | $9 |
| $8 baseline + Common or Targeted Bot Control | $19 |
| $8 baseline + ATP with fewer than 10K analyzed logins | $19 |
| $8 baseline + both ATP and ACFP | $30 plus Fraud Control usage |
| $8 baseline + Anti-DDoS | $29 plus $0.15/million inspected |

For a strict IP-restricted application, premium groups are normally poor value:
the allowlist already excludes outside bots, fraudulent registrations,
credential stuffing, and most application-layer attack traffic. Prefer the $8
IP allowlist + rate limit + CRS configuration unless logs demonstrate a threat
the premium service addresses.

Logging is off by default. `enable_logging = true` can add CloudWatch ingestion
and storage charges. CAPTCHA attempts, challenge responses, increased body
inspection, Marketplace groups, and provider-region differences can also add
cost. Prices change; verify the current [AWS WAF pricing
page](https://aws.amazon.com/waf/pricing/) before deploying. **You are
responsible for all costs this module incurs in your account.**

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.1, < 7.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.58.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_composite_alarm.security_events](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_composite_alarm) | resource |
| [aws_cloudwatch_log_group.waf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_metric_alarm.blocked_requests](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.rate_limit_blocks](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_wafv2_ip_set.allowlist](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_web_acl.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |
| [aws_wafv2_web_acl_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association) | resource |
| [aws_wafv2_web_acl_logging_configuration.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration) | resource |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alarm_action_arns"></a> [alarm\_action\_arns](#input\_alarm\_action\_arns) | SNS topic or other CloudWatch action ARNs notified by the production alarm. Keep actions in the module provider region; CloudFront alarms use us-east-1. | `list(string)` | `[]` | no |
| <a name="input_allowed_country_codes"></a> [allowed\_country\_codes](#input\_allowed\_country\_codes) | ISO 3166-1 alpha-2 country codes to allow. When non-empty, requests from any other country are blocked. Mutually exclusive with blocked\_country\_codes. | `list(string)` | `[]` | no |
| <a name="input_allowed_ip_cidrs"></a> [allowed\_ip\_cidrs](#input\_allowed\_ip\_cidrs) | IPv4 CIDR blocks for the allowlist IP set. They bypass later rules by default; set ip\_allowlist\_bypass\_rules=false with default\_action=block to inspect them before the final allow. | `list(string)` | `[]` | no |
| <a name="input_association_resource_arns"></a> [association\_resource\_arns](#input\_association\_resource\_arns) | ARNs of REGIONAL resources (ALBs, API Gateway stages, AppSync APIs) to associate with the web ACL. Must be empty for CLOUDFRONT scope — attach via the distribution's web\_acl\_id instead. | `list(string)` | `[]` | no |
| <a name="input_blocked_country_codes"></a> [blocked\_country\_codes](#input\_blocked\_country\_codes) | ISO 3166-1 alpha-2 country codes to block. Mutually exclusive with allowed\_country\_codes. | `list(string)` | `[]` | no |
| <a name="input_blocked_requests_alarm_threshold"></a> [blocked\_requests\_alarm\_threshold](#input\_blocked\_requests\_alarm\_threshold) | Blocked requests across the shared web ACL in one 5-minute period that can trigger the production alarm. Tune for aggregate traffic across every association. | `number` | `100` | no |
| <a name="input_default_action"></a> [default\_action](#input\_default\_action) | Default action for requests that match no rule: allow or block. | `string` | `"allow"` | no |
| <a name="input_enable_logging"></a> [enable\_logging](#input\_enable\_logging) | Send WAF request logs to a CloudWatch log group. Disabled by default to keep costs down. | `bool` | `false` | no |
| <a name="input_enable_production_alarms"></a> [enable\_production\_alarms](#input\_enable\_production\_alarms) | Create cost-incurring production CloudWatch alarms for blocked requests. Disabled by default and rejected unless the required Environment tag is prod. | `bool` | `false` | no |
| <a name="input_ip_allowlist_bypass_rules"></a> [ip\_allowlist\_bypass\_rules](#input\_ip\_allowlist\_bypass\_rules) | When true, allowed IPs bypass all other rules. Set false with default\_action=block to inspect and rate-limit allowed IPs before allowing them; non-allowed IPs then reach the default block action. | `bool` | `true` | no |
| <a name="input_log_kms_key_arn"></a> [log\_kms\_key\_arn](#input\_log\_kms\_key\_arn) | Optional KMS key ARN to encrypt the WAF log group. | `string` | `null` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | Retention in days for the WAF CloudWatch log group. | `number` | `14` | no |
| <a name="input_managed_rule_groups"></a> [managed\_rule\_groups](#input\_managed\_rule\_groups) | Managed rule groups to attach, evaluated in list order. Standard AWS and Marketplace groups need only name/vendor\_name. AWS premium groups require their matching configuration object. | <pre>list(object({<br/>    name                  = string<br/>    vendor_name           = optional(string, "AWS")<br/>    version               = optional(string)<br/>    override_action       = optional(string, "none")<br/>    rule_action_overrides = optional(map(string), {})<br/>    bot_control = optional(object({<br/>      inspection_level        = string<br/>      enable_machine_learning = optional(bool, false)<br/>    }))<br/>    account_takeover_prevention = optional(object({<br/>      login_path           = string<br/>      enable_regex_in_path = optional(bool, false)<br/>      request_inspection = optional(object({<br/>        payload_type              = string<br/>        username_field_identifier = string<br/>        password_field_identifier = string<br/>      }))<br/>      response_inspection = optional(object({<br/>        type            = string<br/>        success_strings = optional(set(string), [])<br/>        failure_strings = optional(set(string), [])<br/>        success_codes   = optional(set(number), [])<br/>        failure_codes   = optional(set(number), [])<br/>        header_name     = optional(string)<br/>        json_identifier = optional(string)<br/>      }))<br/>    }))<br/>    account_creation_fraud_prevention = optional(object({<br/>      creation_path          = string<br/>      registration_page_path = string<br/>      enable_regex_in_path   = optional(bool, false)<br/>      request_inspection = object({<br/>        payload_type                   = string<br/>        username_field_identifier      = optional(string)<br/>        password_field_identifier      = optional(string)<br/>        email_field_identifier         = optional(string)<br/>        address_field_identifiers      = optional(list(string), [])<br/>        phone_number_field_identifiers = optional(list(string), [])<br/>      })<br/>      response_inspection = optional(object({<br/>        type            = string<br/>        success_strings = optional(set(string), [])<br/>        failure_strings = optional(set(string), [])<br/>        success_codes   = optional(set(number), [])<br/>        failure_codes   = optional(set(number), [])<br/>        header_name     = optional(string)<br/>        json_identifier = optional(string)<br/>      }))<br/>    }))<br/>    anti_ddos = optional(object({<br/>      sensitivity_to_block = optional(string, "LOW")<br/>      client_side_challenge = object({<br/>        usage_of_action    = string<br/>        sensitivity        = optional(string, "HIGH")<br/>        exempt_uri_regexes = optional(list(string), [])<br/>      })<br/>    }))<br/>  }))</pre> | <pre>[<br/>  {<br/>    "name": "AWSManagedRulesCommonRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesKnownBadInputsRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesAmazonIpReputationList"<br/>  }<br/>]</pre> | no |
| <a name="input_name"></a> [name](#input\_name) | Name of the web ACL. Also used as a prefix for related resources (IP set, log group, metrics). | `string` | n/a | yes |
| <a name="input_rate_limit_blocks_alarm_threshold"></a> [rate\_limit\_blocks\_alarm\_threshold](#input\_rate\_limit\_blocks\_alarm\_threshold) | Requests blocked by the rate-limit rule in one 5-minute period that can trigger the production alarm. Used only when rate limiting is enabled. | `number` | `10` | no |
| <a name="input_rate_limit_per_5_minutes"></a> [rate\_limit\_per\_5\_minutes](#input\_rate\_limit\_per\_5\_minutes) | Maximum requests allowed from a single IP per 5-minute window before it is blocked. Set to 0 to disable rate limiting. | `number` | `0` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Scope of the web ACL: CLOUDFRONT (requires the us-east-1 provider) or REGIONAL (ALB, API Gateway, AppSync). | `string` | `"REGIONAL"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags applied to all resources created by this module. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_allowlist_ip_set_arn"></a> [allowlist\_ip\_set\_arn](#output\_allowlist\_ip\_set\_arn) | ARN of the IP allowlist set, or null when allowed\_ip\_cidrs is empty. |
| <a name="output_log_group_arn"></a> [log\_group\_arn](#output\_log\_group\_arn) | ARN of the WAF CloudWatch log group, or null when logging is disabled. |
| <a name="output_log_group_name"></a> [log\_group\_name](#output\_log\_group\_name) | Name of the WAF CloudWatch log group, or null when logging is disabled. |
| <a name="output_notification_alarm_arn"></a> [notification\_alarm\_arn](#output\_notification\_alarm\_arn) | ARN of the production alarm that owns notification actions, or null when production alarms are disabled. |
| <a name="output_notification_alarm_name"></a> [notification\_alarm\_name](#output\_notification\_alarm\_name) | Name of the production alarm that owns notification actions, or null when production alarms are disabled. |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | ARN of the web ACL. For CLOUDFRONT scope, set this as web\_acl\_id on each distribution. |
| <a name="output_web_acl_capacity"></a> [web\_acl\_capacity](#output\_web\_acl\_capacity) | Web ACL capacity units (WCUs) currently in use. |
| <a name="output_web_acl_id"></a> [web\_acl\_id](#output\_web\_acl\_id) | ID of the web ACL. |
| <a name="output_web_acl_name"></a> [web\_acl\_name](#output\_web\_acl\_name) | Name of the web ACL. |
<!-- END_TF_DOCS -->

## License

AGPL-3.0 — see [LICENSE](LICENSE).
