# terraform-aws-waf-shared

One WAFv2 web ACL, shared across many CloudFront distributions or ALBs.

WAF pricing is per web ACL ($5/mo), per rule ($1/mo), and per million requests —
but associating an existing ACL with another resource is free. This module
leans into that: define the rules once, attach the ACL everywhere.

The module creates a single web ACL in one scope. Instantiate it twice if you
need both CloudFront and regional coverage.

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
  source = "git::https://github.com/tier1dev/terraform-aws-waf-shared.git?ref=v0.1.0"

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
  source = "git::https://github.com/tier1dev/terraform-aws-waf-shared.git?ref=v0.1.0"

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

## Rule evaluation order

| Priority | Rule | Enabled by |
|----------|------|------------|
| 0 | IP allowlist (allow, bypasses everything below) | `allowed_ip_cidrs` |
| 10 | Geo blocklist or geo allowlist | `blocked_country_codes` / `allowed_country_codes` |
| 20 | Rate limit per source IP | `rate_limit_per_5_minutes` |
| 100+ | AWS managed rule groups, in list order | `managed_rule_groups` |

Set `override_action = "count"` on a managed rule group to run it in
detection-only mode before enforcing it.

## Cost warning

WAF charges a fixed monthly fee the moment the ACL exists — **you pay even
with zero traffic**. Rough estimates (us-east-1 list prices, rounded):

| Configuration | Est. monthly baseline, no traffic |
|---------------|-----------------------------------|
| ACL + default 3 managed rule groups | ~$8 |
| ACL + every module feature on (6 managed groups, geo, rate limit, IP allowlist) | ~$14 |
| Both scopes instantiated (CloudFront + regional) with everything on | ~$28 |

On top of the baseline:

- Requests: ~$0.60 per million, billed once per ACL no matter how many
  resources share it. Sharing one ACL is the whole point of this module.
- Some managed rule groups carry their own subscription and per-request fees
  (Bot Control, Fraud Control, Account Takeover Prevention — roughly $10/mo
  each plus usage). None are in the module defaults; check before adding them.
- Logging is off by default. `enable_logging = true` adds WAF log delivery
  plus CloudWatch ingestion (~$0.50/GB) and storage.

These are estimates only — pricing varies by region and changes over time.
Verify against the [AWS WAF pricing page](https://aws.amazon.com/waf/pricing/)
before deploying. **You are responsible for all costs this module incurs in
your account.**

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0, < 7.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.58.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.waf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_wafv2_ip_set.allowlist](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_web_acl.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |
| [aws_wafv2_web_acl_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association) | resource |
| [aws_wafv2_web_acl_logging_configuration.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration) | resource |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_allowed_country_codes"></a> [allowed\_country\_codes](#input\_allowed\_country\_codes) | ISO 3166-1 alpha-2 country codes to allow. When non-empty, requests from any other country are blocked. Mutually exclusive with blocked\_country\_codes. | `list(string)` | `[]` | no |
| <a name="input_allowed_ip_cidrs"></a> [allowed\_ip\_cidrs](#input\_allowed\_ip\_cidrs) | IPv4 CIDR blocks that bypass all subsequent rules (admin/office exceptions). Creates an IP set and an allow rule at the highest priority. | `list(string)` | `[]` | no |
| <a name="input_association_resource_arns"></a> [association\_resource\_arns](#input\_association\_resource\_arns) | ARNs of REGIONAL resources (ALBs, API Gateway stages, AppSync APIs) to associate with the web ACL. Must be empty for CLOUDFRONT scope — attach via the distribution's web\_acl\_id instead. | `list(string)` | `[]` | no |
| <a name="input_blocked_country_codes"></a> [blocked\_country\_codes](#input\_blocked\_country\_codes) | ISO 3166-1 alpha-2 country codes to block. Mutually exclusive with allowed\_country\_codes. | `list(string)` | `[]` | no |
| <a name="input_default_action"></a> [default\_action](#input\_default\_action) | Default action for requests that match no rule: allow or block. | `string` | `"allow"` | no |
| <a name="input_enable_logging"></a> [enable\_logging](#input\_enable\_logging) | Send WAF request logs to a CloudWatch log group. Disabled by default to keep costs down. | `bool` | `false` | no |
| <a name="input_log_kms_key_arn"></a> [log\_kms\_key\_arn](#input\_log\_kms\_key\_arn) | Optional KMS key ARN to encrypt the WAF log group. | `string` | `null` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | Retention in days for the WAF CloudWatch log group. | `number` | `14` | no |
| <a name="input_managed_rule_groups"></a> [managed\_rule\_groups](#input\_managed\_rule\_groups) | AWS managed rule groups to attach, evaluated in list order. Set override\_action to count to run a group in detection-only mode. | <pre>list(object({<br/>    name            = string<br/>    vendor_name     = optional(string, "AWS")<br/>    override_action = optional(string, "none")<br/>  }))</pre> | <pre>[<br/>  {<br/>    "name": "AWSManagedRulesCommonRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesKnownBadInputsRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesAmazonIpReputationList"<br/>  }<br/>]</pre> | no |
| <a name="input_name"></a> [name](#input\_name) | Name of the web ACL. Also used as a prefix for related resources (IP set, log group, metrics). | `string` | n/a | yes |
| <a name="input_rate_limit_per_5_minutes"></a> [rate\_limit\_per\_5\_minutes](#input\_rate\_limit\_per\_5\_minutes) | Maximum requests allowed from a single IP per 5-minute window before it is blocked. Set to 0 to disable rate limiting. | `number` | `0` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Scope of the web ACL: CLOUDFRONT (requires the us-east-1 provider) or REGIONAL (ALB, API Gateway, AppSync). | `string` | `"REGIONAL"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags applied to all resources created by this module. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_allowlist_ip_set_arn"></a> [allowlist\_ip\_set\_arn](#output\_allowlist\_ip\_set\_arn) | ARN of the IP allowlist set, or null when allowed\_ip\_cidrs is empty. |
| <a name="output_log_group_arn"></a> [log\_group\_arn](#output\_log\_group\_arn) | ARN of the WAF CloudWatch log group, or null when logging is disabled. |
| <a name="output_log_group_name"></a> [log\_group\_name](#output\_log\_group\_name) | Name of the WAF CloudWatch log group, or null when logging is disabled. |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | ARN of the web ACL. For CLOUDFRONT scope, set this as web\_acl\_id on each distribution. |
| <a name="output_web_acl_capacity"></a> [web\_acl\_capacity](#output\_web\_acl\_capacity) | Web ACL capacity units (WCUs) currently in use. |
| <a name="output_web_acl_id"></a> [web\_acl\_id](#output\_web\_acl\_id) | ID of the web ACL. |
| <a name="output_web_acl_name"></a> [web\_acl\_name](#output\_web\_acl\_name) | Name of the web ACL. |
<!-- END_TF_DOCS -->

## License

AGPL-3.0 — see [LICENSE](LICENSE).
