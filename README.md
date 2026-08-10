# terraform-aws-waf-shared

One WAFv2 web ACL, shared across many CloudFront distributions or ALBs.

WAF pricing is per web ACL ($5/mo), per rule ($1/mo), and per million requests —
but associating an existing ACL with another resource is free. This module
leans into that: define the rules once, attach the ACL everywhere.

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
  source = "git::https://github.com/tier1dev/terraform-aws-waf-shared.git?ref=v0.2.0"

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
  source = "git::https://github.com/tier1dev/terraform-aws-waf-shared.git?ref=v0.2.0"

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

> **Version note:** the alarm inputs are currently available on `main` and are
> not part of the existing `v0.2.0` tag. Cut a new module release before pinning
> production consumers to this feature.

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
Add a `rule_action_override` for it before flipping the group to `none`.

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
| <a name="input_allowed_ip_cidrs"></a> [allowed\_ip\_cidrs](#input\_allowed\_ip\_cidrs) | IPv4 CIDR blocks that bypass all subsequent rules (admin/office exceptions). Creates an IP set and an allow rule at the highest priority. | `list(string)` | `[]` | no |
| <a name="input_association_resource_arns"></a> [association\_resource\_arns](#input\_association\_resource\_arns) | ARNs of REGIONAL resources (ALBs, API Gateway stages, AppSync APIs) to associate with the web ACL. Must be empty for CLOUDFRONT scope — attach via the distribution's web\_acl\_id instead. | `list(string)` | `[]` | no |
| <a name="input_blocked_country_codes"></a> [blocked\_country\_codes](#input\_blocked\_country\_codes) | ISO 3166-1 alpha-2 country codes to block. Mutually exclusive with allowed\_country\_codes. | `list(string)` | `[]` | no |
| <a name="input_blocked_requests_alarm_threshold"></a> [blocked\_requests\_alarm\_threshold](#input\_blocked\_requests\_alarm\_threshold) | Blocked requests across the shared web ACL in one 5-minute period that can trigger the production alarm. Tune for aggregate traffic across every association. | `number` | `100` | no |
| <a name="input_default_action"></a> [default\_action](#input\_default\_action) | Default action for requests that match no rule: allow or block. | `string` | `"allow"` | no |
| <a name="input_enable_logging"></a> [enable\_logging](#input\_enable\_logging) | Send WAF request logs to a CloudWatch log group. Disabled by default to keep costs down. | `bool` | `false` | no |
| <a name="input_enable_production_alarms"></a> [enable\_production\_alarms](#input\_enable\_production\_alarms) | Create cost-incurring production CloudWatch alarms for blocked requests. Disabled by default and rejected unless the required Environment tag is prod. | `bool` | `false` | no |
| <a name="input_log_kms_key_arn"></a> [log\_kms\_key\_arn](#input\_log\_kms\_key\_arn) | Optional KMS key ARN to encrypt the WAF log group. | `string` | `null` | no |
| <a name="input_log_retention_days"></a> [log\_retention\_days](#input\_log\_retention\_days) | Retention in days for the WAF CloudWatch log group. | `number` | `14` | no |
| <a name="input_managed_rule_groups"></a> [managed\_rule\_groups](#input\_managed\_rule\_groups) | AWS managed rule groups to attach, evaluated in list order. Set override\_action to count to run a group in detection-only mode. | <pre>list(object({<br/>    name            = string<br/>    vendor_name     = optional(string, "AWS")<br/>    override_action = optional(string, "none")<br/>  }))</pre> | <pre>[<br/>  {<br/>    "name": "AWSManagedRulesCommonRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesKnownBadInputsRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesAmazonIpReputationList"<br/>  }<br/>]</pre> | no |
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
