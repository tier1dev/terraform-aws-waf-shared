# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-16

### Added

- Full configuration support for all current AWS premium managed rule groups:
  Bot Control, Account Takeover Prevention, Account Creation Fraud Prevention,
  and Anti-DDoS.
- Managed group versions and per-rule action overrides for targeted tuning.
- An inspected IP allowlist mode that runs rate and managed rules before the
  final allow decision while retaining the existing bypass mode by default.
- Terraform coverage for all 11 standard and four premium AWS managed groups,
  premium configuration validation, and strict allowlist ordering.
- Managed-rule selection guidance, premium configuration examples, and a
  detailed standard-versus-premium WAF cost model in the README.
- Optional, disabled-by-default production CloudWatch alarms with a single
  notification path, governance tag enforcement, and Terraform tests.
- A single-request HTTPS smoke test that refuses redirects, credentials,
  response downloads, attack payloads, and rate-limit bursts.
- Companion links, AWS/IAM prerequisites, deployment commands, and repository
  validation instructions in the README.

## [0.2.0] - 2026-08-08

### Added

- `scripts/waf_count_report.py`: reports what count-mode rules would block if
  enforced, read from the module's CloudWatch log group via Logs Insights.
  Deduplicates by request and separates net-new blocks from raw rule matches,
  breaks impact down by rule group, rule, URI, source IP and country, and can
  gate a pipeline with `--max-block-percent`.
- Test suite for the report script, plus ruff and pytest gates in pre-commit
  and CI.

## [0.1.0] - 2026-08-08

### Added

- Initial module: a single WAFv2 web ACL (CLOUDFRONT or REGIONAL scope) shared
  across many CloudFront distributions or ALBs.
- AWS managed rule groups (Common, KnownBadInputs, AmazonIpReputationList by
  default) with per-group count-mode override.
- Geographic controls: country blocklist or country allowlist.
- IP-based rate limiting and an IP allowlist that bypasses all rules.
- Optional request logging to a correctly named `aws-waf-logs-*` CloudWatch
  log group (off by default to keep costs down).
- Working examples for CloudFront and ALB consumption.
