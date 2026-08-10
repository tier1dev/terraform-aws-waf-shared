output "web_acl_arn" {
  description = "ARN of the web ACL. For CLOUDFRONT scope, set this as web_acl_id on each distribution."
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID of the web ACL."
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_name" {
  description = "Name of the web ACL."
  value       = aws_wafv2_web_acl.this.name
}

output "web_acl_capacity" {
  description = "Web ACL capacity units (WCUs) currently in use."
  value       = aws_wafv2_web_acl.this.capacity
}

output "allowlist_ip_set_arn" {
  description = "ARN of the IP allowlist set, or null when allowed_ip_cidrs is empty."
  value       = one(aws_wafv2_ip_set.allowlist[*].arn)
}

output "log_group_name" {
  description = "Name of the WAF CloudWatch log group, or null when logging is disabled."
  value       = one(aws_cloudwatch_log_group.waf[*].name)
}

output "log_group_arn" {
  description = "ARN of the WAF CloudWatch log group, or null when logging is disabled."
  value       = one(aws_cloudwatch_log_group.waf[*].arn)
}

output "notification_alarm_name" {
  description = "Name of the production alarm that owns notification actions, or null when production alarms are disabled."
  value = var.enable_production_alarms ? (
    local.rate_limit_enabled ?
    aws_cloudwatch_composite_alarm.security_events[0].alarm_name :
    aws_cloudwatch_metric_alarm.blocked_requests[0].alarm_name
  ) : null
}

output "notification_alarm_arn" {
  description = "ARN of the production alarm that owns notification actions, or null when production alarms are disabled."
  value = var.enable_production_alarms ? (
    local.rate_limit_enabled ?
    aws_cloudwatch_composite_alarm.security_events[0].arn :
    aws_cloudwatch_metric_alarm.blocked_requests[0].arn
  ) : null
}
