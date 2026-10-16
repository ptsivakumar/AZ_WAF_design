output "id" {
  value       = azurerm_web_application_firewall_policy.this.id
  description = "WAF policy resource ID. Pass to firewall_policy_id on the gateway, listener or path_rule."
}

output "name" {
  value = azurerm_web_application_firewall_policy.this.name
}

output "mode" {
  value = var.mode
}

output "managed_ruleset_version" {
  value       = var.managed_ruleset_version
  description = "Recorded so the reconciliation step can detect a version change."
}

output "intended_exclusions" {
  value       = var.exclusions
  description = <<-EOT
    The exclusion set this module INTENDED to apply.
    pipelines/reconcile-exclusions.sh compares this against what is actually on the
    policy in Azure and fails the pipeline on drift. A managed rule set version change
    silently resets rule-level exclusions, so this comparison is the control.
  EOT
}

output "http_listener_ids" {
  value       = azurerm_web_application_firewall_policy.this.http_listener_ids
  description = "Listeners this policy is associated with - reverse lookup for evidence capture."
}

output "path_based_rule_ids" {
  value       = azurerm_web_application_firewall_policy.this.path_based_rule_ids
  description = "Path rules this policy is associated with."
}
