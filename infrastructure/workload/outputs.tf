output "resource_group_name" {
  value = local.rg_name
}

output "subscription_id" {
  value       = data.azurerm_subscription.current.subscription_id
  description = "Confirms which subscription the run targeted. Worth having in the pipeline log."
}

output "log_analytics_workspace_id" {
  value = local.log_analytics_workspace_id
}

# --------------------------------------------------------- bypass test inputs
# tests/bypass-test.sh takes HOSTNAMES, not URLs.
output "origin_hostname" {
  value       = azurerm_linux_web_app.this.default_hostname
  description = "The origin. The direct path that must be refused once lockdown is on."
}

output "frontdoor_hostname" {
  value       = var.enable_frontdoor ? azurerm_cdn_frontdoor_endpoint.this[0].host_name : null
  description = "Pattern A entry point, no scheme."
}

output "frontdoor_endpoint" {
  value = var.enable_frontdoor ? "https://${azurerm_cdn_frontdoor_endpoint.this[0].host_name}" : null
}

output "frontdoor_id" {
  value       = var.enable_frontdoor ? azurerm_cdn_frontdoor_profile.this[0].resource_guid : null
  description = "X-Azure-FDID. Needed to prove the header check works and that a FOREIGN FDID is rejected."
}

output "appgw_public_ip" {
  value       = var.enable_appgw ? azurerm_public_ip.appgw[0].ip_address : null
  description = "Pattern B entry point."
}

# ------------------------------------------------------------- WAF policies
output "waf_appgw_policy_id" {
  value = var.enable_appgw ? module.waf_appgw[0].id : null
}

output "waf_afd_policy_id" {
  value = var.enable_frontdoor ? module.waf_afd[0].id : null
}

output "appgw_ruleset_applied" {
  value = var.enable_appgw ? var.appgw_ruleset_version : null
}

output "afd_ruleset_applied" {
  value = var.enable_frontdoor ? var.afd_ruleset_version : null
}

# Consumed by pipelines/reconcile-exclusions.sh to detect portal drift.
output "intended_exclusions" {
  value = {
    appgw = var.appgw_exclusions
    afd   = var.afd_exclusions
  }
}

# --------------------------------------------------------------- test state
output "current_test_state" {
  value = {
    waf_mode         = var.waf_mode
    lockdown_enabled = var.lockdown_enabled
    appgw_enabled    = var.enable_appgw
    frontdoor_enabled = var.enable_frontdoor
  }
  description = "Record this alongside every piece of evidence. Which switches were set is half the finding."
}
