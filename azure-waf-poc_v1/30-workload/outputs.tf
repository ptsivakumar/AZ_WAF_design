output "frontdoor_endpoint" {
  value       = "https://${azurerm_cdn_frontdoor_endpoint.fd.host_name}"
  description = "Pattern A entry point. Use in the bypass test as the LEGITIMATE path."
}

output "appgw_public_ip" {
  value       = azurerm_public_ip.agw.ip_address
  description = "Pattern B entry point."
}

output "origin_hostname" {
  value       = azurerm_linux_web_app.app.default_hostname
  description = "The origin. Use in the bypass test as the DIRECT path that must be refused once lockdown is on."
}

output "frontdoor_id" {
  value       = azurerm_cdn_frontdoor_profile.fd.resource_guid
  description = "X-Azure-FDID value. Needed to prove the header check works and to prove a FOREIGN FDID is rejected."
}

output "lockdown_enabled" {
  value = var.lockdown_enabled
}

output "waf_appgw_policy_id"  { value = module.waf_appgw.id }
output "waf_afd_policy_id"    { value = module.waf_afd.id }
output "afd_ruleset_applied"  { value = module.waf_afd.managed_ruleset_version }
output "appgw_ruleset_applied"{ value = module.waf_appgw.managed_ruleset_version }
output "intended_exclusions"  { value = module.waf_appgw.intended_exclusions }
