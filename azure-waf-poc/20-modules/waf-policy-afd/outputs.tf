output "id" {
  value = azurerm_cdn_frontdoor_firewall_policy.this.id
}

output "name" {
  value = azurerm_cdn_frontdoor_firewall_policy.this.name
}

output "security_policy_id" {
  value       = try(azurerm_cdn_frontdoor_security_policy.this[0].id, null)
  description = "The object Azure Policy must inspect to answer 'does this domain have a WAF'. Null when no domains were bound."
}

output "managed_ruleset_version" {
  value       = var.managed_ruleset_version
  description = "Record the value that actually applied - this is PoC objective evidence."
}

output "intended_exclusions" {
  value = var.exclusions
}
