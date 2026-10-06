output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.central.id
}

output "initiative_id" {
  value = azurerm_management_group_policy_set_definition.waf.id
}

output "assignment_id" {
  value = azurerm_management_group_policy_assignment.waf.id
}

output "custom_policy_ids" {
  value = { for k, v in azurerm_policy_definition.custom : k => v.id }
}

output "current_effect" {
  value       = var.initiative_effect
  description = "Record this in the evidence log alongside each compliance snapshot."
}
