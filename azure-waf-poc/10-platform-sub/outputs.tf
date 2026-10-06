output "platform_resource_group" {
  value = azurerm_resource_group.platform.name
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.central.id
}

output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}

output "initiative_id" {
  value       = var.enable_policy ? azurerm_policy_set_definition.waf[0].id : null
  description = "Null until enable_policy is true."
}

output "assignment_id" {
  value       = var.enable_policy ? azurerm_subscription_policy_assignment.waf[0].id : null
  description = "Null until enable_policy is true."
}

output "custom_policy_ids" {
  value = { for k, v in azurerm_policy_definition.custom : k => v.id }
}

# Hand this to whoever holds RBAC Administrator when enable_remediation_role
# is false. They create one role assignment:
#   az role assignment create --assignee-object-id <this value> \
#     --assignee-principal-type ServicePrincipal \
#     --role Contributor --scope /subscriptions/<subscription_id>
# Until that exists, DeployIfNotExists policies evaluate but cannot remediate.
output "policy_assignment_principal_id" {
  value       = var.enable_policy ? azurerm_subscription_policy_assignment.waf[0].identity[0].principal_id : null
  description = "Managed identity of the policy assignment. Needed for the remediation role assignment."
}

output "current_effect" {
  value       = var.initiative_effect
  description = "Record this in the evidence log alongside each compliance snapshot."
}

output "scope_caveat" {
  value = "Subscription-scoped PoC. Management-group assignment and cross-subscription inheritance are NOT exercised here. Record this as an environment limitation in the findings report."
}
