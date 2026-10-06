output "active_exceptions" {
  value = {
    for k, v in azurerm_resource_policy_exemption.this : k => {
      id         = v.id
      category   = v.exemption_category
      expires_on = v.expires_on
      controls   = v.policy_definition_reference_ids
    }
  }
  description = "Applied exemptions. Compare against the ARG register query - they must agree."
}

output "records_loaded" {
  value       = keys(local.records)
  description = "Every record in the repository, including expired and pending ones."
}

output "records_active" {
  value       = keys(local.active)
  description = "Records actually deployed. The difference from records_loaded is the expired/pending set."
}
