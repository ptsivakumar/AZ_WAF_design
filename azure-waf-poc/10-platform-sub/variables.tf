variable "subscription_id" {
  type        = string
  description = "The sandbox subscription GUID. For ccoe-waf-sandbox, read it from `az account show --query id -o tsv`."
}

variable "prefix" {
  type    = string
  default = "wafpoc"
}

variable "location" {
  type    = string
  default = "westeurope"
}

# ---------------------------------------------------------------- guards
# Both default to false so the very first apply succeeds with Contributor
# alone. Turn them on as permissions arrive.

variable "enable_policy" {
  type        = bool
  default     = false
  description = <<-EOT
    false  = resource groups and Log Analytics only. Works with Contributor.
    true   = also create the policy definitions, the initiative and the
             subscription assignment. Requires Resource Policy Contributor
             on this subscription, because the built-in Contributor role has
             "Microsoft.Authorization/*/Write" in its NotActions.
  EOT
}

variable "enable_remediation_role" {
  type        = bool
  default     = false
  description = <<-EOT
    true creates the role assignment that gives the policy assignment's
    managed identity permission to remediate. Needs
    Microsoft.Authorization/roleAssignments/write — Role Based Access Control
    Administrator or User Access Administrator. Contributor does NOT have it.
    Leave false and hand the policy_assignment_principal_id output to whoever
    does; DeployIfNotExists remediation will not run until that is in place.
  EOT
}

variable "initiative_effect" {
  type        = string
  default     = "Audit"
  description = "Audit for weeks 1-3. Flip to Deny for step 2.4. This single variable is the audit-to-enforce switch."
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.initiative_effect)
    error_message = "initiative_effect must be Audit, Deny or Disabled."
  }
}

variable "builtin_policy_display_names" {
  type        = list(string)
  description = "Microsoft built-ins to include. Confirm each exists before applying - display names occasionally change. `az policy definition list --query \"[?displayName=='<name>'].id\"` returns empty if it has been renamed."
  default = [
    "Azure Web Application Firewall should be enabled for Azure Front Door entry-points",
    "Web Application Firewall (WAF) should be enabled for Application Gateway",
    "Azure Front Door profiles should use Premium tier that supports managed WAF rules and private link",
    "Azure Web Application Firewall on Azure Application Gateway should have request body inspection enabled",
    "Azure Application Gateway should have Resource logs enabled"
  ]
}

variable "tags" {
  type = map(string)
  default = {
    purpose    = "waf-poc"
    owner      = "ccoe"
    disposable = "true"
  }
}
