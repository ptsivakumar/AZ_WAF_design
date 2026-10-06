###############################################################################
# 10-platform-sub — SUBSCRIPTION-SCOPED variant of 10-platform.
#
# USE THIS ONE when the sandbox is a single subscription with no management
# group, which is the ccoe-waf-sandbox situation.
# Use 10-platform/ instead once a test management group exists.
#
# WHAT CHANGES vs. the management-group version:
#   azurerm_policy_definition                    -> management_group_id omitted,
#                                                   so it lands at subscription scope
#   azurerm_management_group_policy_set_definition -> azurerm_policy_set_definition
#   azurerm_management_group_policy_assignment     -> azurerm_subscription_policy_assignment
#
# WHAT YOU GIVE UP, and must record in the findings report:
#   - Management-group-scoped assignment is not exercised. In production the
#     initiative is assigned at the Landing Zones management group and inherited
#     by every subscription beneath it. Here it covers one subscription only.
#   - Definition storage at the intermediate root is not exercised. A definition
#     stored in a subscription can only ever be assigned to that subscription —
#     which is exactly why production stores them at a management group.
#   - Inheritance behaviour across subscriptions is untested.
#   These are limitations of the environment, not of the design. Say so plainly.
#
# REQUIRED PERMISSIONS
#   Contributor alone is NOT enough. The built-in Contributor role has
#   "Microsoft.Authorization/*/Write" in its NotActions, which blocks policy
#   definitions, assignments and exemptions.
#   You also need: Resource Policy Contributor on this subscription.
#   And for the DeployIfNotExists remediation identity to be granted its role:
#   Role Based Access Control Administrator or User Access Administrator,
#   or ask someone who has it to create that one role assignment for you.
###############################################################################

terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 5.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "azurerm_subscription" "current" {}

# Two resource groups stand in for the two subscriptions the PoC plan asked
# for. Weaker separation, but it keeps the platform and workload split visible.
resource "azurerm_resource_group" "platform" {
  name     = "${var.prefix}-platform-rg"
  location = var.location
  tags     = var.tags
}

# ------------------------------------------------------------- telemetry
resource "azurerm_log_analytics_workspace" "central" {
  name                = "${var.prefix}-law"
  resource_group_name = azurerm_resource_group.platform.name
  location            = azurerm_resource_group.platform.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

# ---------------------------------------------- custom policy definitions
locals {
  policy_files = fileset("${path.module}/../10-platform/policies", "*.json")
  policies = {
    for f in local.policy_files :
    trimsuffix(f, ".json") => jsondecode(file("${path.module}/../10-platform/policies/${f}"))
  }
}

# No management_group_id — the definition is created at subscription scope.
resource "azurerm_policy_definition" "custom" {
  for_each = var.enable_policy ? local.policies : {}

  name         = each.key
  policy_type  = "Custom"
  mode         = lookup(each.value, "mode", "Indexed")
  display_name = each.value.displayName
  description  = lookup(each.value, "description", null)

  policy_rule = jsonencode(each.value.policyRule)
  parameters  = jsonencode(lookup(each.value, "parameters", {}))

  metadata = jsonencode({
    category = "WAF"
    version  = "1.0.0"
    source   = "CCoE Azure WAF PoC — subscription scope"
  })
}

data "azurerm_policy_definition" "builtin" {
  for_each     = var.enable_policy ? toset(var.builtin_policy_display_names) : toset([])
  display_name = each.value
}

# ---------------------------------------------------------- the initiative
# In provider v5 azurerm_policy_set_definition has NO management_group_id
# argument, so it is created at the provider's subscription scope.
resource "azurerm_policy_set_definition" "waf" {
  count = var.enable_policy ? 1 : 0

  name         = "${var.prefix}-waf-initiative"
  policy_type  = "Custom"
  display_name = "Azure WAF guardrails — CCoE PoC (subscription scope)"
  description  = "Thirteen controls covering ingress, baseline, origin lockdown and tagging. Subscription-scoped for the sandbox."

  metadata = jsonencode({ category = "WAF", version = "1.0.0" })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
      metadata      = { displayName = "Effect for custom controls" }
    }
  })

  dynamic "policy_definition_reference" {
    for_each = azurerm_policy_definition.custom
    content {
      policy_definition_id = policy_definition_reference.value.id
      reference_id         = policy_definition_reference.key
      parameter_values = jsonencode({
        effect = { value = "[parameters('effect')]" }
      })
    }
  }

  dynamic "policy_definition_reference" {
    for_each = data.azurerm_policy_definition.builtin
    content {
      policy_definition_id = policy_definition_reference.value.id
      reference_id         = replace(policy_definition_reference.key, " ", "-")
    }
  }
}

# ----------------------------------------------------------- assignment
resource "azurerm_subscription_policy_assignment" "waf" {
  count = var.enable_policy ? 1 : 0

  name                 = substr("${var.prefix}-waf-assign", 0, 24)
  display_name         = "Azure WAF guardrails (PoC)"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = azurerm_policy_set_definition.waf[0].id

  location = var.location
  identity {
    type = "SystemAssigned"
  }

  enforce = true

  parameters = jsonencode({
    effect = { value = var.initiative_effect }
  })

  non_compliance_message {
    content = "This resource does not meet the CCoE Azure WAF baseline. See the WAF design proposal, section 7."
  }
}

# The remediation identity needs permission to create diagnostic settings.
# Creating THIS role assignment needs Microsoft.Authorization/roleAssignments/write,
# which Contributor does NOT have. If the apply fails here, set
# enable_remediation_role = false and ask someone with RBAC Administrator to
# create the assignment manually — the identity's principal ID is an output.
resource "azurerm_role_assignment" "remediation" {
  count = var.enable_policy && var.enable_remediation_role ? 1 : 0

  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_subscription_policy_assignment.waf[0].identity[0].principal_id
}
